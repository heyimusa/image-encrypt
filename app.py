from flask import Flask, render_template, request, send_file, jsonify
import hashlib
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization
import secrets

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Store RSA keys in memory (in production, you'd want to store these securely)
RSA_KEYS = {}

class Encryptor:
    @staticmethod
    def sha256_encrypt(file_data, password):
        key = hashlib.sha256(password.encode()).digest()
        fernet = Fernet(base64.b64encode(key))
        return fernet.encrypt(file_data)

    @staticmethod
    def sha256_decrypt(file_data, password):
        try:
            key = hashlib.sha256(password.encode()).digest()
            fernet = Fernet(base64.b64encode(key))
            return fernet.decrypt(file_data)
        except Exception:
            raise ValueError("Invalid password or corrupted file for SHA-256 decryption")

    @staticmethod
    def aes_encrypt(file_data, password):
        # Generate a random 256-bit key from the password
        key = hashlib.sha256(password.encode()).digest()
        # Generate a random IV
        iv = secrets.token_bytes(16)
        
        # Create AES cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        # Add padding
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(file_data) + padder.finalize()
        
        # Encrypt the data
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Return IV + encrypted data
        return iv + encrypted_data

    @staticmethod
    def aes_decrypt(file_data, password):
        try:
            # Extract IV and encrypted data
            iv = file_data[:16]
            encrypted_data = file_data[16:]
            
            # Generate key from password
            key = hashlib.sha256(password.encode()).digest()
            
            # Create AES cipher
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            
            # Decrypt the data
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Remove padding
            unpadder = padding.PKCS7(128).unpadder()
            return unpadder.update(padded_data) + unpadder.finalize()
        except Exception:
            raise ValueError("Invalid password or corrupted file for AES decryption")

    @staticmethod
    def generate_rsa_keys():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        
        # Generate a unique key ID
        key_id = secrets.token_hex(8)
        
        # Store the keys
        RSA_KEYS[key_id] = private_key
        
        # Return the key ID and public key PEM
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return key_id, public_pem.decode()

    @staticmethod
    def rsa_encrypt(file_data, public_key_pem):
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        
        # RSA can only encrypt small amounts of data, so we'll generate a symmetric key
        symmetric_key = secrets.token_bytes(32)
        
        # Encrypt the symmetric key with RSA
        encrypted_symmetric_key = public_key.encrypt(
            symmetric_key,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Use the symmetric key to encrypt the file data (using AES)
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(file_data) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Combine everything: len(encrypted_key) + encrypted_key + iv + encrypted_data
        key_length = len(encrypted_symmetric_key).to_bytes(4, 'big')
        return key_length + encrypted_symmetric_key + iv + encrypted_data

    @staticmethod
    def rsa_decrypt(file_data, key_id):
        if key_id not in RSA_KEYS:
            raise ValueError("Invalid or expired key ID")
        
        try:
            private_key = RSA_KEYS[key_id]
            
            # Extract the encrypted symmetric key
            key_length = int.from_bytes(file_data[:4], 'big')
            encrypted_symmetric_key = file_data[4:4+key_length]
            iv = file_data[4+key_length:4+key_length+16]
            encrypted_data = file_data[4+key_length+16:]
            
            # Decrypt the symmetric key
            try:
                symmetric_key = private_key.decrypt(
                    encrypted_symmetric_key,
                    rsa_padding.OAEP(
                        mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            except Exception:
                raise ValueError("Invalid RSA key or corrupted file")
            
            # Decrypt the file data
            cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            unpadder = padding.PKCS7(128).unpadder()
            return unpadder.update(padded_data) + unpadder.finalize()
        except ValueError:
            raise
        except Exception:
            raise ValueError("Error during RSA decryption process")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate-rsa-keys', methods=['POST'])
def generate_rsa_keys():
    key_id, public_key = Encryptor.generate_rsa_keys()
    return jsonify({'key_id': key_id, 'public_key': public_key})

@app.route('/encrypt', methods=['POST'])
def encrypt():
    if 'file' not in request.files:
        return 'No file uploaded', 400
    
    file = request.files['file']
    password = request.form.get('password', '')
    method = request.form.get('method', 'sha256')
    
    if file.filename == '':
        return 'No file selected', 400
    
    # Read file data
    file_data = file.read()
    
    try:
        if method == 'sha256':
            encrypted_data = Encryptor.sha256_encrypt(file_data, password)
        elif method == 'aes':
            encrypted_data = Encryptor.aes_encrypt(file_data, password)
        elif method == 'rsa':
            public_key = request.form.get('public_key')
            if not public_key:
                return 'Public key is required for RSA encryption', 400
            encrypted_data = Encryptor.rsa_encrypt(file_data, public_key)
        else:
            return 'Invalid encryption method', 400
        
        # Save encrypted file
        encrypted_filename = f'{file.filename}.encrypted'
        encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)
        
        return send_file(
            encrypted_path,
            as_attachment=True,
            download_name=encrypted_filename
        )
    
    except Exception as e:
        return str(e), 400
    finally:
        # Clean up the encrypted file after sending
        try:
            if 'encrypted_path' in locals():
                os.remove(encrypted_path)
        except:
            pass

@app.route('/decrypt', methods=['POST'])
def decrypt():
    if 'file' not in request.files:
        return 'No file uploaded', 400
    
    file = request.files['file']
    password = request.form.get('password', '')
    method = request.form.get('method', 'sha256')
    
    if file.filename == '':
        return 'No file selected', 400
    
    # Read file data
    file_data = file.read()
    
    try:
        if method == 'sha256':
            try:
                decrypted_data = Encryptor.sha256_decrypt(file_data, password)
            except Exception:
                return 'Decryption failed: Invalid password for SHA-256 decryption', 400
        elif method == 'aes':
            try:
                decrypted_data = Encryptor.aes_decrypt(file_data, password)
            except Exception:
                return 'Decryption failed: Invalid password for AES decryption', 400
        elif method == 'rsa':
            key_id = request.form.get('key_id')
            if not key_id:
                return 'Key ID is required for RSA decryption', 400
            try:
                decrypted_data = Encryptor.rsa_decrypt(file_data, key_id)
            except ValueError as ve:
                return f'RSA Decryption failed: {str(ve)}', 400
            except Exception:
                return 'Decryption failed: Invalid Key ID or corrupted file', 400
        else:
            return 'Invalid decryption method', 400
        
        # Get original filename by removing .encrypted extension
        original_filename = file.filename
        if original_filename.endswith('.encrypted'):
            original_filename = original_filename[:-10]  # Remove '.encrypted'
        
        # Save decrypted file with original filename
        decrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], original_filename)
        with open(decrypted_path, 'wb') as f:
            f.write(decrypted_data)
        
        # Send file with original filename
        return send_file(
            decrypted_path,
            as_attachment=True,
            download_name=original_filename
        )
    
    except Exception as e:
        # Log the actual error for debugging (in production, use proper logging)
        print(f"Decryption error: {str(e)}")
        return 'An error occurred during decryption. Please check your file and credentials.', 400
    finally:
        # Clean up the decrypted file after sending
        try:
            if 'decrypted_path' in locals():
                os.remove(decrypted_path)
        except:
            pass

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(host='0.0.0.0', debug=False)