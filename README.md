# Image Encryption/Decryption Web App

A simple web application for encrypting and decrypting images using multiple encryption methods (SHA-256, AES, and RSA).

## Features
- Support multiple encryption methods:
  - SHA-256
  - AES
  - RSA
- Simple web interface
- File upload/download
- Docker support

## Prerequisites
- Docker
- Docker Compose

## Quick Start

1. Clone the repository

bash
git clone <your-repository-url>
cd image_crypto

2. Build and run with Docker Compose

bash
docker-compose up --build

3. Access the application

Open your browser and navigate to `http://localhost:5000` to access the web interface.


bash
docker-compose down

3. Access the application
- Open your browser and navigate to `http://localhost:5000`

4. To stop the application

bash
docker-compose down

## Manual Setup (Without Docker)

1. Create a Python virtual environment

bash
python -m venv venv
source venv/bin/activate

2. Install dependencies

bash
pip install -r requirements.txt

3. Run the application

bash
python app.py

4. Access the application at `http://localhost:5000`

## Usage

### Encryption
1. Select encryption method (SHA-256, AES, or RSA)
2. For SHA-256 and AES:
   - Enter a password
   - Upload file
   - Click "Encrypt"
3. For RSA:
   - Click "Generate New RSA Keys"
   - Note the Key ID (needed for decryption)
   - Upload file
   - Click "Encrypt"

### Decryption
1. Select the same encryption method used for encryption
2. For SHA-256 and AES:
   - Enter the same password used for encryption
   - Upload encrypted file
   - Click "Decrypt"
3. For RSA:
   - Enter the Key ID from encryption
   - Upload encrypted file
   - Click "Decrypt"

