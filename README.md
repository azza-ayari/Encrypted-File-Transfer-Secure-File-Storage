# Secure File Transfer System

A secure, end-to-end encrypted file transfer system implemented in Python.

## Features
- **End-to-End Encryption:** Files are encrypted client-side using AES-256-GCM.
- **Integrity Checks:** HMAC-SHA256 ensures data has not been tampered with.
- **Secure Transport:** TLS 1.3 for secure communication.
- **Resumable Uploads:** Support for resuming interrupted transfers.
- **Zero-Knowledge Storage:** The server stores encrypted blobs and has no access to the plaintext or encryption keys.


## How to Run

1. **Install dependencies:**
   `pip install cryptography`

2. **Generate self-signed certificate (for testing):**
   `openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost"`

3. **Configure:**
   Rename `config.py.example` to `config.py` and set your `SHARED_HMAC_KEY`.

4. **Start Server:**
   `python server.py`

5. **Run Client:**
   `python client.py upload <file>`

## Security Considerations
- This project uses client-side encryption. The server never handles the encryption keys.
- TLS 1.3 is required for network transport.
- Always generate new keys for production deployments.
