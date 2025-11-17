# SecureChat Testing & Setup Guide

This document provides step-by-step instructions to set up and test the SecureChat system.

## Prerequisites

- Python 3.8+
- MySQL Server (or Docker)
- All packages from `requirements.txt`

## Step 1: Set up Virtual Environment

```bash
# Windows (PowerShell)
python -m venv .venv
.venv\Scripts\Activate.ps1

# Linux/Mac
python3 -m venv .venv
source .venv/bin/activate
```

## Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

## Step 3: Set up MySQL Database

### Option A: Using Docker (Recommended)

```bash
docker run -d --name securechat-db \
  -e MYSQL_ROOT_PASSWORD=rootpass \
  -e MYSQL_DATABASE=securechat \
  -e MYSQL_USER=scuser \
  -e MYSQL_PASSWORD=scpass \
  -p 3306:3306 \
  mysql:8
```

### Option B: Using existing MySQL

Make sure you have:
- Database: `securechat`
- User: `scuser`
- Password: `scpass`

## Step 4: Initialize Database Schema

```bash
python -m app.storage.db --init
```

Output should show: `Database schema initialized`

## Step 5: Generate CA and Certificates

### Generate Root CA

```bash
python scripts/gen_ca.py --name "FAST-NU Root CA"
```

Output files:
- `certs/ca-key.pem` (CA private key)
- `certs/ca-cert.pem` (CA certificate)

### Generate Server Certificate

```bash
python scripts/gen_cert.py --cn server.local --out certs
```

Output files:
- `certs/server_local-key.pem`
- `certs/server_local-cert.pem`

### Generate Client Certificate

```bash
python scripts/gen_cert.py --cn client.local --out certs
```

Output files:
- `certs/client_local-key.pem`
- `certs/client_local-cert.pem`

## Step 6: Start the Server

In Terminal 1:
```bash
python -m app.server
```

Expected output:
```
[*] Starting SecureChat Server on localhost:5000
[+] Server listening on localhost:5000
[*] Client connected: ...
```

## Step 7: Connect a Client

In Terminal 2:
```bash
python -m app.client
```

Follow the prompts:
- Enter a username
- Enter a password
- Type messages

## Testing Scenarios

### Scenario 1: Basic Chat Session

1. Start server
2. Start client
3. Login with credentials
4. Type a few messages
5. Press Ctrl+C to exit
6. Check `transcripts/` folder for session logs

### Scenario 2: Certificate Verification

The system verifies:
- ✓ Certificates are signed by CA
- ✓ Certificates are within validity period
- ✓ CN/SAN matches expected hostname

To test invalid certificate scenarios, modify certificate validation temporarily.

### Scenario 3: Message Encryption

All messages are encrypted with AES-128 ECB + PKCS#7 padding using the derived session key.

## File Locations

- **Certificates**: `certs/` directory
- **Session Transcripts**: `transcripts/` directory
- **Environment Config**: `.env` file
- **Database**: MySQL database `securechat`

## Troubleshooting

### Connection Refused
- Make sure server is running on the correct host/port
- Check `.env` file for correct SERVER_HOST and SERVER_PORT

### Certificate Errors
- Regenerate certificates if they're expired
- Ensure CA certificate is correctly loaded
- Verify paths in `.env` file

### Database Connection Errors
- Check MySQL is running
- Verify credentials in `.env` file
- Ensure database `securechat` exists

### Module Import Errors
- Activate virtual environment
- Install all requirements: `pip install -r requirements.txt`
- Check PYTHONPATH includes project root

## Security Features Implemented

1. **PKI-based Authentication**
   - X.509 certificates signed by Root CA
   - CN/SAN validation

2. **Confidentiality**
   - AES-128 ECB encryption of messages
   - PKCS#7 padding

3. **Integrity**
   - SHA-256 hashing
   - Transcript verification

4. **Authenticity & Non-Repudiation**
   - RSA PKCS#1 v1.5 signatures
   - Session receipts signed by server

5. **Key Exchange**
   - Diffie-Hellman 2048-bit IETF Group 14
   - Trunc16(SHA256(Ks)) key derivation

6. **User Authentication**
   - Salted SHA-256 password hashing
   - MySQL user storage

## Production Recommendations

⚠️ **Do NOT use in production without:**

1. Using a proper secure channel (TLS)
2. Implementing proper error handling
3. Adding rate limiting and DoS protection
4. Implementing session timeout
5. Adding audit logging
6. Using stronger password hashing (bcrypt/argon2)
7. Implementing proper access controls
8. Regular security audits

## References

- X.509 PKI: https://en.wikipedia.org/wiki/X.509
- Diffie-Hellman: https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange
- AES: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
- RSA: https://en.wikipedia.org/wiki/RSA_(cryptosystem)
