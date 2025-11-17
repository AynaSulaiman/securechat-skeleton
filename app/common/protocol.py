"""Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt."""
from pydantic import BaseModel
from typing import Optional

class Hello(BaseModel):
    """Client initiates: username, nonce, cert."""
    username: str
    nonce: str  # base64-encoded random bytes
    cert_pem: str  # base64-encoded certificate PEM

class ServerHello(BaseModel):
    """Server responds: nonce, cert, signature on (client_nonce || server_nonce)."""
    nonce: str  # server nonce (base64)
    cert_pem: str  # server certificate (base64)
    signature: str  # signature on (client_nonce || server_nonce) (base64)

class DHClientKeyShare(BaseModel):
    """Client DH public value."""
    client_dh_public: str  # base64-encoded DH public value

class DHServerKeyShare(BaseModel):
    """Server DH public value."""
    server_dh_public: str  # base64-encoded DH public value

class Register(BaseModel):
    """Client registration request: username, password_hash."""
    username: str
    password_hash: str  # base64-encoded salted hash
    salt: str  # base64-encoded salt

class Login(BaseModel):
    """Client login request: username, password_hash."""
    username: str
    password_hash: str  # base64-encoded salted hash

class Message(BaseModel):
    """Encrypted chat message."""
    sender: str
    ciphertext: str  # base64-encoded AES-encrypted message
    timestamp: int  # milliseconds since epoch

class Receipt(BaseModel):
    """Session receipt signed by server."""
    session_id: str
    transcript_hash: str  # hex-encoded SHA-256
    signature: str  # base64-encoded RSA signature
    timestamp: int  # milliseconds since epoch
