"""RSA PKCS#1 v1.5 SHA-256 sign/verify."""
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def load_rsa_private_key_pem(key_pem: bytes, password: bytes = None):
    """Load RSA private key from PEM format."""
    return serialization.load_pem_private_key(
        key_pem,
        password=password,
        backend=default_backend()
    )

def load_rsa_public_key_pem(key_pem: bytes):
    """Load RSA public key from PEM format."""
    return serialization.load_pem_public_key(key_pem, default_backend())

def rsa_sign(data: bytes, private_key) -> bytes:
    """
    Sign data using RSA PKCS#1 v1.5 with SHA-256.
    
    Args:
        data: bytes to sign
        private_key: RSA private key
    
    Returns:
        Signature bytes
    """
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature

def rsa_verify(data: bytes, signature: bytes, public_key) -> bool:
    """
    Verify RSA PKCS#1 v1.5 SHA-256 signature.
    
    Args:
        data: original data
        signature: signature bytes
        public_key: RSA public key
    
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
