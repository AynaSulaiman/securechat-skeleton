"""AES-128(ECB)+PKCS#7 helpers (use library)."""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt plaintext using AES-128 in ECB mode with PKCS#7 padding.
    
    Args:
        plaintext: bytes to encrypt
        key: 16-byte AES key
    
    Returns:
        Encrypted ciphertext (includes PKCS#7 padding)
    """
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

def aes_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt ciphertext using AES-128 in ECB mode with PKCS#7 padding.
    
    Args:
        ciphertext: encrypted bytes
        key: 16-byte AES key
    
    Returns:
        Decrypted plaintext (PKCS#7 padding removed)
    """
    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
