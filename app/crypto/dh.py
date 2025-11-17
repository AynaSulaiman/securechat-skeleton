"""Classic DH helpers + Trunc16(SHA256(Ks)) derivation."""
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
import hashlib

# Standard 2048-bit DH parameters (IETF Group 14)
DH_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
DH_G = 2

def dh_generate_params():
    """Generate DH parameters (p, g) for 2048-bit IETF Group 14."""
    parameters = dh.DHParameterNumbers(DH_P, DH_G)
    return parameters

def dh_generate_private_key(params: dh.DHParameterNumbers) -> dh.DHPrivateKey:
    """Generate a private key for the given DH parameters."""
    param_obj = params.parameters(default_backend())
    private_key = param_obj.generate_private_key()
    return private_key

def dh_public_key_bytes(private_key: dh.DHPrivateKey) -> bytes:
    """Extract the public key (y) as bytes."""
    public_key = private_key.public_key()
    y = public_key.public_numbers().y
    return y.to_bytes(256, byteorder='big')

def dh_compute_shared_secret(private_key: dh.DHPrivateKey, peer_public_y: bytes, params: dh.DHParameterNumbers) -> bytes:
    """
    Compute shared secret from our private key and peer's public value.
    
    Args:
        private_key: Our DH private key
        peer_public_y: Peer's public value as bytes
        params: DH parameters (p, g)
    
    Returns:
        Shared secret as bytes
    """
    peer_y = int.from_bytes(peer_public_y, byteorder='big')
    peer_public_numbers = dh.DHPublicNumbers(peer_y, params)
    peer_public_key = peer_public_numbers.public_key(default_backend())
    shared_secret = private_key.exchange(peer_public_key)
    return shared_secret

def kdf_trunc16_sha256(shared_secret: bytes) -> bytes:
    """
    Derive a 16-byte session key from shared secret using SHA-256 truncation.
    
    Args:
        shared_secret: Diffie-Hellman shared secret
    
    Returns:
        16-byte session key (first 16 bytes of SHA-256)
    """
    h = hashlib.sha256(shared_secret).digest()
    return h[:16]
