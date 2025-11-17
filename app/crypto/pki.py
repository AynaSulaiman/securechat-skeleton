"""X.509 validation: signed-by-CA, validity window, CN/SAN."""
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone

def load_certificate_pem(cert_pem: bytes) -> x509.Certificate:
    """Load an X.509 certificate from PEM bytes."""
    return x509.load_pem_x509_certificate(cert_pem, default_backend())

def load_ca_certificate_pem(ca_pem: bytes) -> x509.Certificate:
    """Load a CA certificate from PEM bytes."""
    return x509.load_pem_x509_certificate(ca_pem, default_backend())

def verify_cert_signed_by_ca(cert: x509.Certificate, ca_cert: x509.Certificate) -> bool:
    """
    Verify that cert was signed by ca_cert.
    
    Args:
        cert: The certificate to verify
        ca_cert: The CA certificate that should have signed it
    
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            cert.signature_algorithm_oid
        )
        return True
    except Exception:
        return False

def verify_cert_validity(cert: x509.Certificate) -> bool:
    """
    Verify that cert is within its validity window (not expired, not yet valid).
    
    Args:
        cert: The certificate to verify
    
    Returns:
        True if cert is valid now, False otherwise
    """
    now = datetime.now(timezone.utc)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    return not_before <= now <= not_after

def get_cert_cn(cert: x509.Certificate) -> str:
    """
    Extract Common Name (CN) from certificate subject.
    
    Args:
        cert: The certificate
    
    Returns:
        CN value, or None if not found
    """
    try:
        cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attr:
            return cn_attr[0].value
    except Exception:
        pass
    return None

def get_cert_san(cert: x509.Certificate) -> list[str]:
    """
    Extract SubjectAltName (SAN) DNS names from certificate.
    
    Args:
        cert: The certificate
    
    Returns:
        List of DNS names
    """
    names = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for general_name in san_ext.value:
            if isinstance(general_name, x509.DNSName):
                names.append(general_name.value)
    except Exception:
        pass
    return names

def verify_cert_cn_or_san(cert: x509.Certificate, expected_cn: str) -> bool:
    """
    Verify that cert's CN or SAN matches the expected value.
    
    Args:
        cert: The certificate
        expected_cn: The expected CN/hostname
    
    Returns:
        True if CN or SAN matches, False otherwise
    """
    # Check CN
    cn = get_cert_cn(cert)
    if cn and cn == expected_cn:
        return True
    
    # Check SAN
    san_names = get_cert_san(cert)
    if expected_cn in san_names:
        return True
    
    return False
