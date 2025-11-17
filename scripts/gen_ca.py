"""Create Root CA (RSA + self-signed X.509) using cryptography."""
import argparse
import os
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone

def gen_ca(ca_name: str, output_dir: str = "certs"):
    """
    Generate a Root CA with self-signed X.509 certificate.
    
    Args:
        ca_name: Common Name for the CA
        output_dir: directory to save keys/certs
    """
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate RSA private key (2048-bit)
    print(f"[*] Generating 2048-bit RSA private key...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Build certificate subject and issuer (same for self-signed)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, ca_name),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NU"),
    ])
    
    # Create certificate
    print(f"[*] Creating self-signed Root CA certificate...")
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=3650)  # 10 years
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            crl_sign=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).sign(private_key, hashes.SHA256(), default_backend())
    
    # Save private key
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Save certificate
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    
    # Write to files
    ca_key_path = os.path.join(output_dir, "ca-key.pem")
    ca_cert_path = os.path.join(output_dir, "ca-cert.pem")
    
    with open(ca_key_path, 'wb') as f:
        f.write(private_key_pem)
    print(f"[+] Saved CA private key: {ca_key_path}")
    
    with open(ca_cert_path, 'wb') as f:
        f.write(cert_pem)
    print(f"[+] Saved CA certificate: {ca_cert_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate Root CA")
    parser.add_argument("--name", default="FAST-NU Root CA", help="CA Common Name")
    parser.add_argument("--out", default="certs", help="Output directory")
    args = parser.parse_args()
    
    gen_ca(args.name, args.out)
