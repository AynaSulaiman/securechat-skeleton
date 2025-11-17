"""Issue server/client cert signed by Root CA (SAN=DNSName(CN))."""
import argparse
import os
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtensionOID
from datetime import datetime, timedelta, timezone

def gen_cert(cn: str, ca_key_path: str, ca_cert_path: str, output_dir: str = "certs"):
    """
    Issue a certificate signed by the Root CA.
    
    Args:
        cn: Common Name (e.g., "server.local", "client.local")
        ca_key_path: path to CA private key (PEM)
        ca_cert_path: path to CA certificate (PEM)
        output_dir: output directory for cert and key
    """
    os.makedirs(output_dir, exist_ok=True)
    
    # Load CA key and cert
    print(f"[*] Loading CA key and certificate...")
    with open(ca_key_path, 'rb') as f:
        ca_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    
    with open(ca_cert_path, 'rb') as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    
    # Generate server/client RSA private key
    print(f"[*] Generating 2048-bit RSA private key for {cn}...")
    server_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Build certificate subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NU"),
    ])
    
    # Create certificate
    print(f"[*] Creating certificate for {cn}...")
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        server_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            key_cert_sign=False,
            crl_sign=False,
            content_commitment=True,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(cn),
        ]),
        critical=False,
    ).sign(ca_key, hashes.SHA256(), default_backend())
    
    # Save private key
    server_key_pem = server_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Save certificate
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    
    # Generate output filenames
    base_name = cn.replace('.', '_')
    key_path = os.path.join(output_dir, f"{base_name}-key.pem")
    cert_path = os.path.join(output_dir, f"{base_name}-cert.pem")
    
    # Write files
    with open(key_path, 'wb') as f:
        f.write(server_key_pem)
    print(f"[+] Saved certificate private key: {key_path}")
    
    with open(cert_path, 'wb') as f:
        f.write(cert_pem)
    print(f"[+] Saved certificate: {cert_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate client/server certificate")
    parser.add_argument("--cn", required=True, help="Common Name (e.g., server.local)")
    parser.add_argument("--ca-key", default="certs/ca-key.pem", help="CA private key path")
    parser.add_argument("--ca-cert", default="certs/ca-cert.pem", help="CA cert path")
    parser.add_argument("--out", default="certs", help="Output directory")
    args = parser.parse_args()
    
    gen_cert(args.cn, args.ca_key, args.ca_cert, args.out)
