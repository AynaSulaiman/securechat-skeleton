"""Client skeleton — plain TCP; no TLS. See assignment spec."""
import socket
import json
import os
import secrets
import base64
import sys
from dotenv import load_dotenv
from app.common.protocol import Hello, ServerHello, DHClientKeyShare, DHServerKeyShare, Register, Login, Message, Receipt
from app.common.utils import now_ms, b64e, b64d, sha256_hex
from app.crypto.aes import aes_encrypt, aes_decrypt
from app.crypto.dh import dh_generate_params, dh_generate_private_key, dh_public_key_bytes, dh_compute_shared_secret, kdf_trunc16_sha256
from app.crypto.pki import load_certificate_pem, verify_cert_signed_by_ca, verify_cert_validity, verify_cert_cn_or_san
from app.crypto.sign import load_rsa_private_key_pem, load_rsa_public_key_pem, rsa_sign, rsa_verify
from app.storage.transcript import Transcript

load_dotenv()

def send_message(sock, msg_obj):
    """Send a message object (JSON) over socket."""
    data = msg_obj.model_dump_json().encode('utf-8')
    sock.send(data + b'\n')

def recv_message(sock):
    """Receive a message object from socket."""
    buffer = b''
    while b'\n' not in buffer:
        chunk = sock.recv(4096)
        if not chunk:
            return None
        buffer += chunk
    
    data, _ = buffer.split(b'\n', 1)
    try:
        return json.loads(data.decode('utf-8'))
    except:
        return None

def main():
    """Run the client."""
    host = os.getenv("SERVER_HOST", "localhost")
    port = int(os.getenv("SERVER_PORT", 5000))
    
    username = input("Enter username: ").strip()
    password = input("Enter password: ").strip()
    
    print(f"[*] Connecting to {host}:{port}...")
    
    try:
        # Connect to server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        print(f"[+] Connected to server")
        
        # Load CA certificate
        ca_cert_path = os.getenv("CA_CERT_PATH")
        with open(ca_cert_path, 'rb') as f:
            ca_cert_pem = f.read()
        ca_cert = load_certificate_pem(ca_cert_pem)
        
        # Load client certificate and key
        client_cert_path = os.getenv("CLIENT_CERT_PATH")
        client_key_path = os.getenv("CLIENT_KEY_PATH")
        
        with open(client_cert_path, 'rb') as f:
            client_cert_pem = f.read()
        with open(client_key_path, 'rb') as f:
            client_key_pem = f.read()
        
        client_cert = load_certificate_pem(client_cert_pem)
        client_key = load_rsa_private_key_pem(client_key_pem)
        
        # Step 1: Send Hello
        client_nonce = b64e(secrets.token_bytes(32))
        hello = Hello(
            username=username,
            nonce=client_nonce,
            cert_pem=b64e(client_cert_pem)
        )
        send_message(sock, hello)
        print(f"[+] Sent Hello")
        
        # Step 2: Receive ServerHello
        server_hello_data = recv_message(sock)
        if not server_hello_data:
            print(f"[-] No ServerHello received")
            return
        
        server_hello = ServerHello(**server_hello_data)
        server_nonce = server_hello.nonce
        
        # Verify server certificate
        server_cert_pem = b64d(server_hello.cert_pem)
        server_cert = load_certificate_pem(server_cert_pem)
        
        if not verify_cert_signed_by_ca(server_cert, ca_cert):
            print(f"[-] Server certificate not signed by CA")
            return
        
        if not verify_cert_validity(server_cert):
            print(f"[-] Server certificate not valid")
            return
        
        if not verify_cert_cn_or_san(server_cert, "server.local"):
            print(f"[-] Server certificate CN/SAN mismatch")
            return
        
        # Verify server signature
        server_public_key = server_cert.public_key()
        nonce_to_verify = (client_nonce + server_nonce).encode('utf-8')
        server_sig = b64d(server_hello.signature)
        
        if not rsa_verify(nonce_to_verify, server_sig, server_public_key):
            print(f"[-] Server signature verification failed")
            return
        
        print(f"[+] Received and verified ServerHello")
        
        # Step 3: DH Key Exchange
        dh_params = dh_generate_params()
        client_dh_key = dh_generate_private_key(dh_params)
        client_dh_public_bytes = dh_public_key_bytes(client_dh_key)
        
        # Send client DH public value
        dh_client = DHClientKeyShare(
            client_dh_public=b64e(client_dh_public_bytes)
        )
        send_message(sock, dh_client)
        print(f"[+] Sent DH client key share")
        
        # Receive server DH public value
        dh_server_data = recv_message(sock)
        if not dh_server_data:
            print(f"[-] No DH server key share received")
            return
        
        dh_server = DHServerKeyShare(**dh_server_data)
        server_dh_public_bytes = b64d(dh_server.server_dh_public)
        
        # Compute shared secret
        shared_secret = dh_compute_shared_secret(client_dh_key, server_dh_public_bytes, dh_params)
        session_key = kdf_trunc16_sha256(shared_secret)
        
        print(f"[+] Computed shared session key")
        
        # Initialize transcript
        session_id = b64e(secrets.token_bytes(16))
        transcript = Transcript(session_id)
        
        # Step 4: Login
        # For this simplified version, just send username/password hash
        # In production, would use proper authentication
        import hashlib
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        login = Login(
            username=username,
            password_hash=password_hash
        )
        send_message(sock, login)
        print(f"[+] Sent Login")
        
        transcript.append_entry("login", username, username, now_ms())
        
        # Step 5: Chat loop
        print(f"[*] Entering chat mode (type messages, Ctrl+C to exit)")
        try:
            while True:
                msg_text = input(f"{username}> ").strip()
                if not msg_text:
                    continue
                
                # Encrypt message
                msg_bytes = msg_text.encode('utf-8')
                # Pad to 16-byte boundary
                pad_len = 16 - (len(msg_bytes) % 16)
                msg_padded = msg_bytes + bytes([pad_len] * pad_len)
                
                ciphertext = aes_encrypt(msg_padded, session_key)
                
                # Send encrypted message
                msg = Message(
                    sender=username,
                    ciphertext=b64e(ciphertext),
                    timestamp=now_ms()
                )
                send_message(sock, msg)
                print(f"[+] Sent encrypted message")
                
                transcript.append_entry("msg", username, b64e(ciphertext), now_ms())
        
        except KeyboardInterrupt:
            print(f"\n[*] Exiting chat...")
        
        # Receive session receipt
        receipt_data = recv_message(sock)
        if receipt_data and "session_id" in receipt_data:
            receipt = Receipt(**receipt_data)
            print(f"[+] Received session receipt: {receipt.session_id[:20]}...")
            print(f"[+] Transcript hash: {receipt.transcript_hash[:20]}...")
        
    except ConnectionRefusedError:
        print(f"[-] Connection refused. Is the server running?")
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        sock.close()
        print(f"[*] Disconnected")

if __name__ == "__main__":
    main()
