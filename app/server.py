"""Server skeleton — plain TCP; no TLS. See assignment spec."""
import socket
import json
import os
import secrets
import base64
from dotenv import load_dotenv
from app.common.protocol import Hello, ServerHello, DHClientKeyShare, DHServerKeyShare, Register, Login, Message, Receipt
from app.common.utils import now_ms, b64e, b64d, sha256_hex
from app.crypto.aes import aes_encrypt, aes_decrypt
from app.crypto.dh import dh_generate_params, dh_generate_private_key, dh_public_key_bytes, dh_compute_shared_secret, kdf_trunc16_sha256
from app.crypto.pki import load_certificate_pem, verify_cert_signed_by_ca, verify_cert_validity, verify_cert_cn_or_san
from app.crypto.sign import load_rsa_private_key_pem, rsa_sign, rsa_verify
from app.storage.db import Database
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

def handle_client(client_sock, client_addr):
    """Handle a client connection."""
    print(f"[*] Client connected: {client_addr}")
    
    try:
        # Load CA certificate
        ca_cert_path = os.getenv("CA_CERT_PATH")
        with open(ca_cert_path, 'rb') as f:
            ca_cert_pem = f.read()
        ca_cert = load_certificate_pem(ca_cert_pem)
        
        # Load server certificate and key
        server_cert_path = os.getenv("SERVER_CERT_PATH")
        server_key_path = os.getenv("SERVER_KEY_PATH")
        
        with open(server_cert_path, 'rb') as f:
            server_cert_pem = f.read()
        with open(server_key_path, 'rb') as f:
            server_key_pem = f.read()
        
        server_cert = load_certificate_pem(server_cert_pem)
        server_key = load_rsa_private_key_pem(server_key_pem)
        
        # Step 1: Receive Hello from client
        print(f"[*] Waiting for Hello message...")
        hello_data = recv_message(client_sock)
        if not hello_data:
            print(f"[-] No Hello received")
            return
        
        hello = Hello(**hello_data)
        client_nonce = hello.nonce
        client_username = hello.username
        
        print(f"[+] Received Hello from {client_username}")
        
        # Verify client certificate
        client_cert_pem = b64d(hello.cert_pem)
        client_cert = load_certificate_pem(client_cert_pem)
        
        if not verify_cert_signed_by_ca(client_cert, ca_cert):
            print(f"[-] Client certificate not signed by CA")
            return
        
        if not verify_cert_validity(client_cert):
            print(f"[-] Client certificate not valid")
            return
        
        if not verify_cert_cn_or_san(client_cert, "client.local"):
            print(f"[-] Client certificate CN/SAN mismatch")
            return
        
        # Step 2: Send ServerHello
        server_nonce = b64e(secrets.token_bytes(32))
        nonce_to_sign = (client_nonce + server_nonce).encode('utf-8')
        signature = rsa_sign(nonce_to_sign, server_key)
        
        server_hello = ServerHello(
            nonce=server_nonce,
            cert_pem=b64e(server_cert_pem),
            signature=b64e(signature)
        )
        send_message(client_sock, server_hello)
        print(f"[+] Sent ServerHello")
        
        # Step 3: DH Key Exchange
        dh_params = dh_generate_params()
        server_dh_key = dh_generate_private_key(dh_params)
        server_dh_public_bytes = dh_public_key_bytes(server_dh_key)
        
        # Receive client DH public value
        dh_client_data = recv_message(client_sock)
        if not dh_client_data:
            print(f"[-] No DH client key share received")
            return
        
        dh_client = DHClientKeyShare(**dh_client_data)
        client_dh_public_bytes = b64d(dh_client.client_dh_public)
        
        # Compute shared secret
        shared_secret = dh_compute_shared_secret(server_dh_key, client_dh_public_bytes, dh_params)
        session_key = kdf_trunc16_sha256(shared_secret)
        
        print(f"[+] Computed shared session key")
        
        # Send server DH public value
        dh_server = DHServerKeyShare(
            server_dh_public=b64e(server_dh_public_bytes)
        )
        send_message(client_sock, dh_server)
        
        # Initialize transcript
        session_id = b64e(secrets.token_bytes(16))
        transcript = Transcript(session_id)
        
        # Step 4: Authentication
        auth_data = recv_message(client_sock)
        if not auth_data:
            print(f"[-] No auth message received")
            return
        
        db = Database()
        
        if "password_hash" in auth_data and "username" in auth_data:
            # Could be register or login
            # For now, try login
            username = auth_data["username"]
            password_hash = auth_data["password_hash"]
            
            # In real scenario, would validate password_hash
            if db.user_exists(username):
                # Login
                print(f"[+] User {username} logged in")
                transcript.append_entry("login", username, username, now_ms())
            else:
                print(f"[-] User {username} does not exist")
                return
        
        # Step 5: Chat loop
        print(f"[*] Entering chat loop...")
        while True:
            msg_data = recv_message(client_sock)
            if not msg_data:
                break
            
            if "ciphertext" in msg_data:
                # Encrypted message
                ciphertext_bytes = b64d(msg_data["ciphertext"])
                plaintext = aes_decrypt(ciphertext_bytes, session_key)
                print(f"[+] Message from {msg_data.get('sender')}: {plaintext.decode('utf-8')}")
                
                transcript.append_entry("msg", msg_data.get("sender"), msg_data["ciphertext"], msg_data.get("timestamp"))
                
                # Echo back or process message
        
        # Generate session receipt
        transcript_hash = transcript.compute_transcript_hash()
        receipt_data = f"{session_id}:{transcript_hash}"
        receipt_sig = rsa_sign(receipt_data.encode('utf-8'), server_key)
        
        receipt = Receipt(
            session_id=session_id,
            transcript_hash=transcript_hash,
            signature=b64e(receipt_sig),
            timestamp=now_ms()
        )
        send_message(client_sock, receipt)
        print(f"[+] Sent session receipt")
        
    except Exception as e:
        print(f"[-] Error handling client: {e}")
    finally:
        client_sock.close()
        print(f"[*] Client disconnected: {client_addr}")

def main():
    """Run the server."""
    host = os.getenv("SERVER_HOST", "localhost")
    port = int(os.getenv("SERVER_PORT", 5000))
    
    print(f"[*] Starting SecureChat Server on {host}:{port}")
    
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen(5)
    
    print(f"[+] Server listening on {host}:{port}")
    
    try:
        while True:
            client_sock, client_addr = server_sock.accept()
            handle_client(client_sock, client_addr)
    except KeyboardInterrupt:
        print(f"[*] Server shutting down...")
    finally:
        server_sock.close()

if __name__ == "__main__":
    main()
