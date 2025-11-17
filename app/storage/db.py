"""MySQL users table + salted hashing (no chat storage)."""
import os
import pymysql
import hashlib
import secrets
import base64
from dotenv import load_dotenv

load_dotenv()

class Database:
    """MySQL connection manager for users table."""
    
    def __init__(self):
        self.host = os.getenv("DB_HOST", "localhost")
        self.port = int(os.getenv("DB_PORT", 3306))
        self.user = os.getenv("DB_USER", "scuser")
        self.password = os.getenv("DB_PASSWORD", "scpass")
        self.database = os.getenv("DB_NAME", "securechat")
    
    def connect(self):
        """Create and return a MySQL connection."""
        return pymysql.connect(
            host=self.host,
            port=self.port,
            user=self.user,
            password=self.password,
            database=self.database
        )
    
    def init_schema(self):
        """Create users table if not exists."""
        conn = self.connect()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    salt VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
        finally:
            cursor.close()
            conn.close()
    
    def register_user(self, username: str, password: str) -> bool:
        """
        Register a new user with salted SHA-256 password hash.
        
        Args:
            username: username
            password: plaintext password
        
        Returns:
            True if registration succeeded, False if user exists
        """
        # Generate random salt
        salt = secrets.token_bytes(32)
        salt_b64 = base64.b64encode(salt).decode('ascii')
        
        # Hash password with salt
        password_hash = hashlib.sha256(password.encode() + salt).hexdigest()
        
        conn = self.connect()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (username, password_hash, salt) VALUES (%s, %s, %s)",
                (username, password_hash, salt_b64)
            )
            conn.commit()
            return True
        except pymysql.IntegrityError:
            return False
        finally:
            cursor.close()
            conn.close()
    
    def verify_password(self, username: str, password: str) -> bool:
        """
        Verify user password.
        
        Args:
            username: username
            password: plaintext password
        
        Returns:
            True if password matches, False otherwise
        """
        conn = self.connect()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "SELECT password_hash, salt FROM users WHERE username = %s",
                (username,)
            )
            result = cursor.fetchone()
            if not result:
                return False
            
            stored_hash, salt_b64 = result
            salt = base64.b64decode(salt_b64)
            
            # Recompute hash
            computed_hash = hashlib.sha256(password.encode() + salt).hexdigest()
            return computed_hash == stored_hash
        finally:
            cursor.close()
            conn.close()
    
    def user_exists(self, username: str) -> bool:
        """Check if user exists."""
        conn = self.connect()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT 1 FROM users WHERE username = %s", (username,))
            return cursor.fetchone() is not None
        finally:
            cursor.close()
            conn.close()

if __name__ == "__main__":
    import sys
    db = Database()
    if "--init" in sys.argv:
        db.init_schema()
        print("Database schema initialized")
