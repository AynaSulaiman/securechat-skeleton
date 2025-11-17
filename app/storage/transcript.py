"""Append-only transcript + TranscriptHash helpers."""
import os
import json
import hashlib
from app.common.utils import sha256_hex

class Transcript:
    """Append-only transcript for a session."""
    
    def __init__(self, session_id: str, transcripts_dir: str = "transcripts"):
        self.session_id = session_id
        self.transcripts_dir = transcripts_dir
        self.entries = []
        self._ensure_dir()
    
    def _ensure_dir(self):
        """Ensure transcripts directory exists."""
        os.makedirs(self.transcripts_dir, exist_ok=True)
    
    def _get_filepath(self):
        """Get transcript file path for this session."""
        return os.path.join(self.transcripts_dir, f"{self.session_id}.json")
    
    def append_entry(self, message_type: str, sender: str, content: str, timestamp: int = None):
        """
        Append an entry to the transcript.
        
        Args:
            message_type: type of message (e.g., "hello", "msg", "receipt")
            sender: who sent this message
            content: message content or ciphertext
            timestamp: milliseconds since epoch
        """
        entry = {
            "type": message_type,
            "sender": sender,
            "content": content,
            "timestamp": timestamp
        }
        self.entries.append(entry)
        self._write_to_disk()
    
    def _write_to_disk(self):
        """Write transcript to disk."""
        filepath = self._get_filepath()
        with open(filepath, 'w') as f:
            json.dump(self.entries, f, indent=2)
    
    def load_from_disk(self):
        """Load transcript from disk if it exists."""
        filepath = self._get_filepath()
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                self.entries = json.load(f)
    
    def get_entries(self):
        """Return all entries."""
        return self.entries
    
    def compute_transcript_hash(self) -> str:
        """
        Compute SHA-256 hash of the transcript.
        
        Returns:
            Hex-encoded SHA-256 hash
        """
        # Serialize entries in order
        transcript_data = json.dumps(self.entries, sort_keys=False).encode('utf-8')
        return sha256_hex(transcript_data)
    
    def compute_transcript_hash_at(self, up_to_index: int) -> str:
        """
        Compute SHA-256 hash of transcript up to a specific index.
        
        Args:
            up_to_index: include entries [0:up_to_index]
        
        Returns:
            Hex-encoded SHA-256 hash
        """
        partial = self.entries[:up_to_index]
        transcript_data = json.dumps(partial, sort_keys=False).encode('utf-8')
        return sha256_hex(transcript_data)
