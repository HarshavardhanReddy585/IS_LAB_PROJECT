"""
crypto_utils.py - Core cryptographic operations for PFS chat

This module implements:
- X25519 Elliptic Curve Diffie-Hellman key exchange
- HKDF key derivation
- AES-256-GCM encryption/decryption
- Key ratcheting for Perfect Forward Secrecy

Security properties:
- Forward secrecy through ephemeral key pairs
- Authenticated encryption with AES-GCM
- Key derivation with HKDF prevents key reuse
- Ratcheting ensures past keys cannot decrypt new messages
"""

import os
import hashlib
import json
import base64
from typing import Tuple, Optional, Dict, Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.backends import default_backend


class RatchetSession:
    """
    Manages a secure session with Perfect Forward Secrecy.
    
    Key Features:
    - Ephemeral X25519 key pairs for each session/ratchet
    - HKDF-based key derivation
    - AES-256-GCM for authenticated encryption
    - Automatic and manual ratcheting support
    """
    
    def __init__(self, session_id: str, auto_ratchet_interval: int = 50):
        """
        Initialize a new ratchet session.
        
        Args:
            session_id: Unique identifier for this session
            auto_ratchet_interval: Number of messages before auto-ratchet (0 to disable)
        """
        self.session_id = session_id
        self.auto_ratchet_interval = auto_ratchet_interval
        
        # Generate initial ephemeral key pair
        self.private_key = X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        
        # Peer's public key (set during handshake)
        self.peer_public_key: Optional[X25519PublicKey] = None
        
        # Derived symmetric key
        self.symmetric_key: Optional[bytes] = None
        self.aesgcm: Optional[AESGCM] = None
        
        # Ratchet tracking
        self.ratchet_count = 0
        self.message_count = 0
        
        # Salt for HKDF (constant per session for deterministic derivation on both sides)
        self.salt = hashlib.sha256(session_id.encode()).digest()
        
    def get_public_key_bytes(self) -> bytes:
        """Get current public key as bytes."""
        from cryptography.hazmat.primitives import serialization
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    def perform_handshake(self, peer_public_key_bytes: bytes) -> None:
        """
        Perform ECDH key exchange and derive symmetric key.
        
        Args:
            peer_public_key_bytes: Raw bytes of peer's X25519 public key
            
        Security note: This establishes the shared secret and derives
        a symmetric key using HKDF with the session_id as context.
        """
        # Load peer's public key
        self.peer_public_key = X25519PublicKey.from_public_bytes(peer_public_key_bytes)
        
        # Perform ECDH to get shared secret
        shared_secret = self.private_key.exchange(self.peer_public_key)
        
        # Derive symmetric key using HKDF
        # Info parameter includes session_id and ratchet_count for uniqueness
        info = f"{self.session_id}:ratchet{self.ratchet_count}".encode()
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits for AES-256
            salt=self.salt,
            info=info,
            backend=default_backend()
        )
        self.symmetric_key = hkdf.derive(shared_secret)
        
        # Initialize AES-GCM cipher
        self.aesgcm = AESGCM(self.symmetric_key)
        
        print(f"[CRYPTO] Handshake complete. Key fingerprint: {self.get_key_fingerprint()}")
        
    def get_key_fingerprint(self) -> str:
        """
        Get truncated SHA-256 hash of current symmetric key for display.
        
        Returns:
            Hex string of first 8 bytes of key hash (for UI display)
        """
        if not self.symmetric_key:
            return "NO_KEY"
        key_hash = hashlib.sha256(self.symmetric_key).digest()
        return key_hash[:8].hex().upper()
    
    def encrypt(self, plaintext: str) -> Dict[str, Any]:
        """
        Encrypt a message using AES-256-GCM.
        
        Args:
            plaintext: Message to encrypt
            
        Returns:
            Dictionary with ciphertext (base64), nonce (base64), and metadata
            
        Raises:
            ValueError: If handshake not completed
        """
        if not self.symmetric_key or not self.aesgcm:
            raise ValueError("Handshake not completed. Cannot encrypt.")
        
        # Generate random 12-byte nonce (96 bits, recommended for GCM)
        nonce = os.urandom(12)
        
        # Encrypt with AES-GCM (includes authentication tag)
        ciphertext = self.aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        
        # Increment message counter
        self.message_count += 1
        
        # Check if auto-ratchet needed
        needs_ratchet = (self.auto_ratchet_interval > 0 and 
                        self.message_count >= self.auto_ratchet_interval)
        
        # Return encrypted message with metadata
        return {
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'ratchet_count': self.ratchet_count,
            'message_count': self.message_count,
            'needs_ratchet': needs_ratchet
        }
    
    def decrypt(self, encrypted_data: Dict[str, Any]) -> str:
        """
        Decrypt a message using AES-256-GCM.
        
        Args:
            encrypted_data: Dictionary with ciphertext and nonce (base64)
            
        Returns:
            Decrypted plaintext string
            
        Raises:
            ValueError: If handshake not completed or authentication fails
        """
        if not self.symmetric_key or not self.aesgcm:
            raise ValueError("Handshake not completed. Cannot decrypt.")
        
        try:
            # Decode base64
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            nonce = base64.b64decode(encrypted_data['nonce'])
            
            # Decrypt and verify authentication tag
            plaintext_bytes = self.aesgcm.decrypt(nonce, ciphertext, None)
            
            return plaintext_bytes.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
    def ratchet(self) -> bytes:
        """
        Perform key ratcheting to establish new session key.
        
        This implements Perfect Forward Secrecy:
        - Generates new ephemeral X25519 key pair
        - Old private key is discarded (cannot decrypt future messages)
        - New key must be exchanged with peer
        
        Returns:
            New public key bytes to send to peer
            
        Security note: After ratchet, old key is overwritten and
        messages encrypted with old key cannot be decrypted with new key.
        """
        # Increment ratchet counter
        self.ratchet_count += 1
        self.message_count = 0  # Reset message counter
        
        # Generate new ephemeral key pair
        self.private_key = X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        
        # Clear old symmetric key (security: prevent reuse)
        self.symmetric_key = None
        self.aesgcm = None
        
        print(f"[CRYPTO] Ratchet #{self.ratchet_count} initiated. New key pair generated.")
        
        return self.get_public_key_bytes()
    
    def complete_ratchet(self, peer_new_public_key_bytes: bytes) -> None:
        """
        Complete ratchet by exchanging new keys with peer.
        
        Args:
            peer_new_public_key_bytes: Peer's new public key after ratchet
        """
        # Perform new handshake with new keys
        self.perform_handshake(peer_new_public_key_bytes)
        print(f"[CRYPTO] Ratchet #{self.ratchet_count} complete. New key fingerprint: {self.get_key_fingerprint()}")


def encrypt_file_chunk(aesgcm: AESGCM, chunk_data: bytes) -> Dict[str, str]:
    """
    Encrypt a file chunk using AES-GCM.
    
    Args:
        aesgcm: Initialized AES-GCM cipher
        chunk_data: Raw bytes to encrypt
        
    Returns:
        Dictionary with encrypted chunk and nonce (base64)
    """
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, chunk_data, None)
    
    return {
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
        'nonce': base64.b64encode(nonce).decode('utf-8')
    }


def decrypt_file_chunk(aesgcm: AESGCM, encrypted_chunk: Dict[str, str]) -> bytes:
    """
    Decrypt a file chunk using AES-GCM.
    
    Args:
        aesgcm: Initialized AES-GCM cipher
        encrypted_chunk: Dictionary with ciphertext and nonce (base64)
        
    Returns:
        Decrypted bytes
    """
    ciphertext = base64.b64decode(encrypted_chunk['ciphertext'])
    nonce = base64.b64decode(encrypted_chunk['nonce'])
    
    return aesgcm.decrypt(nonce, ciphertext, None)
