"""
test_crypto.py - Unit tests for cryptographic operations

Tests:
- E2E encryption/decryption
- Key ratcheting
- Forward secrecy validation
"""

import pytest
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.crypto_utils import RatchetSession


def test_basic_encryption_decryption():
    """Test basic encrypt/decrypt flow."""
    # Create two sessions
    alice_session = RatchetSession("test_session_1", auto_ratchet_interval=0)
    bob_session = RatchetSession("test_session_1", auto_ratchet_interval=0)
    
    # Exchange keys
    alice_pub = alice_session.get_public_key_bytes()
    bob_pub = bob_session.get_public_key_bytes()
    
    alice_session.perform_handshake(bob_pub)
    bob_session.perform_handshake(alice_pub)
    
    # Test message
    plaintext = "Hello, Bob! This is a secret message."
    
    # Alice encrypts
    encrypted = alice_session.encrypt(plaintext)
    
    # Bob decrypts
    decrypted = bob_session.decrypt(encrypted)
    
    assert decrypted == plaintext
    print("✓ Basic encryption/decryption works")


def test_key_fingerprint_match():
    """Test that both parties derive same key."""
    alice_session = RatchetSession("test_session_2", auto_ratchet_interval=0)
    bob_session = RatchetSession("test_session_2", auto_ratchet_interval=0)
    
    # Exchange keys
    alice_pub = alice_session.get_public_key_bytes()
    bob_pub = bob_session.get_public_key_bytes()
    
    alice_session.perform_handshake(bob_pub)
    bob_session.perform_handshake(alice_pub)
    
    # Check fingerprints match
    alice_fp = alice_session.get_key_fingerprint()
    bob_fp = bob_session.get_key_fingerprint()
    
    assert alice_fp == bob_fp
    print(f"✓ Key fingerprints match: {alice_fp}")


def test_ratchet_changes_key():
    """Test that ratcheting produces new key."""
    alice_session = RatchetSession("test_session_3", auto_ratchet_interval=0)
    bob_session = RatchetSession("test_session_3", auto_ratchet_interval=0)
    
    # Initial handshake
    alice_pub = alice_session.get_public_key_bytes()
    bob_pub = bob_session.get_public_key_bytes()
    
    alice_session.perform_handshake(bob_pub)
    bob_session.perform_handshake(alice_pub)
    
    # Get initial fingerprint
    initial_fp = alice_session.get_key_fingerprint()
    
    # Perform ratchet
    alice_new_pub = alice_session.ratchet()
    bob_new_pub = bob_session.ratchet()
    
    alice_session.complete_ratchet(bob_new_pub)
    bob_session.complete_ratchet(alice_new_pub)
    
    # Get new fingerprint
    new_fp = alice_session.get_key_fingerprint()
    
    # Fingerprints should be different
    assert initial_fp != new_fp
    print(f"✓ Ratchet changed key: {initial_fp} → {new_fp}")
    
    # But should still match between parties
    assert alice_session.get_key_fingerprint() == bob_session.get_key_fingerprint()
    print("✓ Keys still match after ratchet")


def test_forward_secrecy():
    """
    Test Perfect Forward Secrecy:
    Old ciphertext cannot be decrypted with new key after ratchet.
    """
    alice_session = RatchetSession("test_session_4", auto_ratchet_interval=0)
    bob_session = RatchetSession("test_session_4", auto_ratchet_interval=0)
    
    # Initial handshake
    alice_pub = alice_session.get_public_key_bytes()
    bob_pub = bob_session.get_public_key_bytes()
    
    alice_session.perform_handshake(bob_pub)
    bob_session.perform_handshake(alice_pub)
    
    # Encrypt message with old key
    plaintext = "Message with old key"
    old_encrypted = alice_session.encrypt(plaintext)
    
    # Bob can decrypt with old key
    decrypted_old = bob_session.decrypt(old_encrypted)
    assert decrypted_old == plaintext
    print("✓ Bob decrypts with old key")
    
    # Perform ratchet (generates new keys)
    alice_new_pub = alice_session.ratchet()
    bob_new_pub = bob_session.ratchet()
    
    alice_session.complete_ratchet(bob_new_pub)
    bob_session.complete_ratchet(alice_new_pub)
    
    # Try to decrypt old message with new key
    # This should FAIL - demonstrating forward secrecy
    try:
        bob_session.decrypt(old_encrypted)
        assert False, "Should not decrypt old message with new key!"
    except ValueError:
        print("✓ Old message CANNOT be decrypted with new key (PFS works!)")
    
    # New message with new key should work
    new_plaintext = "Message with new key"
    new_encrypted = alice_session.encrypt(new_plaintext)
    decrypted_new = bob_session.decrypt(new_encrypted)
    assert decrypted_new == new_plaintext
    print("✓ New message decrypts with new key")


def test_ratchet_count():
    """Test ratchet counter increments correctly."""
    session = RatchetSession("test_session_5", auto_ratchet_interval=0)
    
    assert session.ratchet_count == 0
    
    session.ratchet()
    assert session.ratchet_count == 1
    
    session.ratchet()
    assert session.ratchet_count == 2
    
    print("✓ Ratchet count increments correctly")


def test_multiple_messages():
    """Test multiple messages in sequence."""
    alice_session = RatchetSession("test_session_6", auto_ratchet_interval=0)
    bob_session = RatchetSession("test_session_6", auto_ratchet_interval=0)
    
    # Handshake
    alice_pub = alice_session.get_public_key_bytes()
    bob_pub = bob_session.get_public_key_bytes()
    
    alice_session.perform_handshake(bob_pub)
    bob_session.perform_handshake(alice_pub)
    
    # Send multiple messages
    messages = [
        "First message",
        "Second message",
        "Third message with special chars: !@#$%^&*()",
        "Fourth message with unicode: 你好 мир"
    ]
    
    for msg in messages:
        encrypted = alice_session.encrypt(msg)
        decrypted = bob_session.decrypt(encrypted)
        assert decrypted == msg
    
    print(f"✓ All {len(messages)} messages encrypted/decrypted correctly")


def test_auto_ratchet():
    """Test automatic ratcheting after message threshold."""
    alice_session = RatchetSession("test_session_7", auto_ratchet_interval=3)
    bob_session = RatchetSession("test_session_7", auto_ratchet_interval=3)
    
    # Handshake
    alice_pub = alice_session.get_public_key_bytes()
    bob_pub = bob_session.get_public_key_bytes()
    
    alice_session.perform_handshake(bob_pub)
    bob_session.perform_handshake(alice_pub)
    
    # Send messages
    for i in range(5):
        encrypted = alice_session.encrypt(f"Message {i}")
        
        # Check if ratchet needed
        if i >= 2:  # After 3rd message (0, 1, 2)
            assert encrypted.get('needs_ratchet') == True
            break
    
    print("✓ Auto-ratchet flag set correctly")


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
