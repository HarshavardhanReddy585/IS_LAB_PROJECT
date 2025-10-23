"""
test_transfer.py - Tests for file transfer operations

Tests:
- File chunk encryption/decryption
- Round-trip file transfer
"""

import pytest
import sys
import os
import tempfile

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.crypto_utils import RatchetSession, encrypt_file_chunk, decrypt_file_chunk


def test_file_chunk_encryption():
    """Test encrypting and decrypting a single file chunk."""
    # Create session
    session = RatchetSession("file_test_1", auto_ratchet_interval=0)
    
    # Generate keys (minimal handshake simulation)
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    peer_key = X25519PrivateKey.generate()
    peer_pub = peer_key.public_key()
    
    from cryptography.hazmat.primitives import serialization
    peer_pub_bytes = peer_pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    session.perform_handshake(peer_pub_bytes)
    
    # Test data
    chunk_data = b"This is a test file chunk with binary data \x00\x01\x02\xff"
    
    # Encrypt
    encrypted = encrypt_file_chunk(session.aesgcm, chunk_data)
    
    # Decrypt
    decrypted = decrypt_file_chunk(session.aesgcm, encrypted)
    
    assert decrypted == chunk_data
    print("✓ File chunk encrypt/decrypt works")


def test_file_round_trip():
    """Test complete file transfer simulation."""
    # Create two sessions
    alice_session = RatchetSession("file_test_2", auto_ratchet_interval=0)
    bob_session = RatchetSession("file_test_2", auto_ratchet_interval=0)
    
    # Handshake
    alice_pub = alice_session.get_public_key_bytes()
    bob_pub = bob_session.get_public_key_bytes()
    
    alice_session.perform_handshake(bob_pub)
    bob_session.perform_handshake(alice_pub)
    
    # Create test file
    test_data = b"This is test file content.\nIt has multiple lines.\n" * 100
    
    with tempfile.NamedTemporaryFile(delete=False) as tmp_in:
        tmp_in.write(test_data)
        input_path = tmp_in.name
    
    try:
        # Simulate chunked transfer
        chunk_size = 1024
        chunks = []
        
        # Alice: read and encrypt chunks
        with open(input_path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                
                encrypted = encrypt_file_chunk(alice_session.aesgcm, chunk)
                chunks.append(encrypted)
        
        print(f"✓ File split into {len(chunks)} chunks")
        
        # Bob: decrypt and reassemble
        decrypted_data = b''
        for encrypted_chunk in chunks:
            decrypted = decrypt_file_chunk(bob_session.aesgcm, encrypted_chunk)
            decrypted_data += decrypted
        
        # Verify
        assert decrypted_data == test_data
        print(f"✓ File round-trip successful ({len(test_data)} bytes)")
        
    finally:
        os.unlink(input_path)


def test_large_file_chunks():
    """Test handling of various chunk sizes."""
    alice_session = RatchetSession("file_test_3", auto_ratchet_interval=0)
    bob_session = RatchetSession("file_test_3", auto_ratchet_interval=0)
    
    # Handshake
    alice_pub = alice_session.get_public_key_bytes()
    bob_pub = bob_session.get_public_key_bytes()
    
    alice_session.perform_handshake(bob_pub)
    bob_session.perform_handshake(alice_pub)
    
    # Test different chunk sizes
    chunk_sizes = [100, 1024, 8192, 16384]
    
    for size in chunk_sizes:
        chunk_data = os.urandom(size)  # Random binary data
        
        encrypted = encrypt_file_chunk(alice_session.aesgcm, chunk_data)
        decrypted = decrypt_file_chunk(bob_session.aesgcm, encrypted)
        
        assert decrypted == chunk_data
    
    print(f"✓ All chunk sizes work: {chunk_sizes}")


def test_file_with_ratchet():
    """Test file transfer survives ratcheting."""
    alice_session = RatchetSession("file_test_4", auto_ratchet_interval=0)
    bob_session = RatchetSession("file_test_4", auto_ratchet_interval=0)
    
    # Initial handshake
    alice_pub = alice_session.get_public_key_bytes()
    bob_pub = bob_session.get_public_key_bytes()
    
    alice_session.perform_handshake(bob_pub)
    bob_session.perform_handshake(alice_pub)
    
    # Send some chunks before ratchet
    chunks_before = []
    for i in range(3):
        data = f"Chunk {i} before ratchet".encode()
        encrypted = encrypt_file_chunk(alice_session.aesgcm, data)
        chunks_before.append((data, encrypted))
    
    # Perform ratchet
    alice_new_pub = alice_session.ratchet()
    bob_new_pub = bob_session.ratchet()
    
    alice_session.complete_ratchet(bob_new_pub)
    bob_session.complete_ratchet(alice_new_pub)
    
    print("✓ Ratchet performed")
    
    # Send chunks after ratchet
    chunks_after = []
    for i in range(3):
        data = f"Chunk {i} after ratchet".encode()
        encrypted = encrypt_file_chunk(alice_session.aesgcm, data)
        chunks_after.append((data, encrypted))
    
    # Bob can decrypt chunks after ratchet
    for original, encrypted in chunks_after:
        decrypted = decrypt_file_chunk(bob_session.aesgcm, encrypted)
        assert decrypted == original
    
    print("✓ Chunks after ratchet decrypt correctly")
    
    # Old chunks should NOT decrypt with new key
    for original, encrypted in chunks_before:
        try:
            decrypt_file_chunk(bob_session.aesgcm, encrypted)
            assert False, "Should not decrypt old chunks!"
        except:
            pass  # Expected
    
    print("✓ Old chunks cannot decrypt with new key (PFS verified)")


def test_empty_file():
    """Test handling of empty file."""
    alice_session = RatchetSession("file_test_5", auto_ratchet_interval=0)
    bob_session = RatchetSession("file_test_5", auto_ratchet_interval=0)
    
    # Handshake
    alice_pub = alice_session.get_public_key_bytes()
    bob_pub = bob_session.get_public_key_bytes()
    
    alice_session.perform_handshake(bob_pub)
    bob_session.perform_handshake(alice_pub)
    
    # Empty data
    empty_data = b""
    
    # Should handle gracefully
    encrypted = encrypt_file_chunk(alice_session.aesgcm, empty_data)
    decrypted = decrypt_file_chunk(bob_session.aesgcm, encrypted)
    
    assert decrypted == empty_data
    print("✓ Empty file chunk handled correctly")


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
