# Secure Encrypted Chat with Perfect Forward Secrecy (PFS)

A practical implementation of end-to-end encrypted chat with Perfect Forward Secrecy, demonstrating modern cryptographic protocols.

**Authors:** Harshavardhan Reddy (230953396), Kshitij Singh (230953460)  
**Institution:** Manipal Institute of Technology, MAHE

## Overview

This project implements a secure multi-user chat application with:
- **Perfect Forward Secrecy (PFS)** through key ratcheting
- **End-to-end encryption** using X25519 ECDH + AES-256-GCM
- **Untrusted relay server** (server never sees plaintext)
- **Graphical user interface** built with Tkinter
- **Encrypted file transfer** capability
- **Real-time key ratcheting** demonstration

## Security Features

### Cryptographic Primitives
- **X25519 ECDH**: Elliptic Curve Diffie-Hellman key exchange
- **HKDF**: Hash-based Key Derivation Function (SHA-256)
- **AES-256-GCM**: Authenticated encryption with 256-bit keys
- **12-byte nonces**: Random nonces for each message (GCM standard)

### Perfect Forward Secrecy
- Ephemeral key pairs generated for each session
- Automatic ratcheting every 50 messages (configurable)
- Manual ratcheting available via UI
- Old keys are discarded after ratchet (cannot decrypt past messages)
- New keys cannot decrypt old ciphertext

### Threat Model
**Protects against:**
- Passive eavesdropping on network traffic
- Retrospective decryption (key compromise)
- Traffic analysis (encrypted metadata)
- Man-in-the-middle (authenticated encryption)

**Does NOT protect against:**
- Endpoint compromise (malware on client)
- Active MITM during key exchange (no PKI/CA in this demo)
- Denial of service attacks

## Project Structure

```
secure-chat-pfs/
├── server/
│   └── server.py              # TCP relay server
├── client/
│   ├── client.py              # Main GUI application
│   └── ui_components.py       # Tkinter widgets
├── crypto/
│   └── crypto_utils.py        # Cryptographic operations
├── tests/
│   ├── test_crypto.py         # Crypto unit tests
│   └── test_transfer.py       # File transfer tests
├── docs/
│   ├── README.md              # This file
│   ├── RUNNING.md             # Lab demonstration guide
│   └── THREAT_MODEL.md        # Security analysis
├── requirements.txt           # Python dependencies
└── demo_script.sh             # Quick demo launcher
```

## Requirements

### Hardware
- Processor: Intel i3/i5 or equivalent (2+ GHz)
- RAM: 4 GB minimum
- Network: LAN/Wi-Fi connection

### Software
- Python 3.10 or higher
- Operating System: Windows, Linux, or macOS
- Wireshark (for traffic analysis demonstration)

## Installation

1. **Clone or extract the project:**
   ```bash
   cd secure-chat-pfs
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Verify installation:**
   ```bash
   python -c "from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey; print('✓ Cryptography installed')"
   ```

## Quick Start

### Option 1: Using Demo Script (Linux/macOS)

```bash
chmod +x demo_script.sh
./demo_script.sh
```

This launches the server and two clients (Alice and Bob) automatically.

### Option 2: Manual Launch

**Terminal 1 - Start Server:**
```bash
cd server
python server.py
```

**Terminal 2 - Start Client 1 (Alice):**
```bash
cd client
python client.py Alice
```

**Terminal 3 - Start Client 2 (Bob):**
```bash
cd client
python client.py Bob
```

### Using the Chat

1. Both clients should show "Connected to server"
2. Select a user from the "Connected Users" list
3. Key exchange happens automatically
4. Chat messages appear with color coding:
   - **Blue**: Your messages
   - **Green**: Received messages
   - **Red**: System messages
5. Click "Force Rekey" to manually trigger key ratcheting
6. Click "Show Ciphertext" to view raw encrypted data
7. Click "Attach File" to send encrypted files

## Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_crypto.py -v

# Run with coverage
pytest tests/ --cov=crypto --cov=client --cov=server
```

**Expected test results:**
- ✓ Basic encryption/decryption
- ✓ Key fingerprint matching
- ✓ Ratcheting changes keys
- ✓ Forward secrecy (old messages unreadable after ratchet)
- ✓ File transfer round-trip

## Configuration

### Server Settings (server/server.py)
```python
SERVER_HOST = '0.0.0.0'    # Listen on all interfaces
SERVER_PORT = 5555         # Default port
MAX_CLIENTS = 10           # Maximum concurrent clients
```

### Client Settings (crypto/crypto_utils.py)
```python
auto_ratchet_interval = 50  # Messages before auto-ratchet (0 to disable)
```

### File Transfer (client/client.py)
```python
FILE_CHUNK_SIZE = 8192      # 8KB chunks
```

## Key Concepts Explained

### Key Exchange Flow
1. Alice generates ephemeral X25519 key pair (private_A, public_A)
2. Bob generates ephemeral X25519 key pair (private_B, public_B)
3. Keys exchanged via server (server only sees public keys)
4. Both compute shared secret: s = X25519(private_A, public_B)
5. Derive symmetric key: K = HKDF(s, salt, session_id)
6. Use K for AES-256-GCM encryption

### Ratcheting Process
1. Generate new ephemeral key pairs
2. Exchange new public keys
3. Derive new symmetric key
4. **Discard old private key** (critical for PFS!)
5. Old ciphertext cannot be decrypted with new key

### Message Format (JSON)
```json
{
  "type": "message",
  "from": "Alice",
  "to": "Bob",
  "encrypted": {
    "ciphertext": "base64_encoded_ciphertext",
    "nonce": "base64_encoded_nonce",
    "ratchet_count": 0,
    "message_count": 5
  }
}
```

## Demonstration Guide

See [docs/RUNNING.md](docs/RUNNING.md) for detailed lab demonstration steps including:
- Wireshark capture setup
- Traffic analysis filters
- PFS verification procedures
- Example outputs and screenshots

## Troubleshooting

### Connection Issues
- **Server not reachable**: Check firewall settings, use `127.0.0.1` for local testing
- **Port in use**: Change `SERVER_PORT` to different value (e.g., 5556)

### Encryption Issues
- **Key exchange timeout**: Restart both clients
- **Decryption failure**: Ensure both clients have completed handshake

### GUI Issues
- **Window not appearing**: Check Tkinter installation: `python -m tkinter`
- **Slow performance**: Reduce `FILE_CHUNK_SIZE` for file transfers

## Security Notes

⚠️ **This is an educational project.** For production use, add:
- Certificate-based authentication (prevent MITM)
- Message ordering and replay protection
- Secure key storage (OS keychain)
- Forward error correction
- DoS protection on server

## License

Educational project for Manipal Institute of Technology.

## References

- [Signal Protocol](https://signal.org/docs/)
- [pyca/cryptography documentation](https://cryptography.io/)
- RFC 7748: X25519 Elliptic Curve Diffie-Hellman
- NIST SP 800-38D: Galois/Counter Mode (GCM)

## Contact

For questions or issues:
- Harshavardhan Reddy: 230953396
- Kshitij Singh: 230953460

---

**Last Updated:** October 2025
