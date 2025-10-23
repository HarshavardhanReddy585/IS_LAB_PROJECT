# Secure Encrypted Chat with Perfect Forward Secrecy (PFS)

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive implementation of a secure multi-user chat system demonstrating **Perfect Forward Secrecy (PFS)** through key ratcheting, built as an academic project for Manipal Institute of Technology.

**Authors:** Harshavardhan Reddy (230953396), Kshitij Singh (230953460)  
**Supervisors:** Dr. Divya Rao, Ms. Pragya Jha

---

## 🎯 Project Objectives

- Implement end-to-end encrypted chat with industry-standard cryptography
- Demonstrate Perfect Forward Secrecy through automatic key ratcheting
- Provide untrusted relay server architecture (zero-knowledge server)
- Create user-friendly GUI for cryptographic operations
- Enable secure file transfer with chunked encryption
- Demonstrate security properties via Wireshark traffic analysis

## ✨ Key Features

### Cryptographic Security
- **X25519 ECDH** key exchange for ephemeral session keys
- **AES-256-GCM** authenticated encryption (confidentiality + integrity)
- **HKDF** (SHA-256) for secure key derivation
- **Perfect Forward Secrecy** via automatic and manual key ratcheting
- **12-byte random nonces** for each message (GCM standard)

### User Experience
- **Tkinter GUI** with intuitive chat interface
- **Real-time key fingerprint** display for verification
- **Ratchet counter** showing security refreshes
- **Ciphertext inspection** for educational purposes
- **File transfer** with progress indication
- **Multi-user support** with independent sessions
- **Group chat** with encrypted messaging for multiple participants

### Demonstration Features
- **Wireshark integration** for traffic analysis
- **Visual key ratcheting** with before/after fingerprints
- **Comprehensive unit tests** validating PFS properties
- **Detailed documentation** for lab presentation

## 📁 Project Structure

```
secure-chat-pfs/
│
├── crypto/                    # Cryptographic operations
│   ├── __init__.py
│   └── crypto_utils.py       # RatchetSession, GroupSession, encryption/decryption
│
├── server/                    # Relay server (untrusted)
│   ├── __init__.py
│   └── server.py             # TCP relay, message routing, group management
│
├── client/                    # GUI client application
│   ├── __init__.py
│   ├── client.py             # Main application logic (with group chat support)
│   └── ui_components.py      # Tkinter widgets (including group UI)
│
├── tests/                     # Unit tests
│   ├── __init__.py
│   ├── test_crypto.py        # Encryption/ratcheting tests
│   └── test_transfer.py      # File transfer tests
│
├── docs/                      # Documentation
│   ├── README.md             # Detailed project guide
│   ├── RUNNING.md            # Lab demonstration steps
│   └── THREAT_MODEL.md       # Security analysis
│
├── requirements.txt           # Python dependencies
├── demo_script.sh            # Quick demo launcher
└── README.md                 # This file
```

## 🚀 Quick Start

### 1. Install Dependencies

```bash
# Ensure Python 3.10+ is installed
python3 --version

# Install required packages
pip install -r requirements.txt
```

### 2. Run Tests (Verify Setup)

```bash
pytest tests/ -v
```

Expected output:
```
✓ test_basic_encryption_decryption PASSED
✓ test_key_fingerprint_match PASSED
✓ test_ratchet_changes_key PASSED
✓ test_forward_secrecy PASSED
✓ test_file_round_trip PASSED
```

### 3. Launch Demo

**Option A: Automated (Linux/macOS)**
```bash
chmod +x demo_script.sh
./demo_script.sh
```

**Option B: Manual Launch**

**Terminal 1 - Server:**
```bash
cd server
python3 server.py
```

**Terminal 2 - Client (Alice):**
```bash
cd client
python3 client.py Alice
```

**Terminal 3 - Client (Bob):**
```bash
cd client
python3 client.py Bob
```

### 4. Start Chatting

**One-on-One Chat:**
1. In Alice's window: Click "Bob" in user list
2. In Bob's window: Click "Alice" in user list
3. Wait for automatic key exchange
4. Verify key fingerprints match in both windows
5. Start sending encrypted messages!

**Group Chat:**
1. In Alice's window: Click "Create Group" button
2. Enter a group name (e.g., "Team Chat")
3. Select members to add (e.g., Bob, Charlie)
4. Click "Create" - Alice generates a shared group key
5. Group keys are distributed to members via encrypted 1-on-1 sessions
6. All members can now select the group and send encrypted messages
7. Messages are encrypted with the shared group key (AES-256-GCM)

## 🔐 Security Architecture

### Encryption Flow

```
┌─────────┐                                    ┌─────────┐
│  Alice  │                                    │   Bob   │
└────┬────┘                                    └────┬────┘
     │                                              │
     │ 1. Generate X25519 key pair                 │
     │    (private_A, public_A)                    │
     │                                              │
     │ 2. Send public_A                            │
     ├──────────────────────────────────────────►  │
     │             (via server)                    │
     │                                              │
     │                    3. Generate X25519 pair  │
     │                       (private_B, public_B) │
     │                                              │
     │  4. Send public_B                           │
     │ ◄────────────────────────────────────────── │
     │             (via server)                    │
     │                                              │
     │ 5. Compute shared secret:                   │
     │    s = X25519(private_A, public_B)          │
     │                                              │
     │ 6. Derive session key:                      │
     │    K = HKDF(s, salt, session_id)            │
     │                                              │
     │ 7. Encrypt message:                         │
     │    C = AES-GCM.encrypt(K, M, nonce)         │
     │                                              │
     │ 8. Send ciphertext                          │
     ├──────────────────────────────────────────►  │
     │                                              │
     │                         9. Decrypt message: │
     │                            M = AES-GCM.decrypt(K, C, nonce)
     │                                              │
```

### Perfect Forward Secrecy via Ratcheting

```
Time  →
─────────────────────────────────────────────────►

Key K1 ──► Messages M1-M50 ──► RATCHET ──► Key K2 ──► Messages M51-M100
    ↑                            ↑              ↑
    │                            │              │
Generated                    Old key K1     New key K2
initially                    DESTROYED!     generated

Result: M1-M50 encrypted with K1 CANNOT be decrypted with K2
        Even if K2 is compromised, M1-M50 remain secure!
```

## 🧪 Testing & Verification

### Run All Tests
```bash
pytest tests/ -v
```

### Run Specific Tests
```bash
# Test PFS property
pytest tests/test_crypto.py::test_forward_secrecy -v

# Test file transfer
pytest tests/test_transfer.py::test_file_round_trip -v
```

### Test Coverage
```bash
pytest tests/ --cov=crypto --cov=client --cov=server --cov-report=html
```

## 📊 Wireshark Demonstration

### Setup
1. Open Wireshark
2. Select Loopback interface (lo0/Loopback)
3. Apply filter: `tcp.port == 5555`
4. Start capture

### Analysis
1. Send messages in chat
2. Stop capture
3. Right-click packet → Follow → TCP Stream

**What you'll see:**
```json
{
  "type": "message",
  "from": "Alice",
  "to": "Bob",
  "encrypted": {
    "ciphertext": "3q7KP9x2m/jVY8nL+KPq4A7dF3...",  // Base64 gibberish
    "nonce": "A7xK2p9L3mN8qR4s",
    "ratchet_count": 0
  }
}
```

**Key observations:**
- ✓ No plaintext visible
- ✓ Server only sees ciphertext
- ✓ Nonce changes per message
- ✓ Traffic is encrypted end-to-end

## 📚 Documentation

Comprehensive documentation available in `docs/`:

- **[README.md](docs/README.md)** - Detailed project guide
- **[RUNNING.md](docs/RUNNING.md)** - Step-by-step lab demonstration
- **[THREAT_MODEL.md](docs/THREAT_MODEL.md)** - Security analysis and threat modeling

## 🎓 Educational Value

This project demonstrates:

1. **Modern Cryptography**
   - Industry-standard algorithms (X25519, AES-GCM, HKDF)
   - Same protocols used by Signal, WhatsApp
   - Proper key derivation and management

2. **Perfect Forward Secrecy**
   - Why PFS matters (key compromise scenarios)
   - How key ratcheting works
   - Practical implementation

3. **System Security**
   - End-to-end encryption architecture
   - Untrusted relay server design
   - Defense in depth

4. **Secure Development**
   - Unit testing for security properties
   - Threat modeling
   - Security documentation

## ⚙️ Configuration

### Server Configuration (server/server.py)
```python
SERVER_HOST = '0.0.0.0'    # Listen on all interfaces
SERVER_PORT = 5555         # Default port
MAX_CLIENTS = 10           # Maximum concurrent clients
BUFFER_SIZE = 65536        # 64KB buffer
```

### Auto-Ratchet Interval (crypto/crypto_utils.py)
```python
auto_ratchet_interval = 50  # Messages before auto-ratchet
                            # Set to 0 to disable auto-ratchet
```

### File Transfer Chunk Size (client/client.py)
```python
FILE_CHUNK_SIZE = 8192      # 8KB chunks
```

## 🛠️ Requirements

### Python Packages
- `cryptography>=41.0.0` - Cryptographic primitives
- `pytest>=7.4.0` - Testing framework
- `pytest-cov>=4.1.0` - Code coverage

### System Requirements
- Python 3.10 or higher
- Tkinter (usually included with Python)
- Network connection (LAN/Wi-Fi)
- 4 GB RAM minimum
- 100 MB disk space

## 🔧 Troubleshooting

### Common Issues

**1. Port 5555 already in use**
```bash
# Find process using port
lsof -i :5555

# Kill the process
kill -9 <PID>

# Or change port in server.py
```

**2. Tkinter not found**
```bash
# Ubuntu/Debian
sudo apt-get install python3-tk

# macOS (usually pre-installed)
# Windows (included with Python installer)
```

**3. Key exchange timeout**
- Restart both clients
- Ensure server is running
- Check firewall settings

**4. Decryption fails**
- Verify key fingerprints match
- Ensure handshake completed
- Check network connectivity

## 🚧 Known Limitations

This is an **educational project**. For production use, add:

1. **Certificate-based key authentication** (prevent MITM)
2. **Message sequence numbers** (prevent replay attacks)
3. **Rate limiting** (prevent DoS)
4. **Secure key storage** (OS keychain integration)
5. **Double ratcheting** (like Signal protocol)
6. **Group chat support** (sender keys)
7. **Offline message queuing**
8. **Mobile support** (Android/iOS)

See [THREAT_MODEL.md](docs/THREAT_MODEL.md) for detailed security analysis.

## 📖 References

- [Signal Protocol](https://signal.org/docs/) - Double Ratchet Algorithm
- [RFC 7748](https://tools.ietf.org/html/rfc7748) - X25519 Specification
- [NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final) - GCM Mode
- [pyca/cryptography](https://cryptography.io/) - Python Cryptography Library

## 📝 License

This project is developed for educational purposes at Manipal Institute of Technology.

## 👥 Authors

**Harshavardhan Reddy** - Registration No. 230953396  
**Kshitij Singh** - Registration No. 230953460

**Supervisors:**
- Dr. Divya Rao - Associate Professor
- Ms. Pragya Jha - Assistant Professor

School of Computer Engineering  
Manipal Institute of Technology, MAHE  
Manipal, India

---

## 🎬 Demo Video

For a visual walkthrough, refer to the lab demonstration guidelines in [RUNNING.md](docs/RUNNING.md).

## 🙏 Acknowledgments

- Manipal Institute of Technology for project support
- pyca/cryptography team for excellent documentation
- Signal Foundation for protocol research

---

**⭐ Star this repository if you found it helpful!**

**🔐 Remember: Security is a process, not a product.**
