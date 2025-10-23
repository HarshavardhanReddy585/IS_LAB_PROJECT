# Quick Usage Guide

## Installation & Setup

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Verify installation
pytest tests/ -v

# 3. Make demo script executable (Linux/macOS)
chmod +x demo_script.sh
```

## Running the Application

### Method 1: Demo Script (Recommended for First-Time)
```bash
./demo_script.sh
```

### Method 2: Manual Launch

**Start Server:**
```bash
cd server
python3 server.py
# Server listens on 0.0.0.0:5555
```

**Start Client 1 (Alice):**
```bash
cd client
python3 client.py Alice
# Connects to localhost:5555 by default
```

**Start Client 2 (Bob):**
```bash
cd client
python3 client.py Bob
```

**Custom Host/Port:**
```bash
python3 client.py Username <host> <port>
# Example:
python3 client.py Alice 192.168.1.100 5555
```

## GUI Controls

### Main Window Components

```
┌─────────────────────────────────────────────────────────┐
│  Secure Chat - Alice                              [_][□][×]
├───────────────┬─────────────────────────────────────────┤
│  Connected    │  Chat Messages                          │
│  Users        │  ┌─────────────────────────────────┐   │
│  ┌─────────┐  │  │                                 │   │
│  │  Bob    │  │  │  System: Connected!             │   │
│  │  Charlie│  │  │  System: Session established    │   │
│  │         │  │  │  You: Hello Bob!                │   │
│  │         │  │  │  Bob: Hi Alice!                 │   │
│  └─────────┘  │  │                                 │   │
│               │  └─────────────────────────────────┘   │
│               │                                         │
│               │  Encryption Info                        │
│               │  Key Fingerprint: A1B2C3D4E5F6G7H8      │
│               │  Ratchet Count: 0                       │
│               │  Session ID: Alice:Bob:1234...          │
│               │  [Force Rekey] [Show Ciphertext]        │
│               │                                         │
│               │  ┌────────────────────────────────┐    │
│               │  │ Type message...                │    │
│               │  └────────────────────────────────┘    │
│               │  [Send] [Attach File]                   │
├───────────────┴─────────────────────────────────────────┤
│  Status: Connected to server                      ● │
└─────────────────────────────────────────────────────────┘
```

### Button Functions

| Button | Action |
|--------|--------|
| **Send** | Encrypt and send typed message |
| **Attach File** | Open file picker and send encrypted file |
| **Force Rekey** | Manually trigger key ratcheting (PFS demo) |
| **Show Ciphertext** | Display raw encrypted data for demonstration |

### Color Coding

- **Blue text**: Your sent messages
- **Green text**: Received messages
- **Red text**: System messages (connection, key exchange, errors)
- **Green indicator**: Connected to server
- **Red indicator**: Disconnected

## Step-by-Step First Use

1. **Start Server**
   ```bash
   python3 server.py
   ```
   Wait for: `[SERVER] Waiting for connections...`

2. **Start Alice**
   ```bash
   python3 client.py Alice
   ```
   GUI opens, shows "Connected to server"

3. **Start Bob**
   ```bash
   python3 client.py Bob
   ```
   GUI opens, both see each other in user list

4. **Establish Session (Alice's side)**
   - Click "Bob" in user list
   - See: "Initiating key exchange..."
   - See: "Secure session established"
   - Note: Key Fingerprint (e.g., "A1B2C3D4...")

5. **Establish Session (Bob's side)**
   - Click "Alice" in user list
   - See: "Secure session established"
   - Verify: Same key fingerprint as Alice

6. **Send Messages**
   - Type in input box
   - Press Enter or click "Send"
   - Message appears in blue (sent)
   - Appears in green on other side (received)

7. **Demonstrate Encryption**
   - Click "Show Ciphertext" after sending
   - See base64-encoded encrypted data
   - Compare with Wireshark capture

8. **Demonstrate PFS**
   - Note current key fingerprint
   - Click "Force Rekey"
   - Note NEW key fingerprint (different!)
   - Ratchet count increments
   - Old messages can't be decrypted with new key

9. **Send File**
   - Click "Attach File"
   - Select any file
   - Progress dialog shows transfer
   - Recipient gets save dialog
   - File decrypted and saved

## Command-Line Arguments

### Server
```bash
python3 server.py [port]

# Examples:
python3 server.py           # Uses default port 5555
python3 server.py 6000      # Uses port 6000
```

### Client
```bash
python3 client.py <username> [host] [port]

# Examples:
python3 client.py Alice                      # localhost:5555
python3 client.py Bob localhost 6000         # Custom port
python3 client.py Charlie 192.168.1.100 5555 # Remote server
```

## Testing Commands

### Run All Tests
```bash
pytest tests/ -v
```

### Run Specific Test
```bash
# Test encryption
pytest tests/test_crypto.py::test_basic_encryption_decryption -v

# Test forward secrecy
pytest tests/test_crypto.py::test_forward_secrecy -v

# Test file transfer
pytest tests/test_transfer.py::test_file_round_trip -v
```

### Test with Coverage
```bash
pytest tests/ --cov=crypto --cov=client --cov=server --cov-report=term-missing
```

### Generate HTML Coverage Report
```bash
pytest tests/ --cov=crypto --cov=client --cov=server --cov-report=html
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
```

## Wireshark Setup

### Quick Setup
1. Open Wireshark
2. Interface: Select "Loopback: lo0" (macOS) or "Loopback" (Windows/Linux)
3. Filter: `tcp.port == 5555`
4. Click green shark fin to start
5. Send messages in chat
6. Click red square to stop
7. Analyze captured packets

### Useful Filters
```
# All chat traffic
tcp.port == 5555

# Only data packets
tcp.port == 5555 and tcp.len > 0

# Specific message types
tcp.port == 5555 and frame contains "message"
tcp.port == 5555 and frame contains "key_exchange"
tcp.port == 5555 and frame contains "ratchet"
```

### Follow TCP Stream
1. Right-click any packet
2. Follow → TCP Stream
3. See JSON messages with encrypted ciphertext
4. Verify plaintext is NOT visible

## Common Tasks

### Change Auto-Ratchet Interval
Edit `crypto/crypto_utils.py`:
```python
# Line ~30
auto_ratchet_interval = 50  # Change this number
```

### Change Server Port
Edit `server/server.py`:
```python
# Line ~16
SERVER_PORT = 5555  # Change to desired port
```

### Change File Chunk Size
Edit `client/client.py`:
```python
# Line ~25
FILE_CHUNK_SIZE = 8192  # Change to desired size in bytes
```

## Troubleshooting Quick Fixes

### Port Already in Use
```bash
# Find process
lsof -i :5555

# Kill process
kill -9 <PID>

# Or change port in server.py
```

### Client Can't Connect
```bash
# Check server is running
ps aux | grep server.py

# Try localhost explicitly
python3 client.py Alice 127.0.0.1 5555

# Check firewall
sudo ufw allow 5555  # Linux
```

### Tkinter Not Found
```bash
# Ubuntu/Debian
sudo apt-get install python3-tk

# Fedora/CentOS
sudo dnf install python3-tkinter

# Arch Linux
sudo pacman -S tk
```

### Tests Failing
```bash
# Reinstall dependencies
pip install --upgrade -r requirements.txt

# Clear cache
find . -type d -name __pycache__ -exec rm -rf {} +
pytest --cache-clear tests/
```

### GUI Not Appearing
```bash
# Test Tkinter
python3 -m tkinter

# Should open a small test window
# If not, reinstall Tkinter (see above)
```

## Performance Tips

### For Large Files
- Reduce chunk size: `FILE_CHUNK_SIZE = 4096`
- Adds more overhead but more reliable

### For Many Messages
- Disable auto-ratchet: `auto_ratchet_interval = 0`
- Use manual ratcheting only

### For Remote Servers
- Use faster port: Try port 5000 instead of 5555
- Increase buffer: `BUFFER_SIZE = 131072`

## Quick Reference Card

```
┌─────────────────────────────────────────────────────┐
│  SECURE CHAT PFS - QUICK REFERENCE                  │
├─────────────────────────────────────────────────────┤
│  START SERVER:                                      │
│    cd server && python3 server.py                   │
│                                                     │
│  START CLIENT:                                      │
│    cd client && python3 client.py <username>        │
│                                                     │
│  RUN TESTS:                                         │
│    pytest tests/ -v                                 │
│                                                     │
│  DEMO SCRIPT:                                       │
│    ./demo_script.sh                                 │
│                                                     │
│  KEY FEATURES:                                      │
│    • X25519 key exchange                            │
│    • AES-256-GCM encryption                         │
│    • Perfect Forward Secrecy                        │
│    • Encrypted file transfer                        │
│                                                     │
│  GUI CONTROLS:                                      │
│    • Select user to start chat                      │
│    • Verify key fingerprints match                  │
│    • Force Rekey = Manual ratcheting                │
│    • Show Ciphertext = See raw encryption           │
│                                                     │
│  WIRESHARK:                                         │
│    Interface: Loopback                              │
│    Filter: tcp.port == 5555                         │
│    Verify: Only ciphertext visible                  │
└─────────────────────────────────────────────────────┘
```

---

**Need more help?** See [RUNNING.md](RUNNING.md) for detailed lab demonstration guide.
