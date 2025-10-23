# Complete Command Reference

All commands needed to run, test, and demonstrate the Secure Chat with PFS project.

## Setup Commands

### Initial Installation

```bash
# Navigate to project directory
cd /Users/manikantagonugondla/Desktop/secure-chat-pfs

# Install Python dependencies
pip install -r requirements.txt

# Verify installation
python3 -c "from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey; print('✓ Installation successful')"
```

### Alternative: Use Virtual Environment (Recommended)

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# macOS/Linux:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Running the Application

### Method 1: Quick Demo (Automated)

```bash
# Make script executable
chmod +x demo_script.sh

# Run demo (launches server + 2 clients)
./demo_script.sh
```

### Method 2: Manual Launch (3 Terminals)

**Terminal 1 - Server:**
```bash
cd /Users/manikantagonugondla/Desktop/secure-chat-pfs/server
python3 server.py
```

**Terminal 2 - Client Alice:**
```bash
cd /Users/manikantagonugondla/Desktop/secure-chat-pfs/client
python3 client.py Alice
```

**Terminal 3 - Client Bob:**
```bash
cd /Users/manikantagonugondla/Desktop/secure-chat-pfs/client
python3 client.py Bob
```

### Method 3: Custom Configuration

**Server on specific port:**
```bash
cd server
python3 server.py 6000  # Run on port 6000
```

**Client connecting to remote server:**
```bash
cd client
python3 client.py Alice 192.168.1.100 6000
#                 ^       ^             ^
#                 |       |             |
#              username  host         port
```

## Testing Commands

### Run All Tests

```bash
cd /Users/manikantagonugondla/Desktop/secure-chat-pfs
pytest tests/ -v
```

**Expected output:**
```
tests/test_crypto.py::test_basic_encryption_decryption PASSED
tests/test_crypto.py::test_key_fingerprint_match PASSED
tests/test_crypto.py::test_ratchet_changes_key PASSED
tests/test_crypto.py::test_forward_secrecy PASSED
tests/test_crypto.py::test_ratchet_count PASSED
tests/test_crypto.py::test_multiple_messages PASSED
tests/test_crypto.py::test_auto_ratchet PASSED
tests/test_transfer.py::test_file_chunk_encryption PASSED
tests/test_transfer.py::test_file_round_trip PASSED
tests/test_transfer.py::test_large_file_chunks PASSED
tests/test_transfer.py::test_file_with_ratchet PASSED
tests/test_transfer.py::test_empty_file PASSED
```

### Run Specific Test Files

```bash
# Test cryptographic operations only
pytest tests/test_crypto.py -v

# Test file transfer only
pytest tests/test_transfer.py -v
```

### Run Individual Tests

```bash
# Test basic encryption
pytest tests/test_crypto.py::test_basic_encryption_decryption -v

# Test Perfect Forward Secrecy
pytest tests/test_crypto.py::test_forward_secrecy -v

# Test file transfer
pytest tests/test_transfer.py::test_file_round_trip -v
```

### Test with Coverage

```bash
# Generate coverage report
pytest tests/ --cov=crypto --cov=client --cov=server --cov-report=term-missing

# Generate HTML coverage report
pytest tests/ --cov=crypto --cov=client --cov=server --cov-report=html

# View HTML report (macOS)
open htmlcov/index.html

# View HTML report (Linux)
xdg-open htmlcov/index.html

# View HTML report (Windows)
start htmlcov/index.html
```

## Wireshark Commands

### Start Wireshark

```bash
# macOS
open -a Wireshark

# Linux
sudo wireshark &

# Windows
# Start from Start Menu or:
"C:\Program Files\Wireshark\Wireshark.exe"
```

### Capture Filters

Use these in Wireshark's capture/display filter:

```
# Capture all chat traffic
tcp.port == 5555

# Only packets with data
tcp.port == 5555 and tcp.len > 0

# Specific message types
tcp.port == 5555 and frame contains "message"
tcp.port == 5555 and frame contains "key_exchange"
tcp.port == 5555 and frame contains "ratchet"
tcp.port == 5555 and frame contains "file_chunk"
```

### Command-Line Packet Capture (Alternative)

```bash
# Capture traffic to file (Linux/macOS)
sudo tcpdump -i lo -w chat_capture.pcap port 5555

# Capture traffic to file (Linux - specific interface)
sudo tcpdump -i any -w chat_capture.pcap port 5555

# Stop capture: Press Ctrl+C

# Read capture file
tcpdump -r chat_capture.pcap -A

# Filter and read
tcpdump -r chat_capture.pcap -A port 5555
```

## Utility Commands

### Check if Port is Available

```bash
# Check if port 5555 is in use
lsof -i :5555

# Check on Linux (alternative)
netstat -tuln | grep 5555

# Check on Windows
netstat -ano | findstr 5555
```

### Kill Process on Port

```bash
# macOS/Linux
lsof -ti :5555 | xargs kill -9

# Find PID and kill manually
lsof -i :5555
kill -9 <PID>

# Windows
# Find PID
netstat -ano | findstr 5555
# Kill process
taskkill /PID <PID> /F
```

### View Project Structure

```bash
cd /Users/manikantagonugondla/Desktop/secure-chat-pfs

# View directory tree (if tree is installed)
tree -L 3

# Alternative without tree
find . -type f -not -path '*/\.*' -not -path '*/__pycache__/*' | head -30

# List all Python files
find . -name "*.py" -type f
```

### Check Python Version

```bash
# Check Python version (must be 3.10+)
python3 --version

# Check pip version
pip --version

# List installed packages
pip list | grep cryptography
```

## Development Commands

### Code Formatting (Optional)

```bash
# Install black (if not already installed)
pip install black

# Format all Python files
black .

# Check what would be formatted (dry run)
black --check .
```

### Type Checking (Optional)

```bash
# Install mypy (if not already installed)
pip install mypy

# Run type checker
mypy crypto/ client/ server/
```

### Linting (Optional)

```bash
# Install flake8 (if not already installed)
pip install flake8

# Run linter
flake8 crypto/ client/ server/ --max-line-length=100
```

## Cleanup Commands

### Clean Python Cache

```bash
cd /Users/manikantagonugondla/Desktop/secure-chat-pfs

# Remove __pycache__ directories
find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null

# Remove .pyc files
find . -name "*.pyc" -delete

# Remove pytest cache
rm -rf .pytest_cache/

# Remove coverage files
rm -rf .coverage htmlcov/
```

### Clean Virtual Environment

```bash
# Deactivate if active
deactivate

# Remove virtual environment
rm -rf venv/

# Recreate if needed
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Troubleshooting Commands

### Debug Connection Issues

```bash
# Test server is listening
nc -zv localhost 5555

# Test with telnet (alternative)
telnet localhost 5555

# Check firewall (macOS)
sudo pfctl -s rules | grep 5555

# Check firewall (Linux)
sudo ufw status
sudo iptables -L | grep 5555
```

### Debug Import Issues

```bash
# Test Python path
python3 -c "import sys; print('\n'.join(sys.path))"

# Test specific import
python3 -c "from crypto.crypto_utils import RatchetSession; print('✓ Import successful')"

# Test Tkinter
python3 -m tkinter
```

### View Logs

```bash
# If logging to file (not implemented in current version)
tail -f server.log
tail -f client.log

# Monitor server output
cd server
python3 server.py 2>&1 | tee server.log
```

## Performance Testing Commands

### Stress Test with Multiple Clients

```bash
# Terminal 1: Server
cd server
python3 server.py

# Terminals 2-6: 5 concurrent clients
for i in {1..5}; do
    cd client
    python3 client.py "User$i" &
done

# Kill all clients
pkill -f "client.py"
```

### Measure Message Throughput

```bash
# Using Python timing (example script)
python3 << EOF
import time
from crypto.crypto_utils import RatchetSession

session = RatchetSession("test", 0)
# Perform handshake (simplified)
start = time.time()
for i in range(1000):
    session.encrypt(f"Message {i}")
elapsed = time.time() - start
print(f"1000 messages in {elapsed:.2f}s = {1000/elapsed:.0f} msg/s")
EOF
```

## Documentation Commands

### View Documentation

```bash
cd /Users/manikantagonugondla/Desktop/secure-chat-pfs

# View README
cat README.md
# or
less README.md

# View specific documentation
cat docs/RUNNING.md
cat docs/THREAT_MODEL.md
cat docs/USAGE_GUIDE.md
```

### Generate Documentation (if using Sphinx)

```bash
# Install sphinx (optional)
pip install sphinx sphinx-rtd-theme

# Generate docs
cd docs
sphinx-quickstart
make html

# View generated docs
open _build/html/index.html
```

## Git Commands (Version Control)

### Initialize Repository

```bash
cd /Users/manikantagonugondla/Desktop/secure-chat-pfs

# Initialize git
git init

# Add all files
git add .

# Commit
git commit -m "Initial commit: Secure Chat with PFS implementation"

# View status
git status

# View log
git log --oneline
```

### Create Branches for Features

```bash
# Create feature branch
git checkout -b feature/double-ratchet

# Make changes...

# Commit changes
git add .
git commit -m "Add double ratchet algorithm"

# Merge back to main
git checkout main
git merge feature/double-ratchet
```

## Platform-Specific Commands

### macOS Specific

```bash
# Open multiple terminals programmatically
osascript -e 'tell application "Terminal" to do script "cd ~/Desktop/secure-chat-pfs/server && python3 server.py"'

# Allow network access (if firewall blocks)
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /usr/local/bin/python3
```

### Linux Specific

```bash
# Open multiple terminals (GNOME)
gnome-terminal -- bash -c "cd server && python3 server.py; bash" &
gnome-terminal -- bash -c "cd client && python3 client.py Alice; bash" &
gnome-terminal -- bash -c "cd client && python3 client.py Bob; bash" &

# Allow port through firewall
sudo ufw allow 5555/tcp

# Or using iptables
sudo iptables -A INPUT -p tcp --dport 5555 -j ACCEPT
```

### Windows Specific

```cmd
REM Open multiple command prompts
start cmd /k "cd server && python server.py"
start cmd /k "cd client && python client.py Alice"
start cmd /k "cd client && python client.py Bob"

REM Allow through Windows Firewall
netsh advfirewall firewall add rule name="Secure Chat" dir=in action=allow protocol=TCP localport=5555
```

## Quick Reference: All-in-One Demo

```bash
#!/bin/bash
# Complete demo in one script

cd /Users/manikantagonugondla/Desktop/secure-chat-pfs

# 1. Install
pip install -r requirements.txt

# 2. Test
pytest tests/ -v

# 3. Run demo
./demo_script.sh
```

---

**End of Command Reference**

For step-by-step demonstration guide, see [RUNNING.md](RUNNING.md)  
For general usage, see [USAGE_GUIDE.md](USAGE_GUIDE.md)
