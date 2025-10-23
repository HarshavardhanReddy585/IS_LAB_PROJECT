# Lab Demonstration Guide

Complete step-by-step instructions for demonstrating the Secure Chat with PFS project.

## Prerequisites

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Install Wireshark:**
   - **Linux:** `sudo apt install wireshark`
   - **macOS:** `brew install --cask wireshark`
   - **Windows:** Download from [wireshark.org](https://www.wireshark.org)

3. **Run tests to verify setup:**
   ```bash
   pytest tests/ -v
   ```

## Part 1: Basic Setup and Communication

### Step 1: Start the Server

Open Terminal 1:
```bash
cd server
python server.py
```

**Expected output:**
```
[SERVER] Chat relay server started on 0.0.0.0:5555
[SERVER] Waiting for connections...
[SERVER] Security note: Server is untrusted relay (sees only ciphertext)
```

### Step 2: Start First Client (Alice)

Open Terminal 2:
```bash
cd client
python client.py Alice localhost 5555
```

**Expected behavior:**
- GUI window opens titled "Secure Chat - Alice"
- Status bar shows "Connected to server" with green indicator
- Chat displays: "Connected! Select a user to start chatting."

### Step 3: Start Second Client (Bob)

Open Terminal 3:
```bash
cd client
python client.py Bob localhost 5555
```

**Expected behavior:**
- GUI window opens titled "Secure Chat - Bob"
- Both Alice and Bob see each other in "Connected Users" list
- Server terminal shows:
  ```
  [SERVER] Client registered: Alice from ('127.0.0.1', xxxxx)
  [SERVER] Client registered: Bob from ('127.0.0.1', xxxxx)
  ```

### Step 4: Establish Secure Session

**In Alice's window:**
1. Click on "Bob" in the user list
2. Observe chat pane:
   ```
   --- Chat with Bob ---
   Initiating key exchange with Bob...
   ```

**In Bob's window:**
1. Click on "Alice" in the user list
2. Both windows show:
   ```
   Secure session established with [peer]
   Key fingerprint: A1B2C3D4E5F6G7H8
   ```

**Verification:**
- ✓ Both clients show SAME key fingerprint
- ✓ Encryption Info panel shows:
  - Key Fingerprint: `A1B2C3D4...`
  - Ratchet Count: `0`
  - Session ID: `Alice:Bob:1234...`

### Step 5: Send Encrypted Messages

**Alice sends:**
```
Hello Bob! This is a secure message.
```

**Bob receives:**
- Message appears in green: `Alice: Hello Bob! This is a secure message.`

**Bob replies:**
```
Hi Alice! I can see your message.
```

**Alice receives:**
- Message appears in green: `Bob: Hi Alice! I can see your message.`

**Key observation:**
- Messages appear instantly
- Server terminal shows:
  ```
  [SERVER] Forwarding encrypted message: Alice -> Bob
  [SERVER] Forwarding encrypted message: Bob -> Alice
  ```
- **Server never sees plaintext!**

## Part 2: Wireshark Traffic Analysis

### Step 6: Start Wireshark Capture

1. **Open Wireshark**
2. **Select interface:**
   - Linux/macOS: Select `lo0` or `Loopback`
   - Windows: Select `Npcap Loopback Adapter`

3. **Apply capture filter:**
   ```
   tcp.port == 5555
   ```

4. **Start capture** (green shark fin icon)

### Step 7: Send Messages and Capture Traffic

**Alice sends several messages:**
```
Message 1: Testing encryption
Message 2: This should be encrypted
Message 3: Wireshark demonstration
```

### Step 8: Analyze Captured Packets

1. **Stop capture** (red square icon)

2. **Filter for TCP data:**
   ```
   tcp.port == 5555 and tcp.len > 0
   ```

3. **Right-click a packet** → Follow → TCP Stream

**What you'll see:**
```json
{
  "type": "message",
  "from": "Alice",
  "to": "Bob",
  "encrypted": {
    "ciphertext": "3q7KP9x2m/jVY8nL+KPq4A7dF3...",
    "nonce": "A7xK2p9L3mN8qR4s",
    "ratchet_count": 0,
    "message_count": 1
  }
}
```

**Key observations:**
- ✓ `ciphertext` is base64-encoded (random-looking)
- ✓ Original plaintext "Testing encryption" is NOT visible
- ✓ Server only sees encrypted blob
- ✓ Nonce changes for each message

### Step 9: Demonstrate Ciphertext Inspection

**In Alice's window:**
1. Send a message
2. Click "Show Ciphertext" button

**Popup shows:**
```json
{
  "ciphertext": "3q7KP9x2m/jVY8nL+KPq4A7dF3g9Hk2M...",
  "nonce": "A7xK2p9L3mN8qR4s",
  "ratchet_count": 0,
  "message_count": 1,
  "needs_ratchet": false
}
```

**Compare with Wireshark:**
- Same base64 strings should appear in both views
- Confirms this is the actual data transmitted over network

## Part 3: Perfect Forward Secrecy Demonstration

### Step 10: Record Initial Key Fingerprint

**Before ratcheting:**
- Note Alice's Key Fingerprint: `A1B2C3D4E5F6G7H8`
- Note Bob's Key Fingerprint: `A1B2C3D4E5F6G7H8`
- Ratchet Count: `0`

### Step 11: Force Key Ratcheting

**In Alice's window:**
1. Click "Force Rekey" button

**Expected behavior:**
- Both windows show:
  ```
  *** KEY RATCHETING INITIATED ***
  New key fingerprint: F9E8D7C6B5A4321
  ```

**Server terminal shows:**
```
[SERVER] Forwarding ratchet: Alice -> Bob
[CRYPTO] Ratchet #1 initiated. New key pair generated.
[CRYPTO] Ratchet #1 complete. New key fingerprint: F9E8D7C6B5A4321
```

**Verification:**
- ✓ Key fingerprint CHANGED: `A1B2C3D4...` → `F9E8D7C6...`
- ✓ Both clients show SAME new fingerprint
- ✓ Ratchet Count: `1`

### Step 12: Verify Forward Secrecy

**Send new message after ratchet:**

**Alice sends:**
```
This message uses the NEW key after ratcheting.
```

**Bob receives successfully:**
- Message appears normally

**Key security property:**
- Old key (`A1B2C3D4...`) is DESTROYED
- Old ciphertext cannot be decrypted with new key
- Even if new key is compromised, old messages remain secure

### Step 13: PFS Test with Unit Tests

**Run forward secrecy test:**
```bash
pytest tests/test_crypto.py::test_forward_secrecy -v
```

**Expected output:**
```
✓ Bob decrypts with old key
✓ Old message CANNOT be decrypted with new key (PFS works!)
✓ New message decrypts with new key
PASSED
```

**This proves:**
1. Message encrypted with key K1 can be decrypted with K1
2. After ratchet to K2, same message CANNOT be decrypted
3. **Perfect Forward Secrecy is working!**

## Part 4: File Transfer Demonstration

### Step 14: Create Test File

Create a test file:
```bash
echo "This is a secret document with sensitive information." > test_file.txt
```

Or use any existing file (images, PDFs work too).

### Step 15: Send Encrypted File

**In Alice's window:**
1. Click "Attach File" button
2. Select `test_file.txt`
3. Progress dialog appears showing:
   ```
   Transferring: test_file.txt
   Chunk 0 / 1
   ```

**Server terminal shows:**
```
[SERVER] Forwarding file chunk 0: Alice -> Bob
```

### Step 16: Receive and Verify File

**Bob's window:**
- Dialog: "Save received file"
- Choose location: `received_test.txt`
- Message: "File saved: /path/to/received_test.txt"

**Verify file integrity:**
```bash
diff test_file.txt received_test.txt
```
- No output = files are identical!

**In Wireshark:**
- File chunks appear as encrypted JSON:
  ```json
  {
    "type": "file_chunk",
    "encrypted": {
      "ciphertext": "X9K3mP2n...",
      "nonce": "L7qW9..."
    }
  }
  ```
- Original file content NOT visible

## Part 5: Advanced Demonstrations

### Step 17: Automatic Ratcheting

Configure auto-ratchet in `crypto/crypto_utils.py`:
```python
auto_ratchet_interval = 5  # Ratchet every 5 messages
```

**Send 6 messages:**

After 5th message:
- System shows: "*** KEY RATCHETING INITIATED ***"
- Automatic ratchet occurs
- 6th message uses new key

### Step 18: Multiple Client Scenario

Start a third client:
```bash
python client.py Charlie localhost 5555
```

**Demonstrate:**
- Alice ↔ Bob session (Key Fingerprint 1)
- Alice ↔ Charlie session (Key Fingerprint 2)
- Each pair has independent encryption keys
- Server routes messages correctly

### Step 19: Security Testing

**Attempt to decrypt without key:**
```bash
pytest tests/test_crypto.py::test_forward_secrecy -v
```

**Try to read encrypted file:**
```bash
# Captured ciphertext from Wireshark
echo "3q7KP9x2m/jVY8nL+KPq4A7dF3..." | base64 -d
# Output: random binary data (unreadable)
```

## Demonstration Checklist

### Before Demo
- [ ] All dependencies installed
- [ ] Tests pass successfully
- [ ] Wireshark installed and configured
- [ ] Firewall allows port 5555

### During Demo
- [ ] Server starts successfully
- [ ] Multiple clients connect
- [ ] Key exchange completes
- [ ] Key fingerprints match
- [ ] Messages encrypt/decrypt
- [ ] Wireshark shows ciphertext only
- [ ] Ratcheting changes key
- [ ] File transfer works
- [ ] Unit tests pass

### Key Points to Highlight

1. **End-to-End Encryption:**
   - Server never sees plaintext
   - Only clients have decryption keys

2. **Perfect Forward Secrecy:**
   - Old keys destroyed after ratchet
   - Past messages unreadable even if current key compromised

3. **Real-World Protocols:**
   - Uses same crypto as Signal/WhatsApp
   - Industry-standard algorithms (X25519, AES-GCM)

4. **Visual Demonstration:**
   - Key fingerprints visible in UI
   - Ciphertext inspection available
   - Wireshark confirms encryption

## Troubleshooting

### Issue: Clients can't connect
**Solution:**
- Check server is running
- Verify port 5555 is not blocked
- Try `127.0.0.1` instead of `localhost`

### Issue: Key exchange timeout
**Solution:**
- Restart both clients
- Check network connectivity
- Ensure firewall allows connections

### Issue: Wireshark shows no packets
**Solution:**
- Select correct interface (Loopback for localhost)
- Check capture filter: `tcp.port == 5555`
- Try without filter first

### Issue: Decryption fails
**Solution:**
- Verify both clients completed handshake
- Check key fingerprints match
- Restart session if needed

## Expected Demonstration Time

- **Setup:** 5 minutes
- **Basic messaging:** 10 minutes
- **Wireshark analysis:** 10 minutes
- **PFS demonstration:** 10 minutes
- **File transfer:** 5 minutes
- **Total:** ~40 minutes

## Wireshark Filters Reference

```
# All chat traffic
tcp.port == 5555

# Only data packets
tcp.port == 5555 and tcp.len > 0

# Specific message types
tcp.port == 5555 and frame contains "message"
tcp.port == 5555 and frame contains "file_chunk"
tcp.port == 5555 and frame contains "ratchet"

# Follow TCP stream
Right-click packet → Follow → TCP Stream
```

## Conclusion

This demonstration shows:
1. ✓ Secure end-to-end encryption
2. ✓ Perfect Forward Secrecy through ratcheting
3. ✓ Untrusted server architecture
4. ✓ Real-time key rotation
5. ✓ Encrypted file transfer
6. ✓ Visual verification with Wireshark

---

**Ready to present!** 🎓🔐
