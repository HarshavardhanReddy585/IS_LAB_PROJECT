# Secure Encrypted Chat with Perfect Forward Secrecy

An Information Security lab project at Manipal Institute of Technology. It is a multi-user, end-to-end encrypted chat with **Perfect Forward Secrecy**: session keys are ratcheted, so a key leaked today can't decrypt yesterday's messages. Messages pass through a relay server that never sees plaintext.

**Authors:** Harshavardhan Reddy, Kshitij Singh

- **Key exchange:** X25519 ECDH with ephemeral keys
- **Encryption:** AES-256-GCM (confidentiality and integrity), a fresh 12-byte nonce per message
- **Key derivation:** HKDF-SHA256, with automatic and manual key ratcheting
- **Also included:** group chat, chunked encrypted file transfer, a Tkinter GUI with key fingerprints and a ratchet counter, unit tests for the PFS properties, and Wireshark traffic analysis

## Repository layout

| Path | Contents |
|---|---|
| [`secure-chat-pfs/`](secure-chat-pfs) | The application: `crypto/`, `server/`, `client/`, `tests/`, and `docs/` (usage, threat model, demo steps) |
| [`report.tex`](report.tex) | The project report (LaTeX) |

See the full guide in **[secure-chat-pfs/README.md](secure-chat-pfs/README.md)**.

## Quick start

```bash
cd secure-chat-pfs
pip install -r requirements.txt
pytest tests/ -v                          # verify the crypto and PFS properties
cd server && python3 server.py            # terminal 1: relay server
cd client && python3 client.py Alice      # terminal 2
cd client && python3 client.py Bob        # terminal 3
```
