"""
client.py - Secure chat client with Tkinter GUI

Features:
- End-to-end encryption with PFS
- User-friendly GUI
- File transfer support
- Real-time key ratcheting
- Ciphertext inspection for demonstration
"""

import socket
import threading
import json
import time
import os
import sys
import tkinter as tk
from tkinter import filedialog, messagebox
from typing import Optional, Dict, List
import base64
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.crypto_utils import RatchetSession, GroupSession, encrypt_file_chunk, decrypt_file_chunk
from ui_components import (
    UserListFrame, ChatDisplayFrame, MessageInputFrame,
    EncryptionInfoFrame, StatusBar, CiphertextDialog, FileTransferDialog,
    CreateGroupDialog, GroupUserListFrame
)


# File transfer settings
FILE_CHUNK_SIZE = 8192  # 8KB chunks


class SecureChatClient:
    """
    Main chat client with E2E encryption.
    
    Security features:
    - X25519 ECDH key exchange
    - AES-256-GCM encryption
    - Perfect Forward Secrecy via ratcheting
    - Client-side encryption only
    """
    
    def __init__(self, host: str, port: int, username: str):
        self.host = host
        self.port = port
        self.username = username
        
        # Network
        self.socket: Optional[socket.socket] = None
        self.connected = False
        self.receive_thread: Optional[threading.Thread] = None
        
        # Crypto sessions: peer_username -> RatchetSession
        self.sessions: Dict[str, RatchetSession] = {}
        self.current_peer: Optional[str] = None

        # Group sessions: group_id -> GroupSession
        self.group_sessions: Dict[str, GroupSession] = {}
        self.current_group: Optional[str] = None
        self.groups: List[Dict] = []  # List of group info dicts

        # Current chat mode: 'user' or 'group'
        self.chat_mode: str = 'user'

        # User list
        self.users: List[str] = []

        # File transfer tracking
        self.file_transfers: Dict[str, Dict] = {}  # transfer_id -> {chunks, filename, total}

        # Pending group key distributions: peer -> [(group_id, group_name, group_key, members)]
        self.pending_group_keys: Dict[str, List[tuple]] = {}

        # Last ciphertext for demonstration
        self.last_ciphertext: Optional[Dict] = None
        
        # UI
        self.root: Optional[tk.Tk] = None
        self.setup_gui()
    
    def setup_gui(self):
        """Create Tkinter GUI."""
        self.root = tk.Tk()
        self.root.title(f"Secure Chat - {self.username}")
        self.root.geometry("900x700")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Main container
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left side - User and Group list
        self.user_group_list = GroupUserListFrame(
            main_frame,
            self.on_user_select,
            self.on_group_select,
            self.open_create_group_dialog
        )
        self.user_group_list.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        
        # Right side
        right_frame = tk.Frame(main_frame)
        right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Chat display
        self.chat_display = ChatDisplayFrame(right_frame)
        self.chat_display.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Encryption info
        self.encryption_info = EncryptionInfoFrame(
            right_frame,
            self.force_rekey,
            self.show_ciphertext
        )
        self.encryption_info.pack(fill=tk.X, pady=(0, 10))
        
        # Message input
        self.message_input = MessageInputFrame(
            right_frame,
            self.send_message,
            self.attach_file
        )
        self.message_input.pack(fill=tk.X)
        self.message_input.set_enabled(False)
        
        # Status bar
        self.status_bar = StatusBar(self.root)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Initial status
        self.chat_display.add_message("=== Secure Chat with Perfect Forward Secrecy ===", 'system')
        self.chat_display.add_message("Connecting to server...", 'system')
    
    def connect(self):
        """Connect to server."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.connected = True
            
            # Start receive thread
            self.receive_thread = threading.Thread(target=self.receive_loop, daemon=True)
            self.receive_thread.start()
            
            # Register with server
            self.send_to_server({
                'type': 'register',
                'username': self.username
            })
            
            self.update_status("Connected to server", True)
            self.chat_display.add_message("Connected! Select a user to start chatting.", 'system')
            
        except Exception as e:
            self.update_status(f"Connection failed: {e}", False)
            self.chat_display.add_message(f"ERROR: {e}", 'error')
    
    def send_to_server(self, message: Dict):
        """Send JSON message to server."""
        if not self.connected:
            return
        
        try:
            data = json.dumps(message).encode('utf-8')
            length = len(data).to_bytes(4, byteorder='big')
            self.socket.sendall(length + data)
        except Exception as e:
            print(f"[CLIENT] Send error: {e}")
            self.connected = False
    
    def receive_loop(self):
        """Receive messages from server."""
        while self.connected:
            try:
                # Receive length
                length_bytes = self._recv_exact(4)
                if not length_bytes:
                    break
                
                msg_length = int.from_bytes(length_bytes, byteorder='big')
                
                # Receive message
                data = self._recv_exact(msg_length)
                if not data:
                    break
                
                message = json.loads(data.decode('utf-8'))
                self.process_message(message)
                
            except Exception as e:
                print(f"[CLIENT] Receive error: {e}")
                break
        
        self.connected = False
        self.update_status("Disconnected", False)
    
    def _recv_exact(self, n: int) -> Optional[bytes]:
        """Receive exactly n bytes."""
        data = b''
        while len(data) < n:
            chunk = self.socket.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data
    
    def process_message(self, message: Dict):
        """Process incoming message from server."""
        msg_type = message.get('type')
        
        if msg_type == 'register_ack':
            self.chat_display.add_message(f"Registered as {self.username}", 'system')
        
        elif msg_type == 'user_list':
            self.update_user_list(message.get('users', []))
        
        elif msg_type == 'key_exchange':
            self.handle_key_exchange(message)
        
        elif msg_type == 'message':
            self.handle_encrypted_message(message)
        
        elif msg_type == 'file_chunk':
            self.handle_file_chunk(message)
        
        elif msg_type == 'ratchet':
            self.handle_ratchet(message)

        elif msg_type == 'group_list':
            self.handle_group_list(message)

        elif msg_type == 'group_created':
            self.handle_group_created(message)

        elif msg_type == 'group_message':
            self.handle_group_message(message)

        elif msg_type == 'group_key_exchange':
            self.handle_group_key_exchange(message)

        elif msg_type == 'group_file_chunk':
            self.handle_group_file_chunk(message)
    
    def update_user_list(self, users: List[str]):
        """Update connected users list."""
        self.users = users
        self.root.after(0, lambda: self.user_group_list.update_users(users, self.username))
    
    def on_user_select(self, username: str):
        """Handle user selection."""
        self.chat_mode = 'user'
        self.current_peer = username
        self.current_group = None
        self.chat_display.add_message(f"\n--- Chat with {username} ---", 'system')

        # Initialize or get session
        if username not in self.sessions:
            self.initiate_session(username)
        else:
            session = self.sessions[username]
            self.encryption_info.update_fingerprint(session.get_key_fingerprint())
            self.encryption_info.update_ratchet_count(session.ratchet_count)
            self.encryption_info.update_session_id(session.session_id)

        self.message_input.set_enabled(True)

    def on_group_select(self, group_index: int):
        """Handle group selection."""
        if group_index >= len(self.groups):
            return

        group = self.groups[group_index]
        group_id = group['group_id']

        self.chat_mode = 'group'
        self.current_group = group_id
        self.current_peer = None

        self.chat_display.add_message(f"\n--- Group: {group['name']} ---", 'system')
        self.chat_display.add_message(f"Members: {', '.join(group['members'])}", 'system')

        # Show group encryption info if session exists
        if group_id in self.group_sessions:
            group_session = self.group_sessions[group_id]
            self.encryption_info.update_fingerprint(group_session.get_key_fingerprint())
            self.encryption_info.update_ratchet_count(0)  # Groups don't ratchet
            self.encryption_info.update_session_id(group_id)

        self.message_input.set_enabled(True)
    
    def initiate_session(self, peer: str):
        """Initiate new encrypted session with peer."""
        session_id = f"{min(self.username, peer)}:{max(self.username, peer)}:{int(time.time())}"
        session = RatchetSession(session_id, auto_ratchet_interval=50)
        self.sessions[peer] = session
        
        self.chat_display.add_message(f"Initiating key exchange with {peer}...", 'system')
        
        # Send our public key
        pub_key_bytes = session.get_public_key_bytes()
        self.send_to_server({
            'type': 'key_exchange',
            'from': self.username,
            'to': peer,
            'public_key': base64.b64encode(pub_key_bytes).decode('utf-8'),
            'session_id': session_id
        })
        
        self.encryption_info.update_session_id(session_id)
    
    def handle_key_exchange(self, message: Dict):
        """Handle incoming public key."""
        peer = message.get('from')
        session_id = message.get('session_id')
        pub_key_b64 = message.get('public_key')

        if peer not in self.sessions:
            # Create session if not exists
            session = RatchetSession(session_id, auto_ratchet_interval=50)
            self.sessions[peer] = session

        session = self.sessions[peer]

        # Perform handshake
        peer_pub_key = base64.b64decode(pub_key_b64)
        session.perform_handshake(peer_pub_key)

        # Send our public key back if needed
        if session.message_count == 0:
            pub_key_bytes = session.get_public_key_bytes()
            self.send_to_server({
                'type': 'key_exchange',
                'from': self.username,
                'to': peer,
                'public_key': base64.b64encode(pub_key_bytes).decode('utf-8'),
                'session_id': session_id
            })

        self.chat_display.add_message(f"Secure session established with {peer}", 'system')
        self.chat_display.add_message(f"Key fingerprint: {session.get_key_fingerprint()}", 'system')

        if peer == self.current_peer:
            self.encryption_info.update_fingerprint(session.get_key_fingerprint())
            self.encryption_info.update_ratchet_count(session.ratchet_count)

        # Check if there are pending group keys to distribute to this peer
        if peer in self.pending_group_keys:
            self.chat_display.add_message(f"Distributing pending group keys to {peer}...", 'system')
            for group_data in self.pending_group_keys[peer]:
                group_id, group_name, group_key, members = group_data
                self.distribute_group_key(peer, group_id, group_name, group_key, members)
            del self.pending_group_keys[peer]
    
    def send_message(self, plaintext: str):
        """Encrypt and send message."""
        if self.chat_mode == 'user':
            self.send_user_message(plaintext)
        elif self.chat_mode == 'group':
            self.send_group_message(plaintext)

    def send_user_message(self, plaintext: str):
        """Encrypt and send message to user."""
        if not self.current_peer:
            messagebox.showwarning("No Peer", "Please select a user to chat with")
            return

        if self.current_peer not in self.sessions:
            messagebox.showwarning("No Session", "Waiting for key exchange...")
            return

        session = self.sessions[self.current_peer]

        try:
            # Encrypt message
            encrypted_data = session.encrypt(plaintext)
            self.last_ciphertext = encrypted_data  # Save for demonstration

            # Send encrypted message
            self.send_to_server({
                'type': 'message',
                'from': self.username,
                'to': self.current_peer,
                'encrypted': encrypted_data
            })

            # Display in chat
            self.chat_display.add_message(f"You: {plaintext}", 'sent')

            # Update encryption info
            self.encryption_info.update_ratchet_count(session.ratchet_count)

            # Check if auto-ratchet needed
            if encrypted_data.get('needs_ratchet'):
                self.perform_ratchet(self.current_peer)

        except Exception as e:
            self.chat_display.add_message(f"Encryption error: {e}", 'error')

    def send_group_message(self, plaintext: str):
        """Encrypt and send message to group."""
        if not self.current_group:
            messagebox.showwarning("No Group", "Please select a group to chat with")
            return

        if self.current_group not in self.group_sessions:
            available_groups = list(self.group_sessions.keys())
            messagebox.showwarning("No Session", f"Group key not available for {self.current_group}.\nAvailable: {available_groups}")
            return

        group_session = self.group_sessions[self.current_group]

        try:
            # Encrypt message
            encrypted_data = group_session.encrypt(plaintext)
            self.last_ciphertext = encrypted_data  # Save for demonstration

            # Send encrypted group message
            self.send_to_server({
                'type': 'group_message',
                'from': self.username,
                'group_id': self.current_group,
                'encrypted': encrypted_data
            })

            # Display in chat
            self.chat_display.add_message(f"You: {plaintext}", 'sent')

        except Exception as e:
            self.chat_display.add_message(f"Encryption error: {e}", 'error')
            import traceback
            traceback.print_exc()
    
    def handle_encrypted_message(self, message: Dict):
        """Decrypt and display received message."""
        sender = message.get('from')
        encrypted_data = message.get('encrypted')
        
        if sender not in self.sessions:
            self.chat_display.add_message(f"No session with {sender}", 'error')
            return
        
        session = self.sessions[sender]
        
        try:
            # Decrypt message
            plaintext = session.decrypt(encrypted_data)
            
            # Display in chat
            self.chat_display.add_message(f"{sender}: {plaintext}", 'received')
            
            # Update UI if this is current peer
            if sender == self.current_peer:
                self.encryption_info.update_ratchet_count(session.ratchet_count)
            
        except Exception as e:
            self.chat_display.add_message(f"Decryption error from {sender}: {e}", 'error')
    
    def attach_file(self):
        """Attach and send file."""
        if self.chat_mode == 'user':
            self.attach_file_to_user()
        elif self.chat_mode == 'group':
            self.attach_file_to_group()

    def attach_file_to_user(self):
        """Attach and send file to user."""
        if not self.current_peer:
            messagebox.showwarning("No Peer", "Please select a user to send file to")
            return

        filepath = filedialog.askopenfilename(title="Select file to send")
        if not filepath:
            return

        filename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath)

        self.chat_display.add_message(f"Sending file: {filename} ({filesize} bytes)", 'system')

        # Send file in chunks
        threading.Thread(target=self.send_file_to_user, args=(filepath,), daemon=True).start()

    def attach_file_to_group(self):
        """Attach and send file to group."""
        if not self.current_group:
            messagebox.showwarning("No Group", "Please select a group to send file to")
            return

        if self.current_group not in self.group_sessions:
            messagebox.showwarning("No Session", "Group key not available")
            return

        filepath = filedialog.askopenfilename(title="Select file to send to group")
        if not filepath:
            return

        filename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath)

        self.chat_display.add_message(f"Sending file to group: {filename} ({filesize} bytes)", 'system')

        # Send file in chunks
        threading.Thread(target=self.send_file_to_group, args=(filepath,), daemon=True).start()
    
    def send_file_to_user(self, filepath: str):
        """Send file in encrypted chunks to user."""
        if self.current_peer not in self.sessions:
            return

        session = self.sessions[self.current_peer]
        filename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath)
        total_chunks = (filesize + FILE_CHUNK_SIZE - 1) // FILE_CHUNK_SIZE

        transfer_id = f"{self.username}:{int(time.time())}"

        # Show progress dialog
        self.root.after(0, lambda: self._create_progress_dialog(filename, total_chunks))

        try:
            with open(filepath, 'rb') as f:
                chunk_num = 0
                while True:
                    chunk_data = f.read(FILE_CHUNK_SIZE)
                    if not chunk_data:
                        break

                    # Encrypt chunk
                    encrypted_chunk = encrypt_file_chunk(session.aesgcm, chunk_data)

                    # Send chunk
                    self.send_to_server({
                        'type': 'file_chunk',
                        'from': self.username,
                        'to': self.current_peer,
                        'transfer_id': transfer_id,
                        'filename': filename,
                        'chunk_num': chunk_num,
                        'total_chunks': total_chunks,
                        'encrypted': encrypted_chunk
                    })

                    chunk_num += 1
                    time.sleep(0.05)  # Small delay to avoid overwhelming

            self.chat_display.add_message(f"File sent: {filename}", 'system')

        except Exception as e:
            self.chat_display.add_message(f"File send error: {e}", 'error')

    def send_file_to_group(self, filepath: str):
        """Send file in encrypted chunks to group."""
        if self.current_group not in self.group_sessions:
            return

        group_session = self.group_sessions[self.current_group]
        filename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath)
        total_chunks = (filesize + FILE_CHUNK_SIZE - 1) // FILE_CHUNK_SIZE

        transfer_id = f"{self.username}:group:{int(time.time())}"

        # Show progress dialog
        self.root.after(0, lambda: self._create_progress_dialog(filename, total_chunks))

        try:
            with open(filepath, 'rb') as f:
                chunk_num = 0
                while True:
                    chunk_data = f.read(FILE_CHUNK_SIZE)
                    if not chunk_data:
                        break

                    # Encrypt chunk with group key
                    encrypted_chunk = encrypt_file_chunk(group_session.aesgcm, chunk_data)

                    # Send chunk to group
                    self.send_to_server({
                        'type': 'group_file_chunk',
                        'from': self.username,
                        'group_id': self.current_group,
                        'transfer_id': transfer_id,
                        'filename': filename,
                        'chunk_num': chunk_num,
                        'total_chunks': total_chunks,
                        'encrypted': encrypted_chunk
                    })

                    chunk_num += 1
                    time.sleep(0.05)  # Small delay to avoid overwhelming

            self.chat_display.add_message(f"File sent to group: {filename}", 'system')

        except Exception as e:
            self.chat_display.add_message(f"Group file send error: {e}", 'error')
    
    def _create_progress_dialog(self, filename: str, total_chunks: int):
        """Create file transfer progress dialog."""
        FileTransferDialog(self.root, filename, total_chunks)
    
    def handle_file_chunk(self, message: Dict):
        """Handle incoming file chunk."""
        sender = message.get('from')
        transfer_id = message.get('transfer_id')
        filename = message.get('filename')
        chunk_num = message.get('chunk_num')
        total_chunks = message.get('total_chunks')
        encrypted_chunk = message.get('encrypted')
        
        if sender not in self.sessions:
            return
        
        session = self.sessions[sender]
        
        # Initialize transfer if new
        if transfer_id not in self.file_transfers:
            self.file_transfers[transfer_id] = {
                'filename': filename,
                'chunks': {},
                'total': total_chunks
            }
            self.chat_display.add_message(f"Receiving file: {filename} from {sender}", 'system')
        
        transfer = self.file_transfers[transfer_id]
        
        try:
            # Decrypt chunk
            decrypted_chunk = decrypt_file_chunk(session.aesgcm, encrypted_chunk)
            transfer['chunks'][chunk_num] = decrypted_chunk
            
            # Check if complete
            if len(transfer['chunks']) == total_chunks:
                self.save_received_file(transfer_id)
                
        except Exception as e:
            self.chat_display.add_message(f"File chunk decryption error: {e}", 'error')
    
    def save_received_file(self, transfer_id: str):
        """Save complete received file."""
        transfer = self.file_transfers[transfer_id]
        filename = transfer['filename']
        
        # Ask where to save
        save_path = filedialog.asksaveasfilename(
            defaultextension=os.path.splitext(filename)[1],
            initialfile=filename,
            title="Save received file"
        )
        
        if save_path:
            try:
                with open(save_path, 'wb') as f:
                    for i in range(transfer['total']):
                        f.write(transfer['chunks'][i])
                
                self.chat_display.add_message(f"File saved: {save_path}", 'system')
            except Exception as e:
                self.chat_display.add_message(f"File save error: {e}", 'error')
        
        # Clean up
        del self.file_transfers[transfer_id]
    
    def force_rekey(self):
        """Manually trigger key ratcheting."""
        if not self.current_peer:
            messagebox.showwarning("No Peer", "Please select a user first")
            return
        
        if self.current_peer not in self.sessions:
            messagebox.showwarning("No Session", "No active session")
            return
        
        self.perform_ratchet(self.current_peer)
    
    def perform_ratchet(self, peer: str):
        """Perform key ratcheting."""
        session = self.sessions[peer]
        
        self.chat_display.add_message("*** KEY RATCHETING INITIATED ***", 'system')
        
        # Generate new key pair
        new_pub_key = session.ratchet()
        
        # Immediately derive new symmetric key using our new private key and peer's existing public key
        if session.peer_public_key:
            # Perform ECDH with our new private key and peer's existing public key
            shared_secret = session.private_key.exchange(session.peer_public_key)
            
            # Derive new symmetric key using HKDF
            info = f"{session.session_id}:ratchet{session.ratchet_count}".encode()
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,  # 256 bits for AES-256
                salt=session.salt,
                info=info,
                backend=default_backend()
            )
            session.symmetric_key = hkdf.derive(shared_secret)
            session.aesgcm = AESGCM(session.symmetric_key)
            
            self.chat_display.add_message(f"New key fingerprint: {session.get_key_fingerprint()}", 'system')
            self.encryption_info.update_fingerprint(session.get_key_fingerprint())
        
        # Send new public key to peer
        self.send_to_server({
            'type': 'ratchet',
            'from': self.username,
            'to': peer,
            'public_key': base64.b64encode(new_pub_key).decode('utf-8'),
            'ratchet_count': session.ratchet_count
        })
        
        self.encryption_info.update_ratchet_count(session.ratchet_count)
    
    def handle_ratchet(self, message: Dict):
        """Handle peer's ratchet notification."""
        peer = message.get('from')
        new_pub_key_b64 = message.get('public_key')
        ratchet_count = message.get('ratchet_count')
        
        if peer not in self.sessions:
            return
        
        session = self.sessions[peer]
        
        # Complete ratchet
        peer_pub_key = base64.b64decode(new_pub_key_b64)
        session.complete_ratchet(peer_pub_key)
        
        self.chat_display.add_message(f"*** KEY RATCHET COMPLETE (#{ratchet_count}) ***", 'system')
        self.chat_display.add_message(f"New key fingerprint: {session.get_key_fingerprint()}", 'system')
        
        if peer == self.current_peer:
            self.encryption_info.update_fingerprint(session.get_key_fingerprint())
            self.encryption_info.update_ratchet_count(session.ratchet_count)
    
    def show_ciphertext(self):
        """Show raw ciphertext for demonstration."""
        if not self.last_ciphertext:
            messagebox.showinfo("No Ciphertext", "Send a message first to see ciphertext")
            return

        CiphertextDialog(self.root, "Raw Ciphertext (Wireshark View)", self.last_ciphertext)

    def open_create_group_dialog(self):
        """Open dialog to create a new group."""
        if not self.users:
            messagebox.showinfo("No Users", "No other users available to create a group")
            return

        CreateGroupDialog(self.root, self.users, self.create_group)

    def create_group(self, group_name: str, members: List[str]):
        """Create a new group."""
        # Generate group ID
        group_id = f"group_{self.username}_{int(time.time())}"

        # Create group session and generate key
        group_session = GroupSession(group_id, group_name)
        group_key = group_session.generate_group_key()
        self.group_sessions[group_id] = group_session

        self.chat_display.add_message(f"Creating group: {group_name}", 'system')

        # Send create group request to server
        self.send_to_server({
            'type': 'create_group',
            'group_id': group_id,
            'group_name': group_name,
            'members': members
        })

        # Distribute group key to each member via encrypted 1-on-1 session
        for member in members:
            if member != self.username:
                self.distribute_group_key(member, group_id, group_name, group_key, members)

    def distribute_group_key(self, recipient: str, group_id: str, group_name: str, group_key: bytes, members: List[str]):
        """Distribute group key to a member via encrypted 1-on-1 session."""
        # Ensure we have a session with this user
        if recipient not in self.sessions:
            self.chat_display.add_message(f"No session with {recipient}, initiating key exchange...", 'system')

            # Store pending group key distribution
            if recipient not in self.pending_group_keys:
                self.pending_group_keys[recipient] = []
            self.pending_group_keys[recipient].append((group_id, group_name, group_key, members))

            # Initiate session with this user
            self.initiate_session(recipient)
            return

        session = self.sessions[recipient]

        try:
            # Encrypt the group key and metadata using 1-on-1 session
            group_data = {
                'group_id': group_id,
                'group_name': group_name,
                'group_key': base64.b64encode(group_key).decode('utf-8'),
                'members': members
            }
            group_data_json = json.dumps(group_data)
            encrypted_key_data = session.encrypt(group_data_json)

            # Send via server
            self.send_to_server({
                'type': 'group_key_exchange',
                'from': self.username,
                'to': recipient,
                'encrypted': encrypted_key_data
            })

            self.chat_display.add_message(f"Sent group key to {recipient}", 'system')

        except Exception as e:
            self.chat_display.add_message(f"Error distributing key to {recipient}: {e}", 'error')

    def handle_group_created(self, message: Dict):
        """Handle group creation confirmation."""
        group_name = message.get('group_name')
        self.chat_display.add_message(f"Group '{group_name}' created successfully!", 'system')

    def handle_group_list(self, message: Dict):
        """Handle updated group list from server."""
        groups = message.get('groups', [])
        self.groups = groups
        self.root.after(0, lambda: self.user_group_list.update_groups(groups))

    def handle_group_key_exchange(self, message: Dict):
        """Handle incoming encrypted group key."""
        sender = message.get('from')
        encrypted_data = message.get('encrypted')

        if sender not in self.sessions:
            self.chat_display.add_message(f"No session with {sender} for group key", 'error')
            return

        session = self.sessions[sender]

        try:
            # Decrypt group key data
            decrypted_json = session.decrypt(encrypted_data)
            group_data = json.loads(decrypted_json)

            group_id = group_data['group_id']
            group_name = group_data['group_name']
            group_key_b64 = group_data['group_key']
            members = group_data['members']

            # Create group session with received key
            group_session = GroupSession(group_id, group_name)
            group_key = base64.b64decode(group_key_b64)
            group_session.set_group_key(group_key)
            self.group_sessions[group_id] = group_session

            self.chat_display.add_message(f"✓ Received group key for '{group_name}' from {sender}", 'system')
            self.chat_display.add_message(f"Group fingerprint: {group_session.get_key_fingerprint()}", 'system')
            self.chat_display.add_message(f"Members: {', '.join(members)}", 'system')

            # Join the group on the server side
            self.send_to_server({
                'type': 'join_group',
                'group_id': group_id
            })

            self.chat_display.add_message(f"✓ Joined group '{group_name}' - You can now send messages!", 'system')

        except Exception as e:
            self.chat_display.add_message(f"Error receiving group key: {e}", 'error')
            import traceback
            traceback.print_exc()

    def handle_group_message(self, message: Dict):
        """Handle incoming group message."""
        group_id = message.get('group_id')
        sender = message.get('from')
        encrypted_data = message.get('encrypted')

        if group_id not in self.group_sessions:
            self.chat_display.add_message(f"No session for group {group_id}", 'error')
            return

        group_session = self.group_sessions[group_id]

        try:
            # Decrypt message
            plaintext = group_session.decrypt(encrypted_data)

            # Display in chat
            self.chat_display.add_message(f"{sender}: {plaintext}", 'received')

        except Exception as e:
            self.chat_display.add_message(f"Group decryption error: {e}", 'error')

    def handle_group_file_chunk(self, message: Dict):
        """Handle incoming group file chunk."""
        sender = message.get('from')
        group_id = message.get('group_id')
        transfer_id = message.get('transfer_id')
        filename = message.get('filename')
        chunk_num = message.get('chunk_num')
        total_chunks = message.get('total_chunks')
        encrypted_chunk = message.get('encrypted')

        if group_id not in self.group_sessions:
            self.chat_display.add_message(f"No session for group {group_id}", 'error')
            return

        group_session = self.group_sessions[group_id]

        # Initialize transfer if new
        if transfer_id not in self.file_transfers:
            self.file_transfers[transfer_id] = {
                'filename': filename,
                'chunks': {},
                'total': total_chunks
            }
            self.chat_display.add_message(f"Receiving file from group: {filename} (from {sender})", 'system')

        transfer = self.file_transfers[transfer_id]

        try:
            # Decrypt chunk
            decrypted_chunk = decrypt_file_chunk(group_session.aesgcm, encrypted_chunk)
            transfer['chunks'][chunk_num] = decrypted_chunk

            # Check if complete
            if len(transfer['chunks']) == total_chunks:
                self.save_received_file(transfer_id)

        except Exception as e:
            self.chat_display.add_message(f"Group file chunk decryption error: {e}", 'error')
    
    def update_status(self, message: str, connected: bool):
        """Update status bar."""
        self.root.after(0, lambda: self.status_bar.set_status(message, connected))
    
    def on_closing(self):
        """Handle window close."""
        if self.connected:
            self.socket.close()
        self.root.destroy()
    
    def run(self):
        """Run the client."""
        # Connect in background
        threading.Thread(target=self.connect, daemon=True).start()
        
        # Start GUI
        self.root.mainloop()


def main():
    """Main entry point."""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python client.py <username> [host] [port]")
        sys.exit(1)
    
    username = sys.argv[1]
    host = sys.argv[2] if len(sys.argv) > 2 else 'localhost'
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 5555
    
    client = SecureChatClient(host, port, username)
    client.run()


if __name__ == '__main__':
    main()
