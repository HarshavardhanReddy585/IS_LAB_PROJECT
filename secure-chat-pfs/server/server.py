"""
server.py - Simple TCP relay server for encrypted chat

This server acts as a message relay ONLY. It:
- Accepts client connections
- Routes encrypted messages between clients
- Does NOT decrypt or inspect message content
- Only forwards JSON blobs

Security model:
- Server is untrusted (zero-knowledge)
- All encryption/decryption happens client-side
- Server only sees ciphertext
"""

import socket
import threading
import json
import time
from typing import Dict, Optional

# Configuration (can be adjusted)
SERVER_HOST = '0.0.0.0'  # Listen on all interfaces
SERVER_PORT = 5555       # Default port (change if needed)
MAX_CLIENTS = 10
BUFFER_SIZE = 65536      # 64KB for large file chunks


class ClientHandler:
    """Handles individual client connection."""
    
    def __init__(self, client_socket: socket.socket, address: tuple, server: 'ChatServer'):
        self.socket = client_socket
        self.address = address
        self.server = server
        self.username: Optional[str] = None
        self.running = True
        
    def handle(self):
        """Main message handling loop."""
        print(f"[SERVER] New connection from {self.address}")
        
        try:
            while self.running:
                # Receive message length first (4 bytes)
                length_bytes = self._recv_exact(4)
                if not length_bytes:
                    break
                
                msg_length = int.from_bytes(length_bytes, byteorder='big')
                
                # Receive actual message
                data = self._recv_exact(msg_length)
                if not data:
                    break
                
                # Parse JSON message
                try:
                    message = json.loads(data.decode('utf-8'))
                    self.process_message(message)
                except json.JSONDecodeError as e:
                    print(f"[SERVER] Invalid JSON from {self.address}: {e}")
                    
        except Exception as e:
            print(f"[SERVER] Error handling client {self.address}: {e}")
        finally:
            self.cleanup()
    
    def _recv_exact(self, n: int) -> Optional[bytes]:
        """Receive exactly n bytes from socket."""
        data = b''
        while len(data) < n:
            chunk = self.socket.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data
    
    def process_message(self, message: Dict):
        """
        Process incoming message and route appropriately.
        
        Message types:
        - 'register': Client registration with username
        - 'message': Encrypted message to forward
        - 'file_chunk': Encrypted file chunk to forward
        - 'key_exchange': Public key exchange
        - 'ratchet': Ratchet notification
        - 'list_users': Request user list
        - 'create_group': Create a new group
        - 'join_group': Join an existing group
        - 'leave_group': Leave a group
        - 'group_message': Message to a group
        - 'list_groups': Request group list
        - 'group_key_exchange': Encrypted group key distribution
        """
        msg_type = message.get('type')
        
        if msg_type == 'register':
            self.handle_register(message)
        elif msg_type == 'message':
            self.handle_message(message)
        elif msg_type == 'file_chunk':
            self.handle_file_chunk(message)
        elif msg_type == 'key_exchange':
            self.handle_key_exchange(message)
        elif msg_type == 'ratchet':
            self.handle_ratchet(message)
        elif msg_type == 'list_users':
            self.handle_list_users()
        elif msg_type == 'create_group':
            self.handle_create_group(message)
        elif msg_type == 'join_group':
            self.handle_join_group(message)
        elif msg_type == 'leave_group':
            self.handle_leave_group(message)
        elif msg_type == 'group_message':
            self.handle_group_message(message)
        elif msg_type == 'list_groups':
            self.handle_list_groups()
        elif msg_type == 'group_key_exchange':
            self.handle_group_key_exchange(message)
        elif msg_type == 'group_file_chunk':
            self.handle_group_file_chunk(message)
        else:
            print(f"[SERVER] Unknown message type: {msg_type}")
    
    def handle_register(self, message: Dict):
        """Register client with username."""
        username = message.get('username')
        if username:
            self.username = username
            self.server.register_client(username, self)
            print(f"[SERVER] Client registered: {username} from {self.address}")
            
            # Send confirmation
            self.send_message({
                'type': 'register_ack',
                'username': username,
                'timestamp': time.time()
            })
            
            # Broadcast user list update
            self.server.broadcast_user_list()
    
    def handle_message(self, message: Dict):
        """Forward encrypted message to recipient."""
        recipient = message.get('to')
        sender = message.get('from')
        
        # Server does NOT decrypt - just forwards the encrypted blob
        print(f"[SERVER] Forwarding encrypted message: {sender} -> {recipient}")
        self.server.route_message(recipient, message)
    
    def handle_file_chunk(self, message: Dict):
        """Forward encrypted file chunk to recipient."""
        recipient = message.get('to')
        sender = message.get('from')
        chunk_num = message.get('chunk_num', 0)
        
        print(f"[SERVER] Forwarding file chunk {chunk_num}: {sender} -> {recipient}")
        self.server.route_message(recipient, message)
    
    def handle_key_exchange(self, message: Dict):
        """Forward public key to peer for ECDH."""
        recipient = message.get('to')
        print(f"[SERVER] Forwarding key exchange: {self.username} -> {recipient}")
        self.server.route_message(recipient, message)
    
    def handle_ratchet(self, message: Dict):
        """Forward ratchet notification to peer."""
        recipient = message.get('to')
        print(f"[SERVER] Forwarding ratchet: {self.username} -> {recipient}")
        self.server.route_message(recipient, message)
    
    def handle_list_users(self):
        """Send current user list to client."""
        users = self.server.get_user_list()
        self.send_message({
            'type': 'user_list',
            'users': users,
            'timestamp': time.time()
        })

    def handle_create_group(self, message: Dict):
        """Create a new group."""
        group_name = message.get('group_name')
        group_id = message.get('group_id')
        members = message.get('members', [])

        if not group_name or not group_id:
            return

        # Add creator to members
        if self.username and self.username not in members:
            members.append(self.username)

        self.server.create_group(group_id, group_name, self.username, members)
        print(f"[SERVER] Group created: {group_name} by {self.username}")

        # Send confirmation to creator
        self.send_message({
            'type': 'group_created',
            'group_id': group_id,
            'group_name': group_name,
            'members': members,
            'timestamp': time.time()
        })

        # Notify all members
        self.server.broadcast_group_list()

    def handle_join_group(self, message: Dict):
        """Join an existing group."""
        group_id = message.get('group_id')

        if group_id and self.username:
            success = self.server.add_to_group(group_id, self.username)
            if success:
                print(f"[SERVER] {self.username} joined group {group_id}")
                self.server.broadcast_group_list()

    def handle_leave_group(self, message: Dict):
        """Leave a group."""
        group_id = message.get('group_id')

        if group_id and self.username:
            success = self.server.remove_from_group(group_id, self.username)
            if success:
                print(f"[SERVER] {self.username} left group {group_id}")
                self.server.broadcast_group_list()

    def handle_group_message(self, message: Dict):
        """Broadcast encrypted message to all group members."""
        group_id = message.get('group_id')
        sender = message.get('from')

        print(f"[SERVER] Broadcasting group message: {sender} -> group {group_id}")
        self.server.broadcast_to_group(group_id, message, exclude=sender)

    def handle_list_groups(self):
        """Send current group list to client."""
        groups = self.server.get_group_list(self.username)
        self.send_message({
            'type': 'group_list',
            'groups': groups,
            'timestamp': time.time()
        })

    def handle_group_key_exchange(self, message: Dict):
        """Forward encrypted group key to specific member."""
        recipient = message.get('to')
        print(f"[SERVER] Forwarding group key: {self.username} -> {recipient}")
        self.server.route_message(recipient, message)

    def handle_group_file_chunk(self, message: Dict):
        """Broadcast encrypted file chunk to all group members."""
        group_id = message.get('group_id')
        sender = message.get('from')
        chunk_num = message.get('chunk_num', 0)

        print(f"[SERVER] Broadcasting group file chunk {chunk_num}: {sender} -> group {group_id}")
        self.server.broadcast_to_group(group_id, message, exclude=sender)
    
    def send_message(self, message: Dict):
        """Send JSON message to this client."""
        try:
            data = json.dumps(message).encode('utf-8')
            length = len(data).to_bytes(4, byteorder='big')
            self.socket.sendall(length + data)
        except Exception as e:
            print(f"[SERVER] Error sending to {self.username}: {e}")
            self.running = False
    
    def cleanup(self):
        """Clean up connection."""
        print(f"[SERVER] Client disconnected: {self.username or self.address}")
        if self.username:
            self.server.unregister_client(self.username)
        self.socket.close()
        self.server.broadcast_user_list()


class ChatServer:
    """
    Main chat server - acts as untrusted relay.
    
    Security note: Server never decrypts messages.
    It only routes encrypted JSON blobs between clients.
    """
    
    def __init__(self, host: str = SERVER_HOST, port: int = SERVER_PORT):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Client registry: username -> ClientHandler
        self.clients: Dict[str, ClientHandler] = {}
        self.clients_lock = threading.Lock()

        # Group registry: group_id -> {name, creator, members: [usernames]}
        self.groups: Dict[str, Dict] = {}
        self.groups_lock = threading.Lock()

        self.running = False
    
    def start(self):
        """Start the server."""
        self.socket.bind((self.host, self.port))
        self.socket.listen(MAX_CLIENTS)
        self.running = True
        
        print(f"[SERVER] Chat relay server started on {self.host}:{self.port}")
        print(f"[SERVER] Waiting for connections...")
        print(f"[SERVER] Security note: Server is untrusted relay (sees only ciphertext)")
        
        try:
            while self.running:
                client_socket, address = self.socket.accept()
                
                # Handle each client in separate thread
                handler = ClientHandler(client_socket, address, self)
                client_thread = threading.Thread(target=handler.handle, daemon=True)
                client_thread.start()
                
        except KeyboardInterrupt:
            print("\n[SERVER] Shutting down...")
        finally:
            self.stop()
    
    def register_client(self, username: str, handler: ClientHandler):
        """Register a client."""
        with self.clients_lock:
            self.clients[username] = handler
    
    def unregister_client(self, username: str):
        """Unregister a client."""
        with self.clients_lock:
            if username in self.clients:
                del self.clients[username]
    
    def route_message(self, recipient: str, message: Dict):
        """Route message to specific recipient."""
        with self.clients_lock:
            if recipient in self.clients:
                self.clients[recipient].send_message(message)
            else:
                # Recipient not connected - could queue or drop
                print(f"[SERVER] Recipient '{recipient}' not found")
    
    def broadcast_user_list(self):
        """Broadcast updated user list to all clients."""
        users = self.get_user_list()
        message = {
            'type': 'user_list',
            'users': users,
            'timestamp': time.time()
        }
        
        with self.clients_lock:
            for handler in self.clients.values():
                handler.send_message(message)
    
    def get_user_list(self) -> list:
        """Get list of currently connected users."""
        with self.clients_lock:
            return list(self.clients.keys())

    def create_group(self, group_id: str, group_name: str, creator: str, members: list):
        """Create a new group."""
        with self.groups_lock:
            self.groups[group_id] = {
                'name': group_name,
                'creator': creator,
                'members': list(set(members))  # Ensure unique members
            }

    def add_to_group(self, group_id: str, username: str) -> bool:
        """Add user to group."""
        with self.groups_lock:
            if group_id in self.groups:
                if username not in self.groups[group_id]['members']:
                    self.groups[group_id]['members'].append(username)
                return True
            return False

    def remove_from_group(self, group_id: str, username: str) -> bool:
        """Remove user from group."""
        with self.groups_lock:
            if group_id in self.groups:
                if username in self.groups[group_id]['members']:
                    self.groups[group_id]['members'].remove(username)
                return True
            return False

    def get_group_list(self, username: Optional[str] = None) -> list:
        """Get list of groups (optionally filtered by member)."""
        with self.groups_lock:
            if username:
                # Return groups this user is a member of
                return [
                    {
                        'group_id': gid,
                        'name': gdata['name'],
                        'creator': gdata['creator'],
                        'members': gdata['members']
                    }
                    for gid, gdata in self.groups.items()
                    if username in gdata['members']
                ]
            else:
                # Return all groups
                return [
                    {
                        'group_id': gid,
                        'name': gdata['name'],
                        'creator': gdata['creator'],
                        'members': gdata['members']
                    }
                    for gid, gdata in self.groups.items()
                ]

    def broadcast_to_group(self, group_id: str, message: Dict, exclude: Optional[str] = None):
        """Broadcast message to all group members."""
        with self.groups_lock:
            if group_id not in self.groups:
                return

            members = self.groups[group_id]['members']

        # Send to each member
        with self.clients_lock:
            for member in members:
                if member != exclude and member in self.clients:
                    self.clients[member].send_message(message)

    def broadcast_group_list(self):
        """Broadcast updated group list to all clients."""
        with self.clients_lock:
            for username, handler in self.clients.items():
                groups = self.get_group_list(username)
                handler.send_message({
                    'type': 'group_list',
                    'groups': groups,
                    'timestamp': time.time()
                })

    def stop(self):
        """Stop the server."""
        self.running = False
        self.socket.close()
        print("[SERVER] Server stopped")


def main():
    """Main entry point."""
    import sys
    
    # Allow custom port via command line
    port = SERVER_PORT
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print(f"Usage: python server.py [port]")
            sys.exit(1)
    
    server = ChatServer(port=port)
    server.start()


if __name__ == '__main__':
    main()
