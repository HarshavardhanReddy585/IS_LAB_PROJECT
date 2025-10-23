"""
ui_components.py - Tkinter GUI components for secure chat client

Provides reusable widgets for:
- User list display
- Chat message display
- Input controls
- Status indicators
- Encryption info display
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from typing import Callable, Optional, List, Dict


class UserListFrame(ttk.LabelFrame):
    """Display connected users."""
    
    def __init__(self, parent, on_user_select: Callable[[str], None]):
        super().__init__(parent, text="Connected Users", padding=5)
        self.on_user_select = on_user_select
        
        # Listbox for users
        self.listbox = tk.Listbox(self, height=15, width=20)
        self.listbox.pack(fill=tk.BOTH, expand=True)
        self.listbox.bind('<<ListboxSelect>>', self._on_select)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(self.listbox, orient=tk.VERTICAL, command=self.listbox.yview)
        self.listbox.config(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.selected_user: Optional[str] = None
    
    def update_users(self, users: List[str], current_user: str):
        """Update user list (exclude current user)."""
        self.listbox.delete(0, tk.END)
        for user in users:
            if user != current_user:
                self.listbox.insert(tk.END, user)
    
    def _on_select(self, event):
        """Handle user selection."""
        selection = self.listbox.curselection()
        if selection:
            self.selected_user = self.listbox.get(selection[0])
            self.on_user_select(self.selected_user)
    
    def get_selected_user(self) -> Optional[str]:
        """Get currently selected user."""
        return self.selected_user


class ChatDisplayFrame(ttk.LabelFrame):
    """Display chat messages."""
    
    def __init__(self, parent):
        super().__init__(parent, text="Chat Messages", padding=5)
        
        # ScrolledText for messages
        self.text_area = scrolledtext.ScrolledText(
            self, 
            wrap=tk.WORD, 
            width=60, 
            height=20,
            state=tk.DISABLED
        )
        self.text_area.pack(fill=tk.BOTH, expand=True)
        
        # Configure tags for styling
        self.text_area.tag_config('sent', foreground='blue')
        self.text_area.tag_config('received', foreground='green')
        self.text_area.tag_config('system', foreground='red', font=('Arial', 9, 'italic'))
        self.text_area.tag_config('error', foreground='red', font=('Arial', 9, 'bold'))
    
    def add_message(self, message: str, tag: str = 'system'):
        """Add message to display."""
        self.text_area.config(state=tk.NORMAL)
        self.text_area.insert(tk.END, message + '\n', tag)
        self.text_area.see(tk.END)
        self.text_area.config(state=tk.DISABLED)
    
    def clear(self):
        """Clear all messages."""
        self.text_area.config(state=tk.NORMAL)
        self.text_area.delete(1.0, tk.END)
        self.text_area.config(state=tk.DISABLED)


class MessageInputFrame(ttk.Frame):
    """Message input controls."""
    
    def __init__(self, parent, on_send: Callable[[str], None], on_attach: Callable):
        super().__init__(parent, padding=5)
        
        # Input field
        self.entry = ttk.Entry(self, width=50)
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.entry.bind('<Return>', lambda e: self._send())
        
        # Send button
        self.send_btn = ttk.Button(self, text="Send", command=self._send)
        self.send_btn.pack(side=tk.LEFT, padx=2)
        
        # Attach file button
        self.attach_btn = ttk.Button(self, text="Attach File", command=on_attach)
        self.attach_btn.pack(side=tk.LEFT, padx=2)
        
        self.on_send = on_send
    
    def _send(self):
        """Handle send button."""
        message = self.entry.get().strip()
        if message:
            self.on_send(message)
            self.entry.delete(0, tk.END)
    
    def set_enabled(self, enabled: bool):
        """Enable/disable input controls."""
        state = tk.NORMAL if enabled else tk.DISABLED
        self.entry.config(state=state)
        self.send_btn.config(state=state)
        self.attach_btn.config(state=state)


class EncryptionInfoFrame(ttk.LabelFrame):
    """Display encryption status and controls."""
    
    def __init__(self, parent, on_rekey: Callable, on_show_ciphertext: Callable):
        super().__init__(parent, text="Encryption Info", padding=5)
        
        # Key fingerprint
        ttk.Label(self, text="Key Fingerprint:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.fingerprint_var = tk.StringVar(value="NO_KEY")
        ttk.Label(self, textvariable=self.fingerprint_var, font=('Courier', 10, 'bold')).grid(
            row=0, column=1, sticky=tk.W, padx=5, pady=2
        )
        
        # Ratchet count
        ttk.Label(self, text="Ratchet Count:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.ratchet_var = tk.StringVar(value="0")
        ttk.Label(self, textvariable=self.ratchet_var, font=('Courier', 10)).grid(
            row=1, column=1, sticky=tk.W, padx=5, pady=2
        )
        
        # Session ID
        ttk.Label(self, text="Session ID:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.session_var = tk.StringVar(value="None")
        ttk.Label(self, textvariable=self.session_var, font=('Courier', 9)).grid(
            row=2, column=1, sticky=tk.W, padx=5, pady=2
        )
        
        # Control buttons
        btn_frame = ttk.Frame(self)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=5)
        
        ttk.Button(btn_frame, text="Force Rekey", command=on_rekey).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="Show Ciphertext", command=on_show_ciphertext).pack(side=tk.LEFT, padx=2)
    
    def update_fingerprint(self, fingerprint: str):
        """Update key fingerprint display."""
        self.fingerprint_var.set(fingerprint)
    
    def update_ratchet_count(self, count: int):
        """Update ratchet count display."""
        self.ratchet_var.set(str(count))
    
    def update_session_id(self, session_id: str):
        """Update session ID display."""
        self.session_var.set(session_id[:16] + "...")


class StatusBar(ttk.Frame):
    """Status bar at bottom of window."""
    
    def __init__(self, parent):
        super().__init__(parent, relief=tk.SUNKEN, padding=2)
        
        self.status_var = tk.StringVar(value="Disconnected")
        self.label = ttk.Label(self, textvariable=self.status_var)
        self.label.pack(side=tk.LEFT)
        
        # Connection indicator
        self.indicator = tk.Canvas(self, width=15, height=15, bg='white', highlightthickness=0)
        self.indicator.pack(side=tk.RIGHT, padx=5)
        self.indicator_circle = self.indicator.create_oval(2, 2, 13, 13, fill='red', outline='')
    
    def set_status(self, message: str, connected: bool = False):
        """Update status message."""
        self.status_var.set(message)
        color = 'green' if connected else 'red'
        self.indicator.itemconfig(self.indicator_circle, fill=color)


class CiphertextDialog:
    """Dialog to show raw ciphertext for demonstration."""
    
    def __init__(self, parent, title: str, ciphertext_data: dict):
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.geometry("600x400")
        
        # Text area
        text_area = scrolledtext.ScrolledText(self.dialog, wrap=tk.WORD)
        text_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Display ciphertext info
        import json
        text_area.insert(tk.END, "=== RAW CIPHERTEXT (Base64) ===\n\n")
        text_area.insert(tk.END, json.dumps(ciphertext_data, indent=2))
        text_area.config(state=tk.DISABLED)
        
        # Close button
        ttk.Button(self.dialog, text="Close", command=self.dialog.destroy).pack(pady=5)


class FileTransferDialog:
    """Dialog showing file transfer progress."""

    def __init__(self, parent, filename: str, total_chunks: int):
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(f"Transferring: {filename}")
        self.dialog.geometry("400x150")

        ttk.Label(self.dialog, text=f"Transferring: {filename}").pack(pady=10)

        # Progress bar
        self.progress_var = tk.DoubleVar(value=0)
        self.progress_bar = ttk.Progressbar(
            self.dialog,
            variable=self.progress_var,
            maximum=100,
            length=350
        )
        self.progress_bar.pack(pady=10)

        # Status label
        self.status_var = tk.StringVar(value="Chunk 0 / {total_chunks}")
        ttk.Label(self.dialog, textvariable=self.status_var).pack(pady=5)

        self.total_chunks = total_chunks

    def update_progress(self, current_chunk: int):
        """Update progress bar."""
        progress = (current_chunk / self.total_chunks) * 100
        self.progress_var.set(progress)
        self.status_var.set(f"Chunk {current_chunk} / {self.total_chunks}")

        if current_chunk >= self.total_chunks:
            self.dialog.after(1000, self.dialog.destroy)


class CreateGroupDialog:
    """Dialog for creating a new group."""

    def __init__(self, parent, available_users: List[str], on_create: Callable):
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Create Group")
        self.dialog.geometry("400x400")
        self.on_create = on_create

        # Group name
        ttk.Label(self.dialog, text="Group Name:").pack(pady=(10, 5))
        self.name_entry = ttk.Entry(self.dialog, width=40)
        self.name_entry.pack(pady=5)

        # Members selection
        ttk.Label(self.dialog, text="Select Members:").pack(pady=(10, 5))

        # Scrollable frame for checkboxes
        members_frame = ttk.Frame(self.dialog)
        members_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        canvas = tk.Canvas(members_frame, height=200)
        scrollbar = ttk.Scrollbar(members_frame, orient=tk.VERTICAL, command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        # Create checkboxes for each user
        self.member_vars = {}
        for user in available_users:
            var = tk.BooleanVar(value=False)
            self.member_vars[user] = var
            ttk.Checkbutton(scrollable_frame, text=user, variable=var).pack(anchor=tk.W, pady=2)

        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Buttons
        btn_frame = ttk.Frame(self.dialog)
        btn_frame.pack(pady=10)

        ttk.Button(btn_frame, text="Create", command=self._on_create).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=self.dialog.destroy).pack(side=tk.LEFT, padx=5)

    def _on_create(self):
        """Handle create button."""
        group_name = self.name_entry.get().strip()
        if not group_name:
            messagebox.showwarning("Invalid Name", "Please enter a group name")
            return

        # Get selected members
        selected_members = [user for user, var in self.member_vars.items() if var.get()]

        if len(selected_members) < 1:
            messagebox.showwarning("No Members", "Please select at least one member")
            return

        self.on_create(group_name, selected_members)
        self.dialog.destroy()


class GroupUserListFrame(ttk.LabelFrame):
    """Combined display for users and groups."""

    def __init__(self, parent, on_user_select: Callable[[str]], on_group_select: Callable[[str]], on_create_group: Callable):
        super().__init__(parent, text="Users & Groups", padding=5)
        self.on_user_select = on_user_select
        self.on_group_select = on_group_select

        # Create group button
        ttk.Button(self, text="Create Group", command=on_create_group).pack(fill=tk.X, pady=(0, 5))

        # Users section
        ttk.Label(self, text="Users:", font=('Arial', 9, 'bold')).pack(anchor=tk.W, pady=(5, 2))
        self.user_listbox = tk.Listbox(self, height=8, width=20)
        self.user_listbox.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        self.user_listbox.bind('<<ListboxSelect>>', self._on_user_select)

        # Groups section
        ttk.Label(self, text="Groups:", font=('Arial', 9, 'bold')).pack(anchor=tk.W, pady=(5, 2))
        self.group_listbox = tk.Listbox(self, height=8, width=20)
        self.group_listbox.pack(fill=tk.BOTH, expand=True)
        self.group_listbox.bind('<<ListboxSelect>>', self._on_group_select)

        self.selected_type: Optional[str] = None  # 'user' or 'group'
        self.selected_id: Optional[str] = None

    def update_users(self, users: List[str], current_user: str):
        """Update user list (exclude current user)."""
        self.user_listbox.delete(0, tk.END)
        for user in users:
            if user != current_user:
                self.user_listbox.insert(tk.END, user)

    def update_groups(self, groups: List[Dict]):
        """Update group list."""
        self.group_listbox.delete(0, tk.END)
        for group in groups:
            display_name = f"{group['name']} ({len(group['members'])})"
            self.group_listbox.insert(tk.END, display_name)

    def _on_user_select(self, event):
        """Handle user selection."""
        selection = self.user_listbox.curselection()
        if selection:
            # Clear group selection
            self.group_listbox.selection_clear(0, tk.END)

            username = self.user_listbox.get(selection[0])
            self.selected_type = 'user'
            self.selected_id = username
            self.on_user_select(username)

    def _on_group_select(self, event):
        """Handle group selection."""
        selection = self.group_listbox.curselection()
        if selection:
            # Clear user selection
            self.user_listbox.selection_clear(0, tk.END)

            # Extract group name from display (format: "name (count)")
            display_text = self.group_listbox.get(selection[0])
            # Note: We'll need to pass group_id from client, for now use index
            self.selected_type = 'group'
            self.on_group_select(selection[0])

    def get_selected(self) -> tuple:
        """Get currently selected item (type, id)."""
        return (self.selected_type, self.selected_id)
