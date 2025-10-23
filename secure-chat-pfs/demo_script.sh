#!/bin/bash

# Demo script for Secure Chat with PFS
# Launches server and two clients for demonstration

echo "==================================="
echo "Secure Chat with PFS - Demo Launcher"
echo "==================================="
echo ""

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "ERROR: python3 not found"
    exit 1
fi

# Check if dependencies are installed
echo "Checking dependencies..."
python3 -c "from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "ERROR: cryptography library not installed"
    echo "Run: pip install -r requirements.txt"
    exit 1
fi

echo "✓ Dependencies OK"
echo ""

# Function to check if port is in use
check_port() {
    if lsof -Pi :$1 -sTCP:LISTEN -t >/dev/null 2>&1 ; then
        return 0
    else
        return 1
    fi
}

# Check if port 5555 is available
if check_port 5555; then
    echo "WARNING: Port 5555 is already in use"
    echo "Please stop the existing server or change SERVER_PORT in server/server.py"
    exit 1
fi

echo "Starting demo with:"
echo "  - Server on port 5555"
echo "  - Client 1: Alice"
echo "  - Client 2: Bob"
echo ""
echo "To stop: Press Ctrl+C in this terminal"
echo ""

# Determine the OS for terminal commands
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    echo "Detected macOS - using Terminal.app"
    
    # Start server in new terminal
    osascript -e 'tell application "Terminal" to do script "cd \"'"$(pwd)"'/server\" && python3 server.py"'
    
    sleep 2
    
    # Start Alice
    osascript -e 'tell application "Terminal" to do script "cd \"'"$(pwd)"'/client\" && python3 client.py Alice localhost 5555"'
    
    sleep 1
    
    # Start Bob
    osascript -e 'tell application "Terminal" to do script "cd \"'"$(pwd)"'/client\" && python3 client.py Bob localhost 5555"'
    
    echo "✓ Server and clients launched in separate Terminal windows"
    echo ""
    echo "Next steps:"
    echo "  1. In Alice's window: Click on 'Bob' in user list"
    echo "  2. In Bob's window: Click on 'Alice' in user list"
    echo "  3. Wait for key exchange to complete"
    echo "  4. Start chatting!"
    echo ""
    echo "Demo features to show:"
    echo "  - Verify key fingerprints match in both windows"
    echo "  - Send messages and see encryption"
    echo "  - Click 'Show Ciphertext' to see raw encrypted data"
    echo "  - Click 'Force Rekey' to trigger ratcheting"
    echo "  - Use 'Attach File' to send encrypted files"
    echo ""
    echo "To monitor traffic: Open Wireshark and filter 'tcp.port == 5555'"
    
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux
    echo "Detected Linux"
    
    # Try to detect terminal emulator
    if command -v gnome-terminal &> /dev/null; then
        TERMINAL="gnome-terminal --"
    elif command -v konsole &> /dev/null; then
        TERMINAL="konsole -e"
    elif command -v xterm &> /dev/null; then
        TERMINAL="xterm -e"
    else
        echo "ERROR: No terminal emulator found (gnome-terminal, konsole, or xterm)"
        echo "Please start manually:"
        echo "  Terminal 1: cd server && python3 server.py"
        echo "  Terminal 2: cd client && python3 client.py Alice"
        echo "  Terminal 3: cd client && python3 client.py Bob"
        exit 1
    fi
    
    # Start server
    $TERMINAL "cd $(pwd)/server && python3 server.py; bash" &
    sleep 2
    
    # Start Alice
    $TERMINAL "cd $(pwd)/client && python3 client.py Alice localhost 5555; bash" &
    sleep 1
    
    # Start Bob
    $TERMINAL "cd $(pwd)/client && python3 client.py Bob localhost 5555; bash" &
    
    echo "✓ Server and clients launched"
    echo ""
    echo "Follow the same steps as described above"
    
else
    # Windows or unknown
    echo "Platform not detected - please start manually:"
    echo ""
    echo "Terminal 1 - Server:"
    echo "  cd server"
    echo "  python server.py"
    echo ""
    echo "Terminal 2 - Alice:"
    echo "  cd client"
    echo "  python client.py Alice localhost 5555"
    echo ""
    echo "Terminal 3 - Bob:"
    echo "  cd client"
    echo "  python client.py Bob localhost 5555"
    exit 1
fi

echo ""
echo "Press Enter to stop all processes..."
read

# Cleanup
echo "Stopping demo..."
if [[ "$OSTYPE" == "darwin"* ]] || [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Kill Python processes on port 5555
    lsof -ti:5555 | xargs kill -9 2>/dev/null
    echo "✓ Demo stopped"
fi
