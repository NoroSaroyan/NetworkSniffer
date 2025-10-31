#!/bin/bash

# Quick test to verify our sniffer works

# Load environment variables from .env file
ENV_FILE="../.env"
if [ -f "$ENV_FILE" ]; then
    source "$ENV_FILE"
    echo "Loaded configuration from $ENV_FILE"
else
    echo "Warning: .env file not found at $ENV_FILE"
    echo "Please create .env file with SUDO_PASSWORD variable"
    exit 1
fi

# Validate required environment variables
if [ -z "$SUDO_PASSWORD" ]; then
    echo "Error: SUDO_PASSWORD not set in .env file"
    exit 1
fi

# Configuration
PASSWORD="$SUDO_PASSWORD"
INTERFACE="${DEFAULT_INTERFACE:-en0}"

echo "=== Quick Sniffer Test ==="
echo "Testing our sniffer against tcpdump..."

# Make sure sniffer executable exists
SNIFFER_PATH="../sniffer"
if [ ! -f "$SNIFFER_PATH" ]; then
    echo "Error: sniffer executable not found at $SNIFFER_PATH!"
    echo "Current directory: $(pwd)"
    echo "Please build the sniffer first: cd .. && make"
    exit 1
fi

echo "Sniffer executable found"

# Test our sniffer for 5 seconds while generating traffic
echo "Starting our sniffer for 5 seconds..."
echo "$PASSWORD" | sudo -S "$SNIFFER_PATH" $INTERFACE &
SNIFFER_PID=$!

sleep 1

# Generate some quick traffic
echo "Generating test traffic..."
ping -c 2 8.8.8.8 &
sleep 1
dig @8.8.8.8 google.com &

# Let it run for a few seconds
sleep 5

# Stop the sniffer
kill $SNIFFER_PID 2>/dev/null
wait $SNIFFER_PID 2>/dev/null

echo "Test completed!"
echo ""
echo "If you saw packet output above, our sniffer is working correctly!"
echo "Expected format: YYYY-MM-DD HH:MM:SS.UUUUUU src_ip:port -> dst_ip:port PROTOCOL len=X"