#!/bin/bash

# =============================================================================
# Automated Network Sniffer Testing Script (macOS Compatible)
# =============================================================================
# This script compares our sniffer with tcpdump and saves results to files
# =============================================================================

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

# Configuration (with defaults from .env)
PASSWORD="$SUDO_PASSWORD"
INTERFACE="${DEFAULT_INTERFACE:-en0}"
TEST_DURATION="${TEST_DURATION:-10}"
OUTPUT_DIR="test_results"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo "=== Automated Network Sniffer Test (macOS) ===" | tee "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"
echo "Timestamp: $(date)" | tee -a "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"
echo "Interface: $INTERFACE" | tee -a "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"
echo "Test Duration: ${TEST_DURATION}s" | tee -a "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"
echo "" | tee -a "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"

# Test 1: Basic functionality test
echo "=== Test 1: Basic Functionality ===" | tee -a "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"

# Start tcpdump in background (limit to some packets)
echo "Starting tcpdump..." | tee -a "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"
echo "$PASSWORD" | sudo -S tcpdump -n -i $INTERFACE -c 20 > "$OUTPUT_DIR/tcpdump_output_$TIMESTAMP.txt" 2>&1 &
TCPDUMP_PID=$!

# Start our sniffer in background  
echo "Starting our sniffer..." | tee -a "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"
echo "$PASSWORD" | sudo -S ./sniffer $INTERFACE > "$OUTPUT_DIR/sniffer_output_$TIMESTAMP.txt" 2>&1 &
SNIFFER_PID=$!

# Wait a moment for both to start
sleep 2

# Generate test traffic
echo "Generating test traffic..." | tee -a "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"

# Test traffic 1: Ping (ICMP)
echo "  - Ping test (ICMP)" | tee -a "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"
ping -c 3 8.8.8.8 >> "$OUTPUT_DIR/traffic_log_$TIMESTAMP.txt" 2>&1 &

# Test traffic 2: DNS (UDP)
echo "  - DNS test (UDP)" | tee -a "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"
dig @8.8.8.8 google.com >> "$OUTPUT_DIR/traffic_log_$TIMESTAMP.txt" 2>&1 &

# Wait a bit
sleep 3

# Test traffic 3: HTTP (TCP)
echo "  - HTTP test (TCP)" | tee -a "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"
curl -I http://example.com >> "$OUTPUT_DIR/traffic_log_$TIMESTAMP.txt" 2>&1 &

# Additional traffic
echo "  - Additional DNS queries" | tee -a "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"
dig @1.1.1.1 cloudflare.com >> "$OUTPUT_DIR/traffic_log_$TIMESTAMP.txt" 2>&1 &

sleep 2
dig @8.8.8.8 github.com >> "$OUTPUT_DIR/traffic_log_$TIMESTAMP.txt" 2>&1 &

# Wait for test duration
echo "Running for ${TEST_DURATION} seconds..." | tee -a "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"
sleep $TEST_DURATION

# Stop our sniffer (tcpdump will stop automatically after 20 packets)
echo "Stopping sniffer..." | tee -a "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"
kill $SNIFFER_PID 2>/dev/null

# Wait for processes to finish
wait $TCPDUMP_PID 2>/dev/null
wait $SNIFFER_PID 2>/dev/null

sleep 1

echo "Test completed!" | tee -a "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"

# Generate analysis
echo "" | tee -a "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"
echo "=== Results Analysis ===" | tee -a "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"

# Count packets
TCPDUMP_PACKETS=$(grep -c " IP " "$OUTPUT_DIR/tcpdump_output_$TIMESTAMP.txt" 2>/dev/null || echo "0")
SNIFFER_PACKETS=$(grep -c " -> " "$OUTPUT_DIR/sniffer_output_$TIMESTAMP.txt" 2>/dev/null || echo "0")

echo "tcpdump captured packets: $TCPDUMP_PACKETS" | tee -a "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"
echo "Our sniffer captured packets: $SNIFFER_PACKETS" | tee -a "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"

# Check file sizes
TCPDUMP_SIZE=$(wc -l < "$OUTPUT_DIR/tcpdump_output_$TIMESTAMP.txt" 2>/dev/null || echo "0")
SNIFFER_SIZE=$(wc -l < "$OUTPUT_DIR/sniffer_output_$TIMESTAMP.txt" 2>/dev/null || echo "0")

echo "tcpdump output lines: $TCPDUMP_SIZE" | tee -a "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"
echo "Our sniffer output lines: $SNIFFER_SIZE" | tee -a "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"

# Check for errors
echo "" | tee -a "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"
echo "=== Error Check ===" | tee -a "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"

if grep -q "Error\|error\|failed\|Failed" "$OUTPUT_DIR/sniffer_output_$TIMESTAMP.txt"; then
    echo "Errors found in sniffer output!" | tee -a "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"
    grep -i "error\|failed" "$OUTPUT_DIR/sniffer_output_$TIMESTAMP.txt" | tee -a "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"
else
    echo "No errors in sniffer output" | tee -a "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"
fi

# Sample comparison
echo "" | tee -a "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"
echo "=== Sample Output Comparison ===" | tee -a "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"
echo "First 10 tcpdump lines:" | tee -a "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"
head -10 "$OUTPUT_DIR/tcpdump_output_$TIMESTAMP.txt" | tee -a "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"
echo "" | tee -a "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"
echo "First 10 sniffer lines:" | tee -a "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"
head -10 "$OUTPUT_DIR/sniffer_output_$TIMESTAMP.txt" | tee -a "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"

echo "" | tee -a "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"
echo "=== Files Created ===" | tee -a "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"
echo "Test results saved in: $OUTPUT_DIR/" | tee -a "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"
ls -la "$OUTPUT_DIR"/*_$TIMESTAMP.* | tee -a "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"

echo "" | tee -a "$OUTPUT_DIR/test_log_$TIMESTAMP.txt"
