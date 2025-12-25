# Usage Guide - NetworkSniffer Distributed System

Complete guide for building, deploying, and using the NetworkSniffer distributed network monitoring system.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Building the Project](#building-the-project)
3. [Component Usage](#component-usage)
4. [System Deployment](#system-deployment)
5. [Testing and Verification](#testing-and-verification)
6. [Configuration Options](#configuration-options)
7. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements

- **macOS 10.14+** with Xcode Command Line Tools
- **C++17** compatible compiler (clang++ version 10+)
- **Root/sudo privileges** for BPF device access
- **Qt 5.15+** or **Qt 6.x** (for GUI client only)
- **CMake 3.16+** (for GUI client build)

### Software Installation

#### macOS Command Line Tools

```bash
xcode-select --install
```

#### Qt Framework (Optional - only needed for GUI client)

**Via Homebrew**:
```bash
brew install qt@6
# or
brew install qt@5
```

**Via Qt Installer**:
- Download from [qt.io](https://www.qt.io/download)
- Install to default location

#### CMake (if not already installed)

```bash
brew install cmake
```

---

## Building the Project

### Quick Build (Sniffer Only)

```bash
cd /path/to/NetworkSniffer
make clean
make
```

This produces the `sniffer` binary for command-line packet capture.

### Complete Build (All Components)

```bash
cd /path/to/NetworkSniffer
mkdir -p build
cd build
cmake ..
make
```

This produces three binaries:
- `sniffer` - Standalone sniffer or distributed client
- `SnifferServer` - Central server hub
- `SnifferGUI` - Qt-based GUI client

### Build Flags and Options

**Debug Build**:
```bash
cmake -DCMAKE_BUILD_TYPE=Debug ..
make
```

**Release Build (Optimized)**:
```bash
cmake -DCMAKE_BUILD_TYPE=Release ..
make
```

**With Qt6 instead of Qt5**:
```bash
cmake -DCMAKE_PREFIX_PATH=/usr/local/opt/qt@6 ..
make
```

---

## Component Usage

### 1. Sniffer Node (Packet Capture)

The sniffer captures packets via BPF and either prints locally or sends to server.

#### Local Mode (Console Output)

```bash
sudo ./sniffer <interface>
```

**Examples**:
```bash
sudo ./sniffer en0           # Capture on main interface
sudo ./sniffer en1           # Capture on secondary interface
sudo ./sniffer lo0           # Capture on loopback
```

**Output Format**:
```
Opened /dev/bpf1
Attached to en0 (bpf buf 4096 bytes)
2024-12-25 14:32:15.123456 192.168.1.10:54321 -> 8.8.8.8:443 TCP len=60
2024-12-25 14:32:16.234567 192.168.1.10:53 -> 8.8.8.8:53 UDP len=56
2024-12-25 14:32:17.345678 192.168.1.10:64 -> 8.8.8.8:64 ICMP len=36
```

**Keyboard Controls**:
- `Ctrl+C` - Stop capture and exit gracefully

#### Distributed Mode (Send to Server)

```bash
sudo ./sniffer <interface> <server_host> <server_port>
```

**Examples**:
```bash
# Connect to local server
sudo ./sniffer en0 127.0.0.1 9090

# Connect to remote server
sudo ./sniffer en0 192.168.1.100 9090

# Multiple sniffers on different interfaces
sudo ./sniffer en0 127.0.0.1 9090  # Terminal 1
sudo ./sniffer en1 127.0.0.1 9090  # Terminal 2
```

**Output in Distributed Mode**:
- Minimal console output (just status messages)
- All traffic logs sent to server
- Appears in GUI client's corresponding tab

---

### 2. Central Server (Log Hub)

The server accepts connections from sniffers and forwards logs to GUI clients.

#### Starting the Server

```bash
./build/SnifferServer <port>
```

**Examples**:
```bash
./build/SnifferServer 9090           # Standard port
./build/SnifferServer 8888           # Custom port
```

#### Server Output

```
Listening on port 9090...
[Sniffer] Connected from 127.0.0.1:12345 (SSID: 1)
[Sniffer] en0 registered on SSID 1
[GUI] Connected from 127.0.0.1:12346
[Server] Forwarding logs: 42 packets from sniffer 1
```

#### Server Keyboard Controls

- `Ctrl+C` - Shutdown server gracefully
- Clients are cleanly disconnected on shutdown

#### Server Configuration

- **Port**: Specified as command-line argument (default: 9090)
- **Max Clients**: Typically hundreds (depends on system resources)
- **Buffer Size**: Automatically optimized
- **Logging**: Directed to standard output/error

---

### 3. GUI Client (Visualization)

The Qt-based GUI displays captured traffic from all connected sniffers in real-time.

#### Launching the GUI

```bash
./build/SnifferGUI
```

No arguments needed - configuration is done in the GUI.

#### GUI Features

**Main Window**:
- Toolbar with connection status
- Tabs organized by sniffer SSID
- Traffic log table with sortable columns
- Real-time statistics display

**Connection Settings**:
1. Enter Server Host (e.g., `127.0.0.1` or `192.168.1.100`)
2. Enter Server Port (e.g., `9090`)
3. Click "Connect" button
4. Wait for connection confirmation

**Log Display**:
- **Timestamp**: Microsecond-precision BPF timestamp
- **Source**: Source IP:Port
- **Destination**: Destination IP:Port
- **Protocol**: TCP, UDP, ICMP, etc.
- **Length**: Packet size in bytes

**Statistics**:
- Total packets captured
- Packets per protocol
- Bandwidth information (if available)
- Connection count

**Filtering** (if implemented):
- Protocol filter (TCP/UDP/ICMP)
- Port number search
- IP address search

---

## System Deployment

### Scenario 1: Local Testing (Single Machine)

Ideal for development and testing on a single macOS machine.

```bash
# Terminal 1: Start server
./build/SnifferServer 9090

# Terminal 2: Start GUI client
./build/SnifferGUI
# In GUI: Connect to localhost:9090

# Terminal 3: Start sniffer
sudo ./sniffer en0 127.0.0.1 9090

# Terminal 4 (optional): Start second sniffer
sudo ./sniffer en1 127.0.0.1 9090
```

**Expected Result**:
- GUI connects to server
- Sniffer connects and appears in GUI as tab
- Traffic appears in real-time in GUI
- Multiple sniffers show in separate tabs

### Scenario 2: Remote Monitoring (Network Deployment)

Monitor multiple machines from a central monitoring station.

```bash
# On monitoring server machine (192.168.1.100)
./build/SnifferServer 9090

# On monitoring workstation
./build/SnifferGUI
# In GUI: Connect to 192.168.1.100:9090

# On sniffer machine 1
sudo ./sniffer en0 192.168.1.100 9090

# On sniffer machine 2
sudo ./sniffer en0 192.168.1.100 9090
```

**Network Topology**:
```
Sniffer 1 (192.168.1.50)
    |
    | TCP to 192.168.1.100:9090
    |
    ├──> Server (192.168.1.100:9090)
    |
    ├──> GUI Client (192.168.1.200)
    |
Sniffer 2 (192.168.1.60)
```

### Scenario 3: Standalone Console Mode

Use sniffer without server/GUI for command-line logging.

```bash
sudo ./sniffer en0 | tee traffic.log
```

Captures to both console and file `traffic.log`.

---

## Testing and Verification

### Pre-Flight Checks

```bash
# Check available network interfaces
ifconfig | grep -E "^[a-z]"

# Check for BPF devices
ls -la /dev/bpf*

# Verify Qt installation (if building GUI)
which qmake
```

### Basic Functionality Test

```bash
# Terminal 1: Start server
./build/SnifferServer 9090

# Terminal 2: Start sniffer
sudo ./sniffer en0 127.0.0.1 9090

# Terminal 3: Generate traffic
ping -c 5 8.8.8.8              # ICMP traffic
curl https://example.com       # TCP/HTTPS traffic
dig @8.8.8.8 example.com      # UDP/DNS traffic

# Verify
# - Sniffer should log each packet
# - Server should show client connected
# - GUI should display packets in real-time
```

### Protocol Validation

```bash
# Test ICMP (ping)
ping -c 5 8.8.8.8
# Expected: ICMP packets with echo-request/echo-reply

# Test DNS (UDP)
dig google.com
# Expected: UDP packets on port 53

# Test HTTPS (TCP)
curl https://google.com
# Expected: TCP packets on port 443 (three-way handshake)

# Test HTTP (TCP)
curl http://example.com
# Expected: TCP packets on port 80
```

### Performance Testing

```bash
# Generate high-volume traffic
for i in {1..100}; do curl https://example.com > /dev/null 2>&1 &; done
wait

# Monitor sniffer
sudo ./sniffer en0

# Check performance metrics
# - Packet rate should be stable
# - No dropped packets
# - CPU usage < 5% on modern hardware
```

---

## Configuration Options

### Sniffer Configuration

**Interface Selection**:
```bash
# List available interfaces
ifconfig | grep -E "^[a-z]" | cut -d: -f1

# Common interfaces on macOS
en0    # Ethernet/WiFi main interface
en1    # Secondary interface
lo0    # Loopback interface
```

**Server Connection**:
- **Host**: Server IP address or hostname
- **Port**: Server TCP port (default 9090)
- **Timeout**: Depends on network latency

### Server Configuration

**Port Selection**:
```bash
# Use port number > 1024 to avoid requiring root for server
./build/SnifferServer 8888

# High-numbered port (less conflict)
./build/SnifferServer 59090
```

**Multiple Servers**:
```bash
# Server 1 on port 9090
./build/SnifferServer 9090

# Server 2 on port 9091
./build/SnifferServer 9091
```

### GUI Configuration

**Display Options** (in application settings):
- Timestamp format (ISO 8601, etc.)
- Packet count per page
- Auto-scroll behavior
- Color scheme (dark/light)

**Connection Options**:
- Server host/port
- Reconnection timeout
- Buffer size

---

## Troubleshooting

### Common Issues and Solutions

#### 1. "Permission Denied" on BPF Device

**Symptom**:
```
Error: Failed to open BPF device: Permission denied
```

**Cause**: BPF device access requires root privileges

**Solution**:
```bash
# Run with sudo
sudo ./sniffer en0

# Or adjust device permissions (not recommended)
sudo chmod 644 /dev/bpf*
```

#### 2. "Interface Not Found" or "Not a Network Interface"

**Symptom**:
```
Error: Failed to bind to interface en0: No such device
```

**Cause**: Interface name is incorrect or doesn't exist

**Solution**:
```bash
# List available interfaces
ifconfig | grep -E "^[a-z]" | cut -d: -f1

# Use correct interface name
sudo ./sniffer en0  # not "Ethernet" or "WiFi"
```

#### 3. Server Connection Failed

**Symptom**:
```
Error: Failed to connect to server 127.0.0.1:9090
```

**Cause**: Server not running or incorrect address/port

**Solution**:
```bash
# Verify server is running
ps aux | grep SnifferServer

# Check port is correct
./build/SnifferServer 9090

# Verify hostname/IP resolution
ping 127.0.0.1
ping 192.168.1.100
```

#### 4. GUI Won't Connect to Server

**Symptom**:
- GUI doesn't show "Connected" status
- No packets appear in tables

**Solution**:
1. Verify server is running: `./build/SnifferServer 9090`
2. Check firewall allows port 9090
3. Verify correct host/port in GUI settings
4. Check network connectivity between machines
5. Look at server output for connection errors

#### 5. No Packets Appearing in GUI

**Symptom**:
- Server running, GUI connected, sniffer running
- But GUI shows no packets

**Cause**: Sniffer may not be connected or generating traffic

**Solution**:
```bash
# Verify sniffer is connected
# - Check server output: should show "[Sniffer] Connected from..."

# Verify traffic is being generated
ping 8.8.8.8  # In separate terminal

# Check sniffer is capturing
# - Sniffer should show logs on console or in server output

# Verify GUI is receiving data
# - Server should log "[Server] Forwarding logs..."
```

#### 6. GUI Crash or Display Issues

**Symptom**:
- GUI crashes on startup
- Font rendering issues
- Window won't appear

**Solution**:
```bash
# Rebuild GUI with clean dependencies
cd build
cmake --build . --target clean
cmake ..
make SnifferGUI

# Run with verbose output for debugging
./SnifferGUI --verbose
```

#### 7. Build Errors with Qt

**Symptom**:
```
error: unknown type name 'QWidget'
```

**Cause**: Qt not found or not properly configured

**Solution**:
```bash
# Check Qt installation
brew list qt@6
which qmake

# Reinstall Qt if needed
brew reinstall qt@6

# Rebuild with explicit Qt path
cmake -DCMAKE_PREFIX_PATH=/usr/local/opt/qt@6 ..
```

### Performance Issues

**High CPU Usage**:
- Sniffer on busy network segment
- Slow parsing of malformed packets
- **Solution**: Add packet filtering, use less busy interface

**Memory Growth**:
- GUI buffer not clearing old logs
- Server not cleaning disconnected clients
- **Solution**: Restart GUI/Server, check for memory leaks

**Packet Loss**:
- BPF buffer too small
- Slow packet processing
- **Solution**: Increase buffer size, optimize parsing code

### Network Issues

**Packets not appearing on interface**:
- Interface might be in monitor mode
- Interface might be inactive
- **Solution**: Try different interface, use `ifconfig` to verify

**Connection refused**:
- Server not listening on specified port
- Port already in use
- **Solution**: Kill process using port, use different port number

### Data Corruption

**Garbled packet data**:
- BPF record alignment issue (internal bug)
- Memory corruption during parsing
- **Solution**: Verify with `tcpdump`, restart system if persistent

---

## Next Steps

- See [ARCHITECTURE.md](ARCHITECTURE.md) for system design details
- See [API_REFERENCE.md](API_REFERENCE.md) for code documentation
- See [PROTOCOL.md](PROTOCOL.md) for network protocol specification
- See [BPF_GUIDE.md](BPF_GUIDE.md) for Berkeley Packet Filter details
