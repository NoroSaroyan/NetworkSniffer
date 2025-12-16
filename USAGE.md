# Distributed BPF Sniffer - Usage Guide

This project implements a distributed network packet sniffer with a central TCP server and Qt GUI client.

## Components

### 1. SnifferServer
The central TCP server that receives traffic logs from sniffers and broadcasts them to GUI clients.

**Usage:**
```bash
./SnifferServer <port>
```

**Example:**
```bash
./SnifferServer 9090
```

### 2. NetworkSniffer
The BPF packet sniffer that captures network traffic and sends logs to the server.

**Usage:**
```bash
# Local mode (prints to console)
sudo ./NetworkSniffer <interface>

# Remote mode (sends to server)
sudo ./NetworkSniffer <interface> <server_ip> <server_port>
```

**Examples:**
```bash
# Local mode
sudo ./NetworkSniffer en0

# Remote mode
sudo ./NetworkSniffer en0 127.0.0.1 9090
```

### 3. SnifferGUI
Qt-based graphical interface for monitoring multiple sniffers.

**Usage:**
```bash
./SnifferGUI
```

Then use the GUI to:
1. Enter server host and port
2. Click "Connect"
3. View logs from different sniffers in separate tabs (organized by SSID)

## Protocol

The system uses a custom binary protocol:

**Frame Format:**
```
[Version:1][Type:1][Length:2][Payload:N][Term:1]
```

**Message Types:**
- 0x01: CLIENT_HELLO - Sniffer introduces itself
- 0x02: SERVER_HELLO - Server responds with SSID
- 0x03: TRAFFIC_LOG - Sniffer sends captured packet log
- 0x04: FORWARD_LOG - Server broadcasts to GUI clients
- 0x05: ERROR - Error messages

## Testing the System

### Step 1: Start the Server
```bash
cd build
./SnifferServer 9090
```

### Step 2: Start the GUI Client
```bash
./SnifferGUI
```
In the GUI:
- Host: 127.0.0.1
- Port: 9090
- Click "Connect"

### Step 3: Start One or More Sniffers
```bash
# Terminal 1
sudo ./NetworkSniffer en0 127.0.0.1 9090

# Terminal 2 (optional - different interface)
sudo ./NetworkSniffer en1 127.0.0.1 9090
```

### Step 4: Generate Traffic
Open a web browser or use curl to generate network traffic:
```bash
curl https://example.com
```

You should see the captured packets appear in the GUI, with each sniffer's logs in its own tab.

## Features

- **Multi-Sniffer Support**: Connect multiple sniffers to one server
- **SSID-Based Routing**: Each sniffer gets a unique Session ID (SSID)
- **Real-Time Monitoring**: GUI displays logs as they arrive
- **Protocol Support**: TCP, UDP, ICMP packet parsing
- **Detailed Logs**: Timestamp, protocol, source/dest IPs and ports

## Requirements

- macOS with BPF support (or Linux with libpcap)
- Qt5 or Qt6
- nlohmann/json library
- Root privileges for packet capture

## Architecture

```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│  Sniffer 1  │────────▶│              │────────▶│             │
│  (SSID: 1)  │  TCP    │   Central    │  TCP    │  Qt GUI     │
└─────────────┘         │   Server     │         │  Client     │
                        │              │         │             │
┌─────────────┐         │   (Port      │         │  (Tabs by   │
│  Sniffer 2  │────────▶│    9090)     │────────▶│   SSID)     │
│  (SSID: 2)  │  TCP    │              │  TCP    │             │
└─────────────┘         └──────────────┘         └─────────────┘
```

Each sniffer captures BPF packets, converts them to JSON, and sends them to the server.
The server tracks each sniffer by SSID and broadcasts logs to all connected GUI clients.
GUI clients display logs in separate tabs based on SSID.
