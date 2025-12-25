# Network Communication Protocol

## Overview

The distributed network sniffer uses a **binary frame protocol** for all communication between three types of
components:

- **Sniffer Nodes**: Remote packet capture clients (BPF devices)
- **Central Server**: Hub for routing traffic logs
- **GUI Client**: Qt application for real-time monitoring

All communication happens over **TCP sockets** using a standardized binary frame format.

---

## Binary Frame Format

Every message exchanged between components uses this envelope:

```
[Version:1][Type:1][Length:2][Payload:N][Terminator:1]
```

| Field          | Size    | Description                            |
|----------------|---------|----------------------------------------|
| **Version**    | 1 byte  | Protocol version (0x01)                |
| **Type**       | 1 byte  | Message type (see Message Types below) |
| **Length**     | 2 bytes | Payload size in bytes (big-endian)     |
| **Payload**    | N bytes | JSON-encoded message data (UTF-8)      |
| **Terminator** | 1 byte  | Frame end marker (0x0A = line feed)    |

### Example Frame

Sending `{"hostname":"MacBook","interface":"en0"}` as CLIENT_HELLO:

```
Raw Bytes (hex):
01 01 00 37 7B 22 68 6F 73 74 6E 61 6D 65 22 3A ... 7D 0A

Breakdown:
01              - Version (0x01)
01              - Type: CLIENT_HELLO
00 37           - Length: 55 bytes (big-endian)
7B 22 68 6F ... - Payload: {"hostname":"MacBook","interface":"en0"}
0A              - Terminator
```

---

## Message Types

| Type             | Value | Direction        | Purpose                  |
|------------------|-------|------------------|--------------------------|
| **CLIENT_HELLO** | 0x01  | Client → Server  | Client introduces itself |
| **SERVER_HELLO** | 0x02  | Server → Client  | Server assigns SSID      |
| **TRAFFIC_LOG**  | 0x03  | Sniffer → Server | Packet data from sniffer |
| **FORWARD_LOG**  | 0x04  | Server → GUI     | Forwarded logs to GUI    |
| **ERROR**        | 0x05  | Server → Client  | Error notification       |

---

## Sniffer → Server Communication

### Registration Handshake

```
┌─────────────────────────────────────────────────────────────────┐
│ SNIFFER NODE (e.g., ./NetworkSniffer en0 127.0.0.1 9090)        │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ TCP Connect to 127.0.0.1:9090
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ CENTRAL SERVER (./SnifferServer 9090)                           │
│ Listening on :9090, new connection accepted                     │
│ Creates new thread for this client                              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ [1] CLIENT_HELLO Frame
                              ↓
Payload: {
  "hostname": "MacBook-Pro-3",
  "interface": "en0"           ← Identifies as SNIFFER
}

Server reads frame, detects "interface" field → is_sniffer = true
Assigns SSID = 1
Stores: clients[0] = {fd: 5, remote_ip: "127.0.0.1", ssid: 1, is_sniffer: true}

                              │ [2] SERVER_HELLO Frame
                              ↓
Payload: {
  "ssid": 1,
  "ip": "127.0.0.1",
  "registered": true
}

Sniffer receives SERVER_HELLO, extracts SSID = 1
                              │
                              │ [3+] TRAFFIC_LOG Frames (continuous)
                              ↓
Payload: {
  "timestamp": "09:42:15.123456",
  "protocol": "TCP",
  "src": "192.168.1.100",
  "dst": "8.8.8.8",
  "src_port": 54321,
  "dst_port": 443,
  "length": 1234,
  "ssid": 1
}
```

### Key Points

1. **Sniffer identifies itself** by including `"interface"` field in CLIENT_HELLO
2. **Server assigns unique SSID** (Sniffer Session ID) for log routing
3. **Continuous streaming** of TRAFFIC_LOG frames for each captured packet
4. **SSID included in logs** so server knows which sniffer sent them

---

## Server → GUI Communication

### Registration Handshake

```
┌──────────────────────────────────────────────────────────────┐
│ GUI CLIENT (SnifferGUI connects to 127.0.0.1:9090)           │
└──────────────────────────────────────────────────────────────┘
                              │
                              │ TCP Connect to 127.0.0.1:9090
                              ↓
┌──────────────────────────────────────────────────────────────┐
│ CENTRAL SERVER                                               │
│ Listening on :9090, new connection accepted                 │
│ Creates new thread for this client                          │
└──────────────────────────────────────────────────────────────┘
                              │
                              │ [1] CLIENT_HELLO Frame
                              ↓
Payload: {
  "type": "gui",              ← Identifies as GUI
  "hostname": "Qt GUI Client"
}

Server reads frame, detects "type":"gui" → is_sniffer = false
Assigns SSID = 2 (separate from sniffers)
Stores: clients[1] = {fd: 6, remote_ip: "127.0.0.1", ssid: 2, is_sniffer: false}

                              │ [2] SERVER_HELLO Frame
                              ↓
Payload: {
  "ssid": 2,
  "ip": "127.0.0.1",
  "registered": true
}

GUI receives SERVER_HELLO, now knows its SSID = 2
                              │
                              │ [3+] FORWARD_LOG Frames (continuous)
                              ↓
Payload: {
  "ssid": 1,                  ← From Sniffer SSID 1
  "log": {
    "timestamp": "09:42:15.123456",
    "protocol": "TCP",
    "src": "192.168.1.100",
    "dst": "8.8.8.8",
    ...
  }
}

GUI receives FORWARD_LOG
Parses JSON, extracts "ssid": 1
Displays in tab labeled "Sniffer #1"
Updates statistics for that sniffer
```

### Key Points

1. **GUI identifies itself** by including `"type":"gui"` field in CLIENT_HELLO
2. **Server assigns separate SSID** to GUI (different from sniffiers)
3. **Continuous receiving** of FORWARD_LOG frames with original SSID
4. **SSID in payload** tells GUI which sniffer's data it is (tab organization)

---

## Complete System Flow

```
╔══════════════════════════════════════════════════════════════════════╗
║                    COMPLETE SYSTEM OVERVIEW                          ║
╚══════════════════════════════════════════════════════════════════════╝

Sniffer #1              Central Server           GUI Client #1
(SSID=1)                                         (SSID=2)
   │                       │                        │
   │ [1] CLIENT_HELLO      │                        │
   ├──────────────────────>│                        │
   │                       │ Accept connection      │
   │ [2] SERVER_HELLO      │ Spawn thread           │
   │<──────────────────────┤ SSID = 1               │
   │                       │                        │
   │ [3] TRAFFIC_LOG       │                        │
   │ ssid: 1               │                        │
   ├──────────────────────>│                        │
   │                       │                        │   TCP Connect
   │                       │                        │───────────────>
   │                       │ Accept connection      │
   │                       │ Spawn thread           │
   │                       │ SSID = 2               │
   │                       │                    [1] CLIENT_HELLO
   │                       │<───────────────────────┤
   │                       │                        │
   │                       │                    [2] SERVER_HELLO
   │ [3] TRAFFIC_LOG       │───────────────────────>│
   │ ssid: 1               │                        │
   ├──────────────────────>│                        │
   │                       │                        │ Routing logic:
   │                       │ If TYPE_TRAFFIC_LOG:   │
   │                       │   Extract SSID = 1     │
   │                       │   For each GUI client:  │
   │                       │   Send FORWARD_LOG     │
   │                       │                        │
   │                       │                    [3] FORWARD_LOG
   │                       │                    ssid: 1, log: {...}
   │                       │───────────────────────>│
   │                       │                        │ Parse and display
   │                       │                        │ in "Sniffer #1" tab
   │                       │                        │ Update stats

         (Continuous streaming of packets)
```

---

## Protocol State Machine

### Sniffer Node

```
START
  │
  ├─> Connect to server (TCP)
  │
  ├─> Send CLIENT_HELLO {"hostname":"...", "interface":"eth0"}
  │
  └─> Wait for SERVER_HELLO
      │
      ├─> Parse SERVER_HELLO, extract SSID
      │
      ├─> Begin packet capture loop
      │     ├─> Read packet from BPF device
      │     ├─> Parse packet (Ethernet, IPv4, TCP/UDP/ICMP)
      │     ├─> Create JSON log
      │     ├─> Send TRAFFIC_LOG {"timestamp":"...", "protocol":"TCP", ..., "ssid": X}
      │     └─> [Loop back to read next packet]
      │
      └─> If error: Close connection, retry
```

### Central Server

```
START (listen on port 9090)
  │
  ├─> Accept TCP connection
  │
  ├─> Spawn new thread for this client
  │
  ├─> Thread reads CLIENT_HELLO
  │     │
  │     ├─> If has "interface" field: is_sniffer = true
  │     │
  │     └─> If has "type":"gui": is_sniffer = false
  │
  ├─> Assign unique SSID, send SERVER_HELLO
  │
  ├─> If is_sniffer:
  │     ├─> Read TRAFFIC_LOG frames
  │     ├─> For each TRAFFIC_LOG:
  │     │     ├─> Lock mutex
  │     │     ├─> For each GUI client:
  │     │     │     └─> Send FORWARD_LOG with same SSID
  │     │     └─> Unlock mutex
  │     └─> [Loop back to read next frame]
  │
  ├─> Else if is_GUI:
  │     ├─> No reading (GUI only receives)
  │     ├─> Wait for FORWARD_LOG to arrive from sniffer
  │     ├─> Send it automatically (socket write buffer)
  │     └─> [Loop back to wait]
  │
  └─> If connection closes: Remove from clients list
```

### GUI Client

```
START
  │
  ├─> Connect to server (TCP)
  │
  ├─> Send CLIENT_HELLO {"type":"gui", "hostname":"..."}
  │
  ├─> Wait for SERVER_HELLO
  │     │
  │     └─> Parse and extract SSID
  │
  ├─> Begin reading frames loop
  │     ├─> Read bytes from socket
  │     ├─> Buffer accumulation (partial frames)
  │     ├─> Parse complete frames
  │     │     │
  │     │     ├─> If TYPE_SERVER_HELLO: Already handled
  │     │     │
  │     │     ├─> If TYPE_FORWARD_LOG:
  │     │     │     ├─> Parse JSON payload
  │     │     │     ├─> Extract "ssid" and "log"
  │     │     │     ├─> Emit forwardLogReceived(ssid, log) signal
  │     │     │     ├─> MainWindow receives signal
  │     │     │     ├─> Update table with packet data
  │     │     │     ├─> Update statistics for sniffer #N
  │     │     │     └─> Update UI (GUI thread via Qt signal/slot)
  │     │     │
  │     │     └─> If TYPE_ERROR: Display error dialog
  │     │
  │     └─> [Loop back to read next frame]
  │
  └─> If connection closes: Show connection lost message
```

---

## Concurrency & Thread Safety

### Server Thread Model

```
Main Thread (listening)
  │
  ├─> accept() on port 9090
  │     │
  │     └─> New connection → spawn new thread
  │           │
  │           ├─ Thread #1: Sniffer client
  │           │   ├─ Read CLIENT_HELLO (lock mutex)
  │           │   ├─ Send SERVER_HELLO (lock mutex)
  │           │   └─ Continuous: read TRAFFIC_LOG → broadcast to GUIs (lock mutex)
  │           │
  │           ├─ Thread #2: Sniffer client
  │           │   ├─ Read CLIENT_HELLO (lock mutex)
  │           │   ├─ Send SERVER_HELLO (lock mutex)
  │           │   └─ Continuous: read TRAFFIC_LOG → broadcast to GUIs (lock mutex)
  │           │
  │           └─ Thread #3: GUI client
  │               ├─ Read CLIENT_HELLO (lock mutex)
  │               ├─ Send SERVER_HELLO (lock mutex)
  │               └─ Wait for FORWARD_LOG (no reading, data pushed by sniffer threads)
  │
  └─> [Loop back to accept next connection]
```

### Mutex Protection

**Critical sections protected by `clients_mutex`:**

1. **Client registration** (add to clients list)
   ```cpp
   {
       std::lock_guard<std::mutex> lock(clients_mutex);
       clients.push_back({fd, remote_ip, ssid, is_sniffer});
   } // Auto unlock
   ```

2. **Log broadcasting** (forward TRAFFIC_LOG to all GUIs)
   ```cpp
   {
       std::lock_guard<std::mutex> lock(clients_mutex);
       for (const auto& gui_client : clients) {
           if (!gui_client.is_sniffer) {
               sendFrame(gui_client.fd, FORWARD_LOG, json_payload);
           }
       }
   }
   ```

---

## Error Handling

### Frame Validation

Each frame is validated before processing:

1. **Version check**: Must be 0x01
2. **Length check**: Must be ≤ 1024 bytes
3. **Terminator check**: Must be 0x0A
4. **JSON parsing**: Must be valid JSON in payload

If validation fails:

- Frame is discarded
- Connection may be closed for protocol violations
- Error logged to stderr

### Connection Failures

**Sniffer reconnection logic:**

```
Try to connect to server
  ├─> If fails: Wait 1 second, retry
  ├─> If fails again: Wait 2 seconds, retry
  └─> Keep retrying indefinitely
```

**GUI connection handling:**

```
Try to connect to server
  ├─> If succeeds: Display logs normally
  ├─> If fails: Show "Connection failed" in UI
  └─> User can retry by clicking "Connect" button
```

---

## Latency & Performance

### Message Flow Timing

```
T0: Sniffer captures packet from BPF device
T0+1ms: Sniffer parses packet
T0+2ms: Sniffer serializes to JSON
T0+3ms: Sniffer creates binary frame
T0+4ms: Write frame to socket (TCP buffer)
T0+5ms: Server receives frame on listening thread
T0+6ms: Server parses binary frame
T0+7ms: Server acquires mutex
T0+8ms: Server sends FORWARD_LOG to GUI
T0+9ms: GUI receives frame from socket
T0+10ms: GUI parses binary frame
T0+11ms: GUI emits Qt signal
T0+12ms: MainWindow slot updates table widget
T0+13ms: Qt renders updated table row

Total latency: ~13ms from packet capture to GUI display
```

### Throughput

- **Per packet**:
    - Sniffer creates 1 TRAFFIC_LOG frame (~200 bytes)
    - Server forwards to N GUI clients (N * 200 bytes)

- **Example**: 10,000 packets/second with 2 sniffers, 3 GUIs
    - 20,000 TRAFFIC_LOG frames/second from sniffers
    - 20,000 × 3 = 60,000 FORWARD_LOG frames/second to GUIs
    - ≈ 12 MB/second network traffic (rough estimate)

---

## Protocol Debugging

### Common Issues

**GUI not receiving logs:**

- Check: GUI sent CLIENT_HELLO with `"type":"gui"`?
- Check: Server assigned SSID in SERVER_HELLO?
- Check: Sniffer actually sending TRAFFIC_LOG frames?
- Check: Server broadcasting to all connected GUIs?

**Sniffer not connecting:**

- Check: Server listening on correct port?
- Check: Firewall not blocking connections?
- Check: Network interface exists?

**Corrupted frames:**

- Check: Version byte is 0x01?
- Check: Length field matches actual payload size?
- Check: Terminator byte is 0x0A?
- Check: JSON payload is valid UTF-8?

### Debug Output

Enable debug logs by checking stderr output:

```bash
./SnifferServer 9090 2>&1 | tee server.log
./SnifferGUI 2>&1 | tee gui.log
./NetworkSniffer en0 127.0.0.1 9090 2>&1 | tee sniffer.log
```

Look for:

- `[DEBUG] Frame read successfully`
- `[GUI] Connected to server`
- `[SNIFFER] Registered with SSID: X`
- Connection/disconnection events

---

## Protocol Specification Summary

| Aspect                | Details                                                   |
|-----------------------|-----------------------------------------------------------|
| **Transport**         | TCP/IP over localhost or network                          |
| **Frame Format**      | Binary envelope + JSON payload                            |
| **Encoding**          | UTF-8 for JSON, uint8_t for binary header                 |
| **Payload Size**      | Max 1024 bytes                                            |
| **Session ID (SSID)** | Assigned per client, unique per connection                |
| **Routing**           | Server maintains client list, broadcasts logs by SSID     |
| **Concurrency**       | Multi-threaded, mutex-protected critical sections         |
| **Reliability**       | TCP handles retransmission, frame validation at app layer |
| **Latency**           | ~13ms from packet capture to GUI display                  |

---


