# API Reference - NetworkSniffer Components

Complete API documentation for all NetworkSniffer components, including the sniffer node (BPF capture), server hub, and GUI client.

## Table of Contents

1. [Sniffer Component](#sniffer-component)
2. [PacketParser Component](#packetparser-component)
3. [Main Entry Point](#main-entry-point)
4. [Server Component](#server-component)
5. [GUI Client Component](#gui-client-component)
6. [Protocol Definitions](#protocol-definitions)

---

## Sniffer Component

### Overview

The `Sniffer` class encapsulates all Berkeley Packet Filter (BPF) device interactions for network packet capture on macOS. It provides a high-level, object-oriented interface for low-level BPF system calls, implementing RAII (Resource Acquisition Is Initialization) principles for automatic resource management.

### Location

- **Header**: `src/sniffer/Sniffer.h`
- **Implementation**: `src/sniffer/Sniffer.cpp`

### Core Responsibilities

1. **BPF Device Discovery**: Find and open available BPF devices (`/dev/bpf0`, `/dev/bpf1`, etc.)
2. **Interface Binding**: Attach BPF device to specific network interface (e.g., `en0`)
3. **Real-Time Configuration**: Set immediate mode for live packet capture
4. **Buffer Management**: Allocate and manage packet capture buffers
5. **Packet Reading**: Continuously read packets and forward for parsing
6. **Resource Cleanup**: Automatically release BPF devices on destruction

### Class Interface

```cpp
class Sniffer {
public:
    // Constructor: Initialize BPF device for specified interface
    explicit Sniffer(const std::string& iface);

    // Destructor: Automatically cleanup resources (RAII)
    ~Sniffer();

    // Main packet capture loop (blocking, runs until error or signal)
    void run();

private:
    // Private implementation methods (encapsulate BPF complexity)
    int openBpfDevice();        // Find available BPF device
    void configureInterface();  // Bind to network interface
    void doReadLoop();          // Main packet read loop

    // Member variables (RAII-managed resources)
    int fd_ = -1;                             // BPF device file descriptor
    std::string iface_;                       // Interface name (e.g., "en0")
    std::vector<unsigned char> buffer_;       // Packet buffer (auto-managed)
};
```

### Key Methods

#### Constructor: `Sniffer(const std::string& iface)`

**Parameters**:
- `iface`: Network interface name (e.g., "en0", "en1", "lo0")

**Behavior**:
- Opens available BPF device
- Binds to specified interface
- Configures immediate mode
- Allocates packet buffer
- Throws `std::runtime_error` on failure

**Example**:
```cpp
try {
    Sniffer sniffer("en0");
    sniffer.run();  // Start capturing
} catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << std::endl;
}
```

#### Method: `void run()`

**Purpose**: Start the main packet capture loop

**Behavior**:
- Runs indefinitely until error or signal (SIGINT/SIGTERM)
- Reads BPF buffer in real-time
- Parses each packet via `PacketParser::parseAndPrint()`
- Outputs formatted packet information to stdout

**Design Pattern**: Main event loop - blocking until termination

### BPF System Calls Used

| Call | Purpose | Header |
|------|---------|--------|
| `open("/dev/bpfX")` | Acquire BPF device | `<fcntl.h>` |
| `ioctl(fd, BIOCSETIF)` | Bind to interface | `<net/bpf.h>` |
| `ioctl(fd, BIOCIMMEDIATE)` | Enable immediate mode | `<net/bpf.h>` |
| `ioctl(fd, BIOCGBLEN)` | Get buffer size | `<net/bpf.h>` |
| `read(fd, buffer, size)` | Read packets | `<unistd.h>` |
| `close(fd)` | Close device | `<unistd.h>` |

### Memory Management

**RAII Principles**:
- **Vector Buffer**: Automatically allocated and freed
- **File Descriptor**: Automatically closed in destructor
- **Exception Safety**: Strong guarantee - cleanup on exception

---

## PacketParser Component

### Overview

The `PacketParser` class implements comprehensive network protocol parsing for multiple layers of the TCP/IP stack. It provides defensive, high-performance analysis of network packets with bounds checking to prevent buffer overruns.

### Location

- **Header**: `src/sniffer/PacketParser.h`
- **Implementation**: `src/sniffer/PacketParser.cpp`

### Design Approach

**Static Methods Only**: `PacketParser` uses exclusively static methods
- No instantiation overhead
- Inherent thread safety
- Stateless packet analysis

**Layered Protocol Analysis**: Follows OSI model progression
```
Ethernet (Layer 2)
    ↓ [EtherType check]
IPv4/IPv6 (Layer 3)
    ↓ [Protocol field]
TCP/UDP/ICMP (Layer 4)
    ↓
Output: Formatted packet summary
```

### Class Interface

```cpp
class PacketParser {
public:
    // Public entry point: Parse packet and print summary
    static void parseAndPrint(
        const unsigned char* packet,  // Raw packet bytes
        size_t caplen,                // Captured length
        const struct timeval& timestamp  // BPF timestamp
    );

private:
    // Private layered parsing methods
    static void parseEthernet(const unsigned char* packet, size_t caplen,
                            const struct timeval& timestamp);

    static void parseIPv4(const unsigned char* packet, size_t offset, size_t caplen,
                         const struct timeval& timestamp);

    static void parseTCP(const unsigned char* packet, size_t offset, size_t caplen,
                        const char* src_ip, const char* dst_ip,
                        const struct timeval& timestamp);

    static void parseUDP(const unsigned char* packet, size_t offset, size_t caplen,
                        const char* src_ip, const char* dst_ip,
                        const struct timeval& timestamp);

    static void formatTimestamp(const struct timeval& timestamp,
                               char* buffer, size_t bufsize);
};
```

### Protocol Support

#### Layer 2 - Ethernet
- **Header**: 14 bytes minimum
- **Fields Parsed**: Destination MAC, Source MAC, EtherType
- **Supported Types**: IPv4 (0x0800), IPv6 (0x86DD), ARP (0x0806)

#### Layer 3 - IPv4
- **Header**: 20-60 bytes (variable with options)
- **Fields Parsed**: Source IP, Destination IP, TTL, Protocol
- **Protocol Detection**: TCP (6), UDP (17), ICMP (1)

#### Layer 4 - TCP
- **Header**: 20-60 bytes (variable with options)
- **Fields Parsed**: Source Port, Destination Port, Flags, Sequence/Ack Numbers

#### Layer 4 - UDP
- **Header**: 8 bytes fixed
- **Fields Parsed**: Source Port, Destination Port, Length

#### Layer 4 - ICMP
- **Header**: 8 bytes minimum
- **Detection**: IPv4 protocol field = 1

### Output Format

```
YYYY-MM-DD HH:MM:SS.UUUUUU srcIP:srcPort -> dstIP:dstPort PROTO len=N
```

**Example**:
```
2024-12-25 14:32:15.123456 192.168.1.10:54321 -> 8.8.8.8:443 TCP len=60
2024-12-25 14:32:16.234567 192.168.1.10:53 -> 8.8.8.8:53 UDP len=56
```

### Key Features

1. **Defensive Parsing**: Every memory access validated with bounds checking
2. **Zero-Copy**: Direct pointer arithmetic, minimal allocations
3. **Extensible**: Easy to add new protocol handlers
4. **Timestamp Precision**: Microsecond accuracy from BPF headers
5. **IP Address Formatting**: Uses `inet_ntop()` for readable addresses

---

## Main Entry Point

### Overview

The `main.cpp` file serves as the entry point for the NetworkSniffer application. It implements the command-line interface, signal handling, and application lifecycle management.

### Location

- **File**: `src/main.cpp`

### Application Flow

1. **Command-line Validation**: Verify correct arguments provided
2. **Signal Handler Setup**: Register SIGINT/SIGTERM handlers
3. **Sniffer Initialization**: Create `Sniffer` instance
4. **Packet Capture Loop**: Run `sniffer.run()` (blocks until signal)
5. **Graceful Shutdown**: Clean termination on Ctrl+C

### Usage

```bash
sudo ./sniffer <interface>
sudo ./sniffer en0          # Capture on en0 interface
sudo ./sniffer en1          # Capture on en1 interface
sudo ./sniffer lo0          # Capture on loopback
```

### Command-Line Interface

**Arguments**:
- `<interface>`: Network interface name (required)

**Error Handling**:
- Exit code 0: Successful execution
- Exit code 1: Argument validation failed
- Exit code 2: Sniffer exception caught

### Signal Handling

**Handled Signals**:
- **SIGINT (2)**: Ctrl+C - user-initiated shutdown
- **SIGTERM (15)**: System shutdown - graceful termination

**Behavior**:
- Prints termination message
- Exits immediately with status 0
- All resources cleaned up automatically (RAII)

### Key Components

```cpp
// Global signal handler flag
static bool running = true;

// Signal handler function
void signalHandler(int signum) {
    std::cout << "\nReceived signal " << signum << ", stopping..." << std::endl;
    running = false;
    exit(0);
}

// Main execution
int main(int argc, char* argv[]) {
    // Validate arguments
    // Setup signal handlers
    // Create Sniffer instance
    // Run packet capture
    // Handle exceptions
}
```

---

## Server Component

### Overview

The Central TCP Server aggregates logs from multiple sniffer nodes and broadcasts them to all connected GUI clients.

### Location

- **File**: `src/server/server.cpp`

### Key Responsibilities

- Listen on configurable TCP port (default 9090)
- Accept connections from sniffers and GUI clients
- Assign Session IDs (SSID) to each sniffer
- Route TRAFFIC_LOG messages to GUI clients
- Maintain client registry and connection state

### Network Protocol

Uses custom binary TCP protocol defined in `PROTOCOL.md`:
- Frame format: `[Version:1][Type:1][Length:2][Payload:N][Term:1]`
- Message types: CLIENT_HELLO, SERVER_HELLO, TRAFFIC_LOG, FORWARD_LOG, ERROR

### Design Pattern

**Thread-per-Client Architecture**:
- Each client connection handled in separate thread
- Thread-safe client registry with locks
- Concurrent handling of multiple sniffers and GUI clients

---

## GUI Client Component

### Overview

The Qt-based GUI client connects to the central server and displays real-time network traffic analysis.

### Location

- **Directory**: `src/client/`
- **Key Classes**: `MainWindow`, `SnifferClient`, `StatsWidget`

### Framework

- **Qt Version**: Qt 5.15+ or Qt 6.x
- **Language**: C++ with Qt MOC (Meta Object Compiler)
- **Platform**: Cross-platform (macOS, Linux, Windows)

### Key Responsibilities

- Connect to server via TCP
- Parse incoming FORWARD_LOG messages
- Display traffic in organized table views (tabs by SSID)
- Calculate and display statistics
- Handle server disconnection/reconnection

### Architecture

**MainWindow** - Top-level UI container
- Manages connection settings
- Creates tab widgets for each sniffer
- Coordinates statistics updates

**SnifferClient** - TCP communication layer
- Connects to server
- Parses binary protocol frames
- Emits signals for UI updates

**StatsWidget** - Traffic statistics display
- Shows real-time metrics
- Updates traffic counts
- Displays protocol breakdowns

---

## Protocol Definitions

### File Location

- **Header**: `src/Protocol.h`

### Distributed System Protocol

The protocol definition header contains:
- Message type constants
- Frame structure definitions
- Client type identifiers
- Session ID management

### Binary Frame Format

```
[Version:1 byte][Type:1 byte][Length:2 bytes][Payload:N bytes][Terminator:1 byte]
```

### Message Types

| Type | Value | Direction | Purpose |
|------|-------|-----------|---------|
| CLIENT_HELLO | 0x01 | Client → Server | Client introduction |
| SERVER_HELLO | 0x02 | Server → Client | SSID assignment |
| TRAFFIC_LOG | 0x03 | Sniffer → Server | Packet log data |
| FORWARD_LOG | 0x04 | Server → GUI | Log broadcast |
| ERROR | 0x05 | Server → Client | Error notification |

See `docs/PROTOCOL.md` for detailed specification.

---

## Design Patterns Used

### RAII (Resource Acquisition Is Initialization)
- Resources acquired in constructor
- Automatically released in destructor
- Exception-safe guarantee

### Thread-per-Client
- Each client connection in separate thread
- Allows concurrent handling
- Scalable to multiple sniffers

### Static Utility Classes
- PacketParser uses only static methods
- No instantiation overhead
- Inherent thread safety

### Producer-Consumer
- Sniffers produce traffic logs
- Server routes to consumers (GUI clients)
- Decouples traffic capture from visualization

---

## Building and Linking

### Sniffer Binary (main.cpp + Sniffer + PacketParser)

```bash
clang++ -std=c++17 -Wall -Wextra -O2 \
    src/main.cpp \
    src/sniffer/Sniffer.cpp \
    src/sniffer/PacketParser.cpp \
    -o sniffer
```

### Server Binary

```bash
clang++ -std=c++17 -Wall -Wextra -O2 \
    src/server/server.cpp \
    src/logging/Logger.cpp \
    -o SnifferServer
```

### GUI Client (requires Qt)

```bash
# See CMakeLists.txt for Qt build configuration
```

---

## Error Handling Strategy

### Sniffer Component

**Exception Safety**: Strong guarantee
- All system call failures throw `std::runtime_error`
- Resources cleaned up automatically
- Constructor cleanup on failure

### Packet Parser

**Defensive Programming**:
- Every buffer access bounds-checked
- Invalid packets safely ignored
- No exceptions thrown

### Server Component

**Robust Error Handling**:
- Client disconnection handled gracefully
- Invalid messages logged and discarded
- Server continues operation

---

## Performance Characteristics

| Metric | Value | Notes |
|--------|-------|-------|
| Packet Rate | 1000+ pps | Tested with real traffic |
| CPU Usage | <5% | Single core on modern hardware |
| Memory Overhead | 4-64KB | Fixed buffer allocation |
| Timestamp Precision | <1μs | Microsecond accuracy |
| Parsing Latency | <1ms | Per-packet processing |

---

## Future Enhancement Points

1. **IPv6 Support**: Extend `PacketParser` to handle IPv6 headers
2. **Protocol Plugins**: Add modular protocol handler system
3. **BPF Filters**: Kernel-level packet filtering for performance
4. **PCAP Export**: Save captures in standard format
5. **Advanced Statistics**: Flow tracking, bandwidth analysis
6. **Performance Optimizations**: Lock-free queues, memory pooling

For detailed technical information, refer to:
- `docs/ARCHITECTURE.md` - System design
- `docs/BPF_GUIDE.md` - BPF technical reference
- `docs/PROTOCOL.md` - Network communication protocol
