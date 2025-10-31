# Berkeley Packet Filter (BPF) Integration Guide

## Complete System Call Documentation and BPF Interface Reference

This document provides comprehensive documentation of the Berkeley Packet Filter integration, system calls used, and kernel interface details for the network sniffer implementation.

## Table of Contents

1. [BPF Overview and History](#bpf-overview-and-history)
2. [System Call Reference](#system-call-reference)
3. [BPF Device Interface](#bpf-device-interface)
4. [ioctl Commands Reference](#ioctl-commands-reference)
5. [Data Structures](#data-structures)
6. [Error Handling](#error-handling)
7. [Performance Considerations](#performance-considerations)
8. [Debugging and Troubleshooting](#debugging-and-troubleshooting)

---

## BPF Overview and History

### What is Berkeley Packet Filter?

Berkeley Packet Filter (BPF) is a technology that provides raw access to network packets at the data link layer. Originally developed at Lawrence Berkeley Laboratory, BPF allows user-space programs to capture and examine network traffic with minimal overhead.

### Key Characteristics

- **Kernel-Level Filtering**: Packets are filtered in kernel space for efficiency
- **Zero-Copy Access**: Direct access to kernel buffers when possible
- **Raw Packet Access**: Complete link-layer frames including all headers
- **High Performance**: Optimized for minimal CPU and memory overhead
- **Secure**: Requires privileged access to prevent network monitoring abuse

### BPF vs. Other Packet Capture Methods

| Feature | BPF | Raw Sockets | AF_PACKET (Linux) |
|---------|-----|-------------|-------------------|
| Platform | BSD/macOS | Universal | Linux-specific |
| Performance | High | Medium | High |
| Kernel Support | Native | Universal | Native |
| Filtering | Kernel-level | User-space | Kernel-level |
| Overhead | Low | Medium | Low |

---

## System Call Reference

### Core System Calls Used

Our implementation uses the following POSIX system calls:

#### 1. open(2) - BPF Device Access

```c
#include <fcntl.h>

int open(const char *pathname, int flags);
```

**Usage in our implementation:**
```cpp
int fd = open("/dev/bpf0", O_RDWR);
```

**Parameters:**
- `pathname`: BPF device path (`/dev/bpf0`, `/dev/bpf1`, etc.)
- `flags`: `O_RDWR` for read/write access

**Return Value:**
- Success: File descriptor (positive integer)
- Failure: -1 (errno set to indicate error)

**Common Error Codes:**
- `EACCES`: Permission denied (need root privileges)
- `EBUSY`: Device already in use by another process
- `ENOENT`: Device file doesn't exist

#### 2. ioctl(2) - Device Configuration

```c
#include <sys/ioctl.h>

int ioctl(int fd, unsigned long request, ...);
```

**Usage in our implementation:**
```cpp
// Bind to network interface
struct ifreq ifr;
strcpy(ifr.ifr_name, "en0");
ioctl(fd, BIOCSETIF, &ifr);

// Enable immediate mode
u_int enable = 1;
ioctl(fd, BIOCIMMEDIATE, &enable);

// Get buffer size
u_int bufsize;
ioctl(fd, BIOCGBLEN, &bufsize);
```

**Parameters:**
- `fd`: BPF device file descriptor
- `request`: BPF-specific command (see ioctl reference below)
- `...`: Command-specific argument (varies by request)

#### 3. read(2) - Packet Data Retrieval

```c
#include <unistd.h>

ssize_t read(int fd, void *buf, size_t count);
```

**Usage in our implementation:**
```cpp
ssize_t bytes_read = read(fd, buffer_.data(), buffer_.size());
```

**Parameters:**
- `fd`: BPF device file descriptor
- `buf`: Buffer to store packet data
- `count`: Maximum bytes to read

**Return Value:**
- Success: Number of bytes read
- Failure: -1 (errno set)
- EOF: 0 (shouldn't occur with BPF devices)

#### 4. close(2) - Resource Cleanup

```c
#include <unistd.h>

int close(int fd);
```

**Usage in our implementation:**
```cpp
close(fd_);  // Release BPF device
```

---

## BPF Device Interface

### Device File Organization

```
/dev/bpf0    ← First BPF device
/dev/bpf1    ← Second BPF device
/dev/bpf2    ← Third BPF device
...
/dev/bpfN    ← Nth BPF device
```

**Device Characteristics:**
- **Exclusive Access**: Each device can only be opened by one process
- **Character Devices**: Stream-oriented, not block-oriented
- **Root Required**: Typically require root privileges to access
- **Dynamic Creation**: Some systems create devices on demand

### Device Discovery Algorithm

```cpp
int Sniffer::openBpfDevice() {
    // Try devices in sequence until one is available
    for (int i = 0; i < 100; ++i) {
        std::string device = "/dev/bpf" + std::to_string(i);
        int fd = open(device.c_str(), O_RDWR);
        if (fd != -1) {
            return fd;  // Found available device
        }
        // Continue to next device if this one is busy
    }
    throw std::runtime_error("No BPF devices available");
}
```

### Device State Management

```
State Diagram:

[Closed] ─open()─→ [Open] ─ioctl(BIOCSETIF)─→ [Bound] ─read()─→ [Active]
   ↑                  │                          │               │
   └─────close()───────┴─────────close()─────────┴──close()──────┘
```

---

## ioctl Commands Reference

### Interface Configuration Commands

#### BIOCSETIF - Bind to Network Interface

```c
#include <net/if.h>

struct ifreq ifr;
memset(&ifr, 0, sizeof(ifr));
strncpy(ifr.ifr_name, "en0", IFNAMSIZ-1);
ioctl(fd, BIOCSETIF, &ifr);
```

**Purpose**: Associates the BPF device with a specific network interface

**Parameters**:
- `ifr.ifr_name`: Interface name (e.g., "en0", "en1", "wlan0")

**Error Conditions**:
- `ENXIO`: Interface doesn't exist
- `ENETDOWN`: Interface is down
- `EBUSY`: Interface already bound to another BPF device

#### BIOCGDLT - Get Data Link Type

```c
u_int dlt;
ioctl(fd, BIOCGDLT, &dlt);
```

**Purpose**: Retrieves the data link layer type for the bound interface

**Common DLT Values**:
- `DLT_EN10MB` (1): Ethernet
- `DLT_NULL` (0): Loopback interface  
- `DLT_IEEE802_11` (105): 802.11 wireless

### Buffer Management Commands

#### BIOCGBLEN - Get Buffer Length

```c
u_int bufsize;
ioctl(fd, BIOCGBLEN, &bufsize);
```

**Purpose**: Gets the kernel's recommended buffer size for optimal performance

**Usage**: Use this size to allocate your read buffer

**Typical Values**: 4KB to 64KB depending on system

#### BIOCSBLEN - Set Buffer Length

```c
u_int bufsize = 32768;  // 32KB
ioctl(fd, BIOCSBLEN, &bufsize);
```

**Purpose**: Sets a custom buffer size (must be called before BIOCSETIF)

**Constraints**: Must be power of 2, within system limits

### Capture Mode Commands

#### BIOCIMMEDIATE - Set Immediate Mode

```c
u_int enable = 1;
ioctl(fd, BIOCIMMEDIATE, &enable);
```

**Purpose**: Controls packet delivery timing
- `enable = 1`: Deliver packets immediately as they arrive
- `enable = 0`: Buffer packets for efficiency (default)

**Use Case**: Real-time monitoring requires immediate mode

#### BIOCPROMISC - Set Promiscuous Mode

```c
ioctl(fd, BIOCPROMISC, NULL);
```

**Purpose**: Enables promiscuous mode to capture all packets on the network segment

**Security Note**: Allows capture of packets not destined for this machine

**Ethical Consideration**: Only use on networks you own or have permission to monitor

### Filtering Commands

#### BIOCSETF - Set BPF Program

```c
struct bpf_program program;
// ... compile BPF bytecode ...
ioctl(fd, BIOCSETF, &program);
```

**Purpose**: Installs a BPF filter program for kernel-level packet filtering

**Advanced Feature**: Not used in our basic implementation

### Statistics Commands

#### BIOCGSTATS - Get Statistics

```c
struct bpf_stat stats;
ioctl(fd, BIOCGSTATS, &stats);
printf("Received: %u, Dropped: %u\n", stats.bs_recv, stats.bs_drop);
```

**Purpose**: Retrieves packet capture statistics

**Fields**:
- `bs_recv`: Packets received by filter
- `bs_drop`: Packets dropped due to buffer overflow

---

## Data Structures

### BPF Header Structure

```c
struct bpf_hdr {
    struct timeval32 bh_tstamp;  // Timestamp
    uint32_t bh_caplen;          // Captured length
    uint32_t bh_datalen;         // Original packet length
    uint16_t bh_hdrlen;          // BPF header length
};
```

**Field Descriptions**:
- `bh_tstamp`: High-precision timestamp when packet was captured
- `bh_caplen`: Number of bytes captured (may be less than original)
- `bh_datalen`: Original packet size on wire
- `bh_hdrlen`: Size of this BPF header (allows for future extensions)

### Timestamp Handling

```cpp
// Convert BPF timestamp to standard timeval
struct timeval tv;
tv.tv_sec = bh->bh_tstamp.tv_sec;
tv.tv_usec = bh->bh_tstamp.tv_usec;
```

**Precision**: Microsecond accuracy for precise timing analysis

### Interface Request Structure

```c
struct ifreq {
    char ifr_name[IFNAMSIZ];    // Interface name
    union {
        struct sockaddr ifr_addr;
        struct sockaddr ifr_dstaddr;
        struct sockaddr ifr_broadaddr;
        struct sockaddr ifr_netmask;
        struct sockaddr ifr_hwaddr;
        short ifr_flags;
        int ifr_ifindex;
        int ifr_metric;
        int ifr_mtu;
        // ... other fields
    };
};
```

**Usage**: Primarily use `ifr_name` for interface binding

---

## Error Handling

### System Call Error Categories

#### 1. Permission Errors
```cpp
if (open("/dev/bpf0", O_RDWR) == -1) {
    if (errno == EACCES) {
        throw std::runtime_error("Root privileges required");
    }
}
```

#### 2. Resource Availability Errors
```cpp
if (errno == EBUSY) {
    // BPF device in use - try next device
    continue;
}
```

#### 3. Configuration Errors
```cpp
if (ioctl(fd, BIOCSETIF, &ifr) == -1) {
    if (errno == ENXIO) {
        throw std::runtime_error("Interface not found: " + interface_name);
    }
}
```

### Error Recovery Strategies

#### Transient Errors
```cpp
// Network read errors are often temporary
ssize_t result = read(fd, buffer, size);
if (result == -1) {
    if (errno == EINTR) {
        continue;  // Interrupted by signal - retry
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        continue;  // No data available - retry
    }
    // Other errors may be fatal
    throw std::runtime_error("Read failed");
}
```

#### Fatal Errors
```cpp
// Some errors indicate unrecoverable conditions
if (errno == ENXIO || errno == ENODEV) {
    throw std::runtime_error("Network interface unavailable");
}
```

---

## Performance Considerations

### Buffer Size Optimization

```cpp
// Query optimal buffer size from kernel
u_int bufsize;
ioctl(fd, BIOCGBLEN, &bufsize);

// Typical optimizations:
// - Larger buffers reduce system call overhead
// - Smaller buffers reduce memory usage
// - Power-of-2 sizes often perform better
```

### Batch Processing Benefits

```
Single read() call can return multiple packets:

Buffer: [bpf_hdr][packet1][padding][bpf_hdr][packet2][padding][bpf_hdr][packet3][padding]
                 ↑                           ↑                           ↑
              Process                     Process                   Process
```

**Advantages**:
- Reduced system call overhead
- Better CPU cache utilization
- Higher overall throughput

### Memory Alignment Importance

```cpp
// CRITICAL: Proper alignment prevents corruption
ptr += BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);

// BPF_WORDALIGN() rounds up to word boundary:
// - Ensures proper memory alignment for next record
// - Prevents segmentation faults on strict alignment architectures
// - Required for portable code across different platforms
```

---

## Debugging and Troubleshooting

### Common Issues and Solutions

#### 1. "Permission Denied" Errors
```bash
# Problem: Can't open BPF devices
open(/dev/bpf0): Permission denied

# Solution: Run with root privileges
sudo ./sniffer en0
```

#### 2. "Device Busy" Errors
```bash
# Problem: All BPF devices in use
open(/dev/bpf0): Device busy
open(/dev/bpf1): Device busy

# Solutions:
# 1. Kill other packet capture programs
sudo pkill tcpdump
sudo pkill wireshark

# 2. Check running processes
sudo lsof /dev/bpf*
```

#### 3. "Interface Not Found" Errors
```bash
# Problem: Invalid interface name
ioctl(BIOCSETIF): No such device

# Solution: Check available interfaces
ifconfig -a
```

### Debugging Tools

#### 1. System Call Tracing
```bash
# Trace system calls (macOS)
sudo dtruss -f ./sniffer en0

# Trace system calls (Linux)
sudo strace ./sniffer eth0
```

#### 2. BPF Device Status
```bash
# Check BPF device permissions
ls -la /dev/bpf*

# Check device usage
sudo lsof /dev/bpf*
```

#### 3. Network Interface Status
```bash
# Check interface status
ifconfig en0

# Check interface statistics
netstat -i
```

### Performance Monitoring

#### 1. Packet Statistics
```cpp
// Get BPF statistics
struct bpf_stat stats;
ioctl(fd, BIOCGSTATS, &stats);
printf("Received: %u packets\n", stats.bs_recv);
printf("Dropped: %u packets\n", stats.bs_drop);

// Drop rate indicates performance issues
double drop_rate = (double)stats.bs_drop / stats.bs_recv;
if (drop_rate > 0.01) {  // >1% drop rate
    printf("Warning: High packet drop rate\n");
}
```

#### 2. System Resource Usage
```bash
# Monitor CPU usage
top -pid $(pgrep sniffer)

# Monitor memory usage
ps -o pid,rss,vsz -p $(pgrep sniffer)
```

---

## Advanced BPF Features

### BPF Program Compilation

```c
// Example: Filter for TCP packets only
struct bpf_insn tcp_filter[] = {
    // Load Ethernet type at offset 12
    BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
    // Jump if not IPv4 (0x0800)
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x0800, 0, 4),
    // Load IP protocol at offset 23 (14+9)
    BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 23),
    // Jump if not TCP (6)
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 6, 0, 1),
    // Accept packet
    BPF_STMT(BPF_RET+BPF_K, (u_int)-1),
    // Reject packet
    BPF_STMT(BPF_RET+BPF_K, 0),
};

struct bpf_program program = {
    sizeof(tcp_filter)/sizeof(tcp_filter[0]),
    tcp_filter
};

ioctl(fd, BIOCSETF, &program);
```

### Integration with Network Stack

```
Packet Flow in Kernel:

Hardware → Driver → Network Stack → BPF → User Space
    ↓         ↓          ↓           ↓        ↓
  PHY/MAC   Link     IP/TCP/UDP    Filter   App
   Layer    Layer      Layer      Program  Logic
```

**BPF Insertion Point**: Packets are copied to BPF before normal network stack processing

**Performance Benefit**: Filtering in kernel space reduces user-space processing overhead

---

## Conclusion

This comprehensive guide provides all the technical details needed to understand and extend the BPF integration in our network sniffer. The combination of system calls, ioctl commands, and data structures creates a powerful interface for network packet capture and analysis.

**Key Takeaways**:
1. **BPF provides raw, high-performance packet access**
2. **System calls form the foundation of kernel interaction**
3. **Proper error handling is critical for robust operation**
4. **Performance optimization requires understanding kernel behavior**
5. **Security and ethics must guide implementation decisions**

The documentation serves as both a reference for the current implementation and a guide for future enhancements and extensions.