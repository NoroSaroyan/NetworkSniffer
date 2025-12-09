# Sniffer Class - BPF Device Management Documentation

## Overview

The `Sniffer` class encapsulates all Berkeley Packet Filter (BPF) device interactions for network packet capture on macOS. It provides a high-level, object-oriented interface for the low-level BPF system calls, implementing RAII (Resource Acquisition Is Initialization) principles for automatic resource management and exception-safe operations.

## Architecture and Design Philosophy

### Core Responsibilities
1. **BPF Device Discovery**: Find and open available BPF devices from the system
2. **Interface Binding**: Attach the BPF device to a specific network interface
3. **Real-time Configuration**: Set up immediate mode for live packet capture
4. **Buffer Management**: Allocate and manage packet capture buffers
5. **Packet Reading**: Continuously read packets and forward them for parsing
6. **Resource Cleanup**: Automatically release BPF devices when done

### Design Patterns Used
- **RAII (Resource Acquisition Is Initialization)**: Resources acquired in constructor, released in destructor
- **Exception Safety**: Strong exception guarantees with automatic cleanup
- **Single Responsibility**: Each method has one clear purpose
- **Defensive Programming**: Comprehensive error checking and validation

## Class Interface Analysis

### Header File Structure (Sniffer.h)

#### Include Dependencies
```cpp
#include <string>
#include <vector>
```

**Why these includes?**
- `<string>`: For the interface name storage (iface_)
- `<vector>`: For dynamic buffer management (buffer_)

**Notable absences**: No system headers in the header file - keeps implementation details private and reduces compilation dependencies.

#### Class Declaration
```cpp
class Sniffer {
public:
    explicit Sniffer(const std::string& iface);
    ~Sniffer();
    void run();

private:
    int openBpfDevice();
    void configureInterface();
    void doReadLoop();
    
    int fd_ = -1;
    std::string iface_;
    std::vector<unsigned char> buffer_;
};
```

**Design decisions explained**:
- **explicit constructor**: Prevents implicit string-to-Sniffer conversions
- **Private implementation methods**: Hides BPF complexity from users
- **Member variable naming**: Trailing underscore indicates private members
- **Vector for buffer**: Automatic memory management, exception-safe

## Implementation Deep Dive (Sniffer.cpp)

### System Headers and Their Purpose
```cpp
#include <sys/types.h>    // Basic system types (size_t, ssize_t, etc.)
#include <sys/socket.h>   // Socket system calls and structures
#include <sys/ioctl.h>    // I/O control operations (ioctl)
#include <net/if.h>       // Network interface structures (struct ifreq)
#include <net/bpf.h>      // BPF-specific structures and constants
#include <fcntl.h>        // File control operations (open, O_RDWR)
#include <unistd.h>       // POSIX system calls (close, read)
#include <cstring>        // C string operations (memset, strncpy)
#include <iostream>       // Output streams for user feedback
#include <stdexcept>      // Standard exception classes
```

**Each header's role**:
- **sys/types.h**: Defines fundamental types used throughout system programming
- **sys/socket.h**: Provides socket-related definitions (though not directly used for sockets here)
- **sys/ioctl.h**: Essential for BPF device configuration through ioctl() calls
- **net/if.h**: Contains network interface structures like `struct ifreq`
- **net/bpf.h**: BPF-specific definitions including `struct bpf_hdr`, `BIOC*` constants
- **fcntl.h**: File operations, particularly `open()` and file flags
- **unistd.h**: POSIX system calls for file operations
- **cstring**: C-style string operations for interface name handling
- **iostream**: User feedback during BPF operations
- **stdexcept**: Modern C++ exception handling

### Constructor Implementation

```cpp
Sniffer::Sniffer(const std::string& iface) : iface_(iface) {
    fd_ = openBpfDevice();
    configureInterface();
}
```

**Constructor flow**:
1. **Member initialization**: Store interface name in `iface_` member
2. **BPF device acquisition**: Find and open an available BPF device
3. **Interface configuration**: Bind BPF device to the specified interface

**Exception safety**: If any step fails, destructor automatically cleans up any acquired resources.

**Why this order?**: Each step depends on the previous one succeeding:
- Interface name must be stored before configuration
- BPF device must be open before binding to interface

### Destructor Implementation

```cpp
Sniffer::~Sniffer() {
    if (fd_ != -1) {
        close(fd_);
    }
}
```

**RAII in action**:
- **Automatic cleanup**: Destructor called when object goes out of scope
- **Idempotent operation**: Safe to call even if fd_ was never set
- **Exception safety**: Destructor should never throw exceptions

**Why check fd_ != -1?**: 
- `-1` is the conventional "invalid file descriptor" value
- Prevents attempting to close an invalid descriptor
- Handles cases where constructor failed before opening device

## BPF Device Discovery and Management

### openBpfDevice() Method

```cpp
int Sniffer::openBpfDevice() {
    for (int i = 0; i < 100; ++i) {
        std::string device = "/dev/bpf" + std::to_string(i);
        int fd = open(device.c_str(), O_RDWR);
        if (fd != -1) {
            std::cout << "Opened " << device << std::endl;
            return fd;
        }
    }
    throw std::runtime_error("Failed to open any BPF device");
}
```

**BPF device numbering**: macOS provides BPF devices numbered `/dev/bpf0` through `/dev/bpf99`.

**Exclusive access model**: Each BPF device can only be used by one process at a time:
- **First available**: Loop finds first device that can be opened
- **Already in use**: If a device is busy, `open()` fails and loop continues
- **Success**: Return file descriptor for subsequent operations

**Why O_RDWR flag?**:
- **Read capability**: Required to read packets from the device
- **Write capability**: Needed for ioctl() configuration operations
- **No O_CREAT**: BPF devices already exist in the system

**Error handling**: If all 100 devices are busy, throw descriptive exception.

**Limitations**: 
- System-wide limit of 100 concurrent BPF users
- No device reservation mechanism
- First-come, first-served allocation

### BPF Device Architecture

**How BPF devices work**:
1. **Kernel module**: BPF is implemented as a kernel module
2. **Character devices**: Each `/dev/bpf*` is a character device
3. **Exclusive access**: Prevents conflicts between monitoring tools
4. **Configurable**: Each device can be bound to different interfaces

**Security model**:
- **Root-only access**: BPF devices require root privileges
- **Reason**: Can capture all network traffic on an interface
- **Alternative**: On some systems, specific groups can access BPF

## Interface Configuration Deep Dive

### configureInterface() Method

```cpp
void Sniffer::configureInterface() {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface_.c_str(), IFNAMSIZ - 1);
    
    if (ioctl(fd_, BIOCSETIF, &ifr) == -1) {
        throw std::runtime_error("Failed to bind to interface " + iface_);
    }
    
    u_int enable = 1;
    if (ioctl(fd_, BIOCIMMEDIATE, &enable) == -1) {
        throw std::runtime_error("Failed to set immediate mode");
    }
    
    u_int bufsize;
    if (ioctl(fd_, BIOCGBLEN, &bufsize) == -1) {
        throw std::runtime_error("Failed to get buffer size");
    }
    
    buffer_.resize(bufsize);
    std::cout << "Attached to " << iface_ << " (bpf buf " << bufsize << " bytes)" << std::endl;
}
```

#### Step 1: Interface Binding (BIOCSETIF)

```cpp
struct ifreq ifr;
memset(&ifr, 0, sizeof(ifr));
strncpy(ifr.ifr_name, iface_.c_str(), IFNAMSIZ - 1);
```

**Purpose**: Tell BPF device which network interface to monitor.

**struct ifreq explained**:
- **Interface request structure**: Standard way to reference network interfaces
- **ifr_name field**: Contains the interface name string
- **IFNAMSIZ**: Maximum interface name length (usually 16 characters)

**Memory safety**:
- **memset()**: Zero-initialize entire structure (clears any padding)
- **strncpy()**: Safely copy string, preventing buffer overflows
- **IFNAMSIZ - 1**: Ensures null terminator space

**Why zero-initialize?**: 
- Structures may contain padding bytes with undefined values
- ioctl() might read the entire structure
- Prevents unpredictable behavior from uninitialized memory

#### Step 2: Immediate Mode (BIOCIMMEDIATE)

```cpp
u_int enable = 1;
if (ioctl(fd_, BIOCIMMEDIATE, &enable) == -1) {
    throw std::runtime_error("Failed to set immediate mode");
}
```

**What is immediate mode?**:
- **Without immediate mode**: BPF buffers packets until buffer is full
- **With immediate mode**: BPF delivers packets immediately upon arrival
- **Why we need it**: For real-time packet analysis

**Buffering behavior comparison**:
- **Default mode**: Higher throughput, higher latency
- **Immediate mode**: Lower latency, potentially lower throughput
- **Our use case**: Interactive packet monitoring requires low latency

**u_int type**: Unsigned integer type for BPF configuration values.

#### Step 3: Buffer Size Discovery (BIOCGBLEN)

```cpp
u_int bufsize;
if (ioctl(fd_, BIOCGBLEN, &bufsize) == -1) {
    throw std::runtime_error("Failed to get buffer size");
}

buffer_.resize(bufsize);
```

**Why query buffer size?**:
- **System-dependent**: Different systems may have different optimal buffer sizes
- **Performance optimization**: Using system's preferred size maximizes efficiency
- **Memory allocation**: Need to know how much memory to allocate

**Typical buffer sizes**:
- **macOS**: Usually 4KB to 32KB
- **Factors**: Available memory, system load, interface speed
- **Trade-offs**: Larger buffers = fewer system calls but more memory usage

**vector::resize()**:
- **Automatic allocation**: std::vector handles memory management
- **Exception safety**: If allocation fails, vector remains in valid state
- **Zero initialization**: New bytes are zero-initialized

## Packet Capture Loop Implementation

### run() Method

```cpp
void Sniffer::run() {
    doReadLoop();
}
```

**Simple delegation**: The public interface delegates to private implementation.

**Design benefits**:
- **Interface stability**: Public API remains simple
- **Implementation flexibility**: Private method can be changed without affecting users
- **Future extensibility**: Could add setup/cleanup around doReadLoop()

### doReadLoop() Method - The Heart of Packet Capture

```cpp
void Sniffer::doReadLoop() {
    while (true) {
        ssize_t bytes_read = read(fd_, buffer_.data(), buffer_.size());
        if (bytes_read <= 0) {
            continue;
        }
        
        unsigned char* ptr = buffer_.data();
        unsigned char* end = ptr + bytes_read;
        
        while (ptr < end) {
            struct bpf_hdr* bh = reinterpret_cast<struct bpf_hdr*>(ptr);
            
            if (ptr + bh->bh_hdrlen > end) {
                break;
            }
            
            unsigned char* packet = ptr + bh->bh_hdrlen;
            if (packet + bh->bh_caplen > end) {
                break;
            }
            
            struct timeval tv;
            tv.tv_sec = bh->bh_tstamp.tv_sec;
            tv.tv_usec = bh->bh_tstamp.tv_usec;
            PacketParser::parseAndPrint(packet, bh->bh_caplen, tv);
            
            ptr += BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);
        }
    }
}
```

#### Read System Call

```cpp
ssize_t bytes_read = read(fd_, buffer_.data(), buffer_.size());
if (bytes_read <= 0) {
    continue;
}
```

**read() system call**:
- **Blocking call**: Waits until packets are available
- **Batch reading**: May return multiple packets in one call
- **Error handling**: Returns 0 on EOF, -1 on error, positive on success

**Why continue on bytes_read <= 0?**:
- **Interrupted system calls**: Signals can interrupt read()
- **Temporary conditions**: May be transient issues
- **Robustness**: Better to retry than exit on temporary problems

#### BPF Record Structure

**Critical concept**: BPF returns packets in a special record format:
```
[struct bpf_hdr][packet data][padding to word boundary]
[struct bpf_hdr][packet data][padding to word boundary]
...
```

**Why this format?**:
- **Metadata**: Each record includes capture timestamp and length info
- **Alignment**: Word-aligned records enable efficient memory access
- **Batching**: Multiple packets can be returned in one read() call

#### Record Processing Loop

```cpp
unsigned char* ptr = buffer_.data();
unsigned char* end = ptr + bytes_read;

while (ptr < end) {
    struct bpf_hdr* bh = reinterpret_cast<struct bpf_hdr*>(ptr);
```

**Pointer arithmetic approach**:
- **ptr**: Current position in the buffer
- **end**: Points to first byte after valid data
- **Loop condition**: Process until all data is consumed

**reinterpret_cast safety**: We know the BPF format guarantees proper alignment.

#### Bounds Checking - Critical for Security

```cpp
if (ptr + bh->bh_hdrlen > end) {
    break;
}

unsigned char* packet = ptr + bh->bh_hdrlen;
if (packet + bh->bh_caplen > end) {
    break;
}
```

**Why bounds checking is essential**:
- **Malformed data**: Network interfaces can produce corrupted data
- **Buffer overruns**: Reading past buffer end causes crashes or security vulnerabilities
- **Defensive programming**: Always validate before dereferencing pointers

**Two-stage validation**:
1. **Header bounds**: Ensure BPF header is complete
2. **Packet bounds**: Ensure packet data is complete

#### Timestamp Extraction

```cpp
struct timeval tv;
tv.tv_sec = bh->bh_tstamp.tv_sec;
tv.tv_usec = bh->bh_tstamp.tv_usec;
```

**Timestamp precision**: BPF provides microsecond-accurate timestamps:
- **tv_sec**: Seconds since Unix epoch (January 1, 1970)
- **tv_usec**: Microseconds within the current second (0-999999)

**Why copy timestamp?**: The bh pointer becomes invalid after advancing to next record.

#### Word Alignment - The Secret Sauce

```cpp
ptr += BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);
```

**BPF_WORDALIGN() macro**:
- **Purpose**: Rounds up to next word boundary (usually 4 or 8 bytes)
- **Why needed**: CPU efficiency requires word-aligned memory access
- **Formula**: Typically `(x + (sizeof(int) - 1)) & ~(sizeof(int) - 1)`

**What happens without word alignment?**:
- **Crashes**: Some architectures crash on misaligned access
- **Performance**: Misaligned access is much slower on all architectures
- **Infinite loops**: Incorrect pointer advancement can loop forever

**Record size calculation**:
- **bh->bh_hdrlen**: Size of BPF header (usually 20 bytes)
- **bh->bh_caplen**: Size of captured packet data
- **Total**: Header + packet data, rounded up to word boundary

## Performance Considerations

### Zero-Copy Architecture
- **Direct buffer access**: Packets are accessed directly from BPF buffer
- **No memory copying**: reinterpret_cast provides direct access
- **Efficiency**: Minimal CPU overhead for packet access

### Batch Processing
- **Multiple packets per read()**: Reduces system call overhead
- **Efficient iteration**: Process all packets from one read() call
- **Scalability**: Can handle high packet rates

### Memory Management
- **Pre-allocated buffer**: Buffer allocated once during initialization
- **Buffer reuse**: Same buffer used for all packet reads
- **Automatic sizing**: Buffer size optimized by system

## Error Handling Strategy

### Exception Types
- **std::runtime_error**: Used for all operational failures
- **Descriptive messages**: Clear error descriptions for debugging
- **Resource cleanup**: RAII ensures cleanup even on exceptions

### Error Categories
1. **Device access errors**: No available BPF devices
2. **Interface binding errors**: Invalid interface name
3. **Configuration errors**: ioctl() failures
4. **Buffer allocation errors**: Insufficient memory

### Recovery Strategies
- **Constructor failures**: Object never created, no cleanup needed
- **Runtime failures**: Destructor ensures cleanup
- **Transient read errors**: Continue operation, don't exit

## Thread Safety and Concurrency

### Current Implementation
- **Single-threaded**: Designed for use by one thread
- **Non-reentrant**: Methods not safe for concurrent access
- **BPF device exclusivity**: Each BPF device used by single process

### Multi-threading Considerations
- **Thread-local instances**: Each thread needs separate Sniffer instance
- **Interface sharing**: Multiple threads could monitor same interface with different BPF devices
- **Synchronization**: Shared data structures would need locking

## Integration with PacketParser

### Loose Coupling
```cpp
PacketParser::parseAndPrint(packet, bh->bh_caplen, tv);
```

**Design benefits**:
- **Separation of concerns**: Sniffer handles BPF, PacketParser handles protocols
- **Modularity**: Could swap in different packet analyzers
- **Testability**: Components can be tested independently

### Data Flow
1. **BPF capture**: Sniffer reads raw packet data from kernel
2. **Validation**: Bounds checking ensures data integrity
3. **Delegation**: PacketParser analyzes protocol structure
4. **Output**: PacketParser generates human-readable output

This comprehensive documentation shows how the Sniffer class elegantly encapsulates the complex Berkeley Packet Filter interface, providing a clean, safe, and efficient foundation for network packet capture on macOS systems.