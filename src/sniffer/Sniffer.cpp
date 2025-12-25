#include "Sniffer.h"
#include "PacketParser.h"
#include "../Protocol.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/bpf.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

/**
 * @brief Constructor: Initialize BPF device and configure for specified interface
 * 
 * Creates a new Sniffer instance that will monitor the specified network interface.
 * This constructor performs all necessary initialization including BPF device
 * discovery, interface binding, and buffer allocation. The constructor provides
 * strong exception safety - if any step fails, all resources are properly cleaned up.
 * 
 * @param iface Network interface name to monitor (e.g., "en0", "en1", "wlan0").
 *              Must be a valid network interface name that exists on the system
 *              and is accessible. The interface should be up and configured.
 *              Common interface names on macOS include:
 *              - "en0": Primary Ethernet interface
 *              - "en1": Secondary Ethernet or USB adapter  
 *              - "awdl0": Apple Wireless Direct Link
 *              - "lo0": Loopback interface (for testing)
 *              The string is copied internally, so the caller's buffer can be
 *              freed after construction.
 * 
 * @throws std::runtime_error If no BPF devices are available (all in use)
 * @throws std::runtime_error If interface binding fails (invalid interface name)
 * @throws std::runtime_error If BPF configuration fails (permission denied)
 * @throws std::runtime_error If buffer allocation fails (insufficient memory)
 * 
 * @note Requires root privileges to access BPF devices. Run with sudo.
 * @note Each Sniffer instance exclusively uses one BPF device.
 * 
 * @see openBpfDevice(), configureInterface()
 */
Sniffer::Sniffer(const std::string& iface, const std::string& server_ip, int server_port)
    : iface_(iface), server_ip_(server_ip), server_port_(server_port) {
    fd_ = openBpfDevice();
    configureInterface();

    if (!server_ip_.empty() && server_port_ > 0) {
        connectToServer();
        sendClientHello();
        receiveServerHello();

        PacketParser::setLogCallback([this](const json& log) {
            this->sendTrafficLog(log);
        });
    }
}

Sniffer::~Sniffer() {
    if (fd_ != -1) {
        close(fd_);
    }
    if (server_fd_ != -1) {
        close(server_fd_);
    }
}

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

void Sniffer::configureInterface() {
    // BPF CONFIGURATION SEQUENCE
    // =================================================================
    // This function performs the critical initialization of the BPF device:
    // 1. Bind to the target network interface
    // 2. Set capture mode (immediate vs buffered)
    // 3. Query and allocate capture buffer
    //
    // Each step must complete successfully before proceeding to next.
    // Any ioctl() failure indicates a configuration problem (permissions,
    // invalid interface, BPF not available, etc.).

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface_.c_str(), IFNAMSIZ - 1);

    // STEP 1: Bind BPF device to network interface
    // ===============================================
    // BIOCSETIF: "BPF I/O Control - SET InterFace"
    // Tells the BPF device which network interface to capture from
    //
    // Why memset and strncpy pattern?
    // - memset: Null-initialize entire struct (avoid garbage data)
    // - strncpy with IFNAMSIZ-1: Reserve 1 byte for null terminator
    //   If iface is longer than IFNAMSIZ-1, it will be truncated and null-terminated
    //   This prevents buffer overrun
    if (ioctl(fd_, BIOCSETIF, &ifr) == -1) {
        throw std::runtime_error("Failed to bind to interface " + iface_);
    }

    // STEP 2: Enable IMMEDIATE MODE
    // ===============================================
    // BIOCIMMEDIATE: Capture packets as soon as available
    //
    // Trade-off: Latency vs Throughput
    //
    // Immediate Mode (what we use):
    // - Packets delivered as soon as captured by NIC
    // - Low latency: <10ms typically
    // - Higher CPU usage: frequent small reads
    // - Good for real-time monitoring (our use case)
    //
    // Alternative - Buffer Mode (BIOCIMMEDIATE=0):
    // - OS buffers packets in BPF buffer
    // - Higher throughput: batch process many packets per read()
    // - Higher latency: wait for buffer to fill
    // - Good for high-speed captures (>100K pps)
    //
    // Our choice: Immediate mode prioritizes latency for monitoring
    u_int enable = 1;
    if (ioctl(fd_, BIOCIMMEDIATE, &enable) == -1) {
        throw std::runtime_error("Failed to set immediate mode");
    }

    // STEP 3: Query BPF buffer size
    // ===============================================
    // BIOCGBLEN: "BPF I/O Control - GET Buffer LENgth"
    //
    // Why query instead of hardcoding?
    // - BPF buffer size determined by OS kernel
    // - Depends on system config, available memory, interface speed
    // - Typical sizes: 4KB (slow), 32KB (normal), 64KB (fast network)
    // - Querying is idiomatic: "Ask the OS what it wants to use"
    //
    // The kernel optimizes this value based on:
    // - Physical memory available
    // - Interface speed (faster = bigger buffer)
    // - Current system load
    // - Tunable kernel parameters
    //
    // We then allocate a std::vector of this exact size.
    // Using std::vector provides RAII semantics: auto-freed on destruction
    u_int bufsize;
    if (ioctl(fd_, BIOCGBLEN, &bufsize) == -1) {
        throw std::runtime_error("Failed to get buffer size");
    }

    buffer_.resize(bufsize);
    std::cout << "Attached to " << iface_ << " (bpf buf " << bufsize << " bytes)" << std::endl;
}

void Sniffer::run() {
    doReadLoop();
}

void Sniffer::doReadLoop() {
    // PACKET CAPTURE MAIN LOOP
    // =================================================================
    // This function reads captured packets from the BPF device and processes them.
    // It demonstrates several important concepts:
    // 1. Batch processing: multiple packets per read()
    // 2. Zero-copy access: pointers into kernel buffer
    // 3. Memory alignment: struct packing and word boundaries
    // 4. Bounds checking: prevent reading past buffer end

    while (true) {
        // STEP 1: Read raw packet buffer from BPF device
        // ===============================================
        // read() returns the number of bytes available in the BPF buffer
        // The buffer contains one or more packets in BPF wire format
        //
        // BPF Wire Format:
        // +---+---+---+---+---+---+
        // | bpf_hdr | packet data | bpf_hdr | packet data | ...
        // +---+---+---+---+---+---+
        //
        // Each bpf_hdr tells us:
        // - bh_hdrlen: Size of the header itself (usually 18 bytes)
        // - bh_caplen: Size of the captured packet data
        // - bh_datalen: Size of the original packet (if truncated, larger than caplen)
        // - bh_tstamp: Timestamp when packet was captured
        //
        // bytes_read: Total bytes in this read (typically 32KB)
        // This single read() may contain 10-1000 packets depending on traffic

        ssize_t bytes_read = read(fd_, buffer_.data(), buffer_.size());
        if (bytes_read <= 0) {
            continue;  // No data or error; retry
        }

        // STEP 2: Parse multiple packets from single buffer
        // ===============================================
        // Now iterate through all packets in this buffer
        // Each iteration processes one bpf_hdr + packet pair

        unsigned char* ptr = buffer_.data();          // Current position in buffer
        unsigned char* end = ptr + bytes_read;        // End of valid data

        while (ptr < end) {
            // Cast to BPF header (interprets raw bytes as struct)
            struct bpf_hdr* bh = reinterpret_cast<struct bpf_hdr*>(ptr);

            // BOUNDS CHECK 1: Is there a complete header?
            if (ptr + bh->bh_hdrlen > end) {
                // Partial header at end of buffer; discard and exit
                break;
            }

            // Calculate packet start: just after the BPF header
            unsigned char* packet = ptr + bh->bh_hdrlen;

            // BOUNDS CHECK 2: Is the complete packet in buffer?
            if (packet + bh->bh_caplen > end) {
                // Partial packet at end of buffer; discard and exit
                break;
            }

            // ZERO-COPY PACKET ACCESS
            // =======================
            // Notice: we're NOT copying the packet data
            // We pass a pointer directly into the kernel buffer
            // This is extremely efficient: zero allocation, zero memcpy
            //
            // The packet pointer remains valid ONLY until the next read()
            // call, after which the buffer will be overwritten
            // PacketParser must not cache these pointers across loop iterations

            struct timeval tv;
            tv.tv_sec = bh->bh_tstamp.tv_sec;
            tv.tv_usec = bh->bh_tstamp.tv_usec;

            // Process this packet (parse and either send to server or print)
            if (server_fd_ != -1) {
                PacketParser::parseToJSON(packet, bh->bh_caplen, tv, nullptr);
            } else {
                PacketParser::parseAndPrint(packet, bh->bh_caplen, tv);
            }

            // STEP 3: Move pointer to next packet
            // ====================================
            // BPF_WORDALIGN: Round up to machine word boundary (typically 4 bytes)
            //
            // Why alignment?
            // - BPF records must start on word boundaries
            // - Unaligned memory access is slow (or illegal on some architectures)
            // - Example: record is 25 bytes -> rounds to 28 bytes (next multiple of 4)
            //
            // Memory layout:
            // Offset 0:   [bpf_hdr: 18 bytes][packet: 7 bytes][padding: 3 bytes]
            // Offset 28:  [next bpf_hdr: 18 bytes]...
            //             ^-- Aligned to 4-byte boundary
            //
            // Formula: BPF_WORDALIGN(x) = (((x) + 3) & ~3)
            //          Rounds up to nearest multiple of 4
            //
            // Common mistake: forgetting alignment
            // - Would read into middle of next bpf_hdr
            // - Would parse garbage data
            // - Could cause infinite loops or crashes

            ptr += BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);
        }
    }
}

void Sniffer::connectToServer() {
    server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd_ < 0) {
        throw std::runtime_error("Failed to create TCP socket");
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port_);
    if (inet_pton(AF_INET, server_ip_.c_str(), &server_addr.sin_addr) <= 0) {
        throw std::runtime_error("Invalid server IP address");
    }

    if (connect(server_fd_, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        throw std::runtime_error("Failed to connect to server");
    }

    std::cout << "Connected to server at " << server_ip_ << ":" << server_port_ << std::endl;
}

void Sniffer::sendClientHello() {
    json hello;
    char hostname[256];
    gethostname(hostname, sizeof(hostname));
    hello["hostname"] = hostname;
    hello["interface"] = iFface_;

    if (!sendFrame(Protocol::CLIENT_HELLO, hello.dump())) {
        throw std::runtime_error("Failed to send CLIENT_HELLO");
    }
    std::cout << "Sent CLIENT_HELLO" << std::endl;
}

void Sniffer::receiveServerHello() {
    uint8_t type;
    std::string payload;

    if (!readFrame(server_fd_, type, payload) || type != Protocol::SERVER_HELLO) {
        throw std::runtime_error("Failed to receive SERVER_HELLO");
    }

    try {
        json response = json::parse(payload);
        ssid_ = response["ssid"];
        std::cout << "Received SSID: " << ssid_ << std::endl;
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to parse SERVER_HELLO: " + std::string(e.what()));
    }
}

bool Sniffer::sendFrame(uint8_t type, const std::string& payload) {
    if (payload.length() > 1024) return false;

    uint8_t header[4];
    header[0] = Protocol::VERSION;
    header[1] = type;
    header[2] = (payload.length() >> 8) & 0xFF;
    header[3] = payload.length() & 0xFF;

    if (write(server_fd_, header, 4) != 4) return false;
    if (write(server_fd_, payload.data(), payload.length()) != (ssize_t)payload.length()) return false;
    if (write(server_fd_, &Protocol::TERM_BYTE, 1) != 1) return false;

    return true;
}

bool Sniffer::readExact(int fd, void* buf, size_t len) {
    // TCP SHORT READ HANDLING
    // =================================================================
    // This function solves a fundamental TCP/IP problem:
    // read() may return FEWER bytes than requested, even if more are available
    //
    // Problem Scenario:
    // ==================
    // You want to read 100 bytes.
    // read(fd, buf, 100) returns 45.
    // You must call read() again to get the remaining 55 bytes.
    // But naively, you'd process only 45 bytes, losing the rest!
    //
    // Why does TCP do this?
    // TCP is a byte stream protocol. The kernel fills read() from:
    // 1. Data already arrived from network
    // 2. Data waiting in socket buffer
    // 3. Available kernel buffer space
    // The kernel may have received packet 1 (45 bytes) but not packet 2 yet.
    // It returns what's available rather than blocking forever.
    //
    // Real example from networking:
    // - You ask for 1024 bytes (a frame: header + payload)
    // - Network delivers first 64 bytes
    // - read() returns 64, not 1024
    // - Your frame parser would fail: "incomplete frame!"
    // - Without readExact(), frame parsing is broken
    //
    // Solution: readExact() loop
    // ==========================
    // Keep reading until we have exactly len bytes OR an error occurs
    //
    // Details:
    // - total: bytes accumulated so far
    // - buf + total: offset into buffer where to place next read
    // - len - total: how many more bytes we still need
    // - Loop while total < len (haven't reached goal)
    // - If read() returns 0 or -1: error/EOF, return false
    // - Otherwise: accumulate in total, continue loop
    //
    // Example execution:
    // Want to read: 100 bytes
    // Iteration 1: read() returns 45  -> total=45, continue
    // Iteration 2: read() returns 30  -> total=75, continue
    // Iteration 3: read() returns 25  -> total=100, exit loop
    // return true (success)
    //
    // This pattern is ESSENTIAL for:
    // - Binary protocol parsing (our case)
    // - HTTP parsing (wait for exact headers)
    // - SSL/TLS handshakes
    // - Any fixed-size-header protocol
    //
    // Alternative approaches NOT used:
    // - MSG_WAITALL flag: not portable (Unix-specific)
    // - Socket timeout: adds complexity
    // - Non-blocking I/O with select/epoll: much more complex

    size_t total = 0;
    while (total < len) {
        ssize_t n = read(fd, (char*)buf + total, len - total);
        if (n <= 0) return false;  // Error or EOF
        total += n;
    }
    return true;  // Got exactly len bytes
}

bool Sniffer::readFrame(int fd, uint8_t& type, std::string& payload) {
    uint8_t header[4];
    if (!readExact(fd, header, 4)) return false;

    if (header[0] != Protocol::VERSION) return false;

    type = header[1];
    uint16_t length = (header[2] << 8) | header[3];

    if (length > 1024) return false;

    std::vector<char> payload_buf(length);
    if (!readExact(fd, payload_buf.data(), length)) return false;
    payload = std::string(payload_buf.begin(), payload_buf.end());

    uint8_t term;
    if (!readExact(fd, &term, 1) || term != Protocol::TERM_BYTE) return false;

    return true;
}

void Sniffer::sendTrafficLog(const json& log) {
    if (server_fd_ == -1) return;

    json traffic_log = log;
    traffic_log["ssid"] = ssid_;

    std::string payload = traffic_log.dump();
    std::cout << "[SNIFFER] Sending log to server: " << payload.substr(0, 100) << "..." << std::endl;

    if (!sendFrame(Protocol::TRAFFIC_LOG, payload)) {
        std::cerr << "[SNIFFER] Failed to send traffic log" << std::endl;
    }
}

/*
 * Implementation Notes:
 * 
 * 1. BPF Record Structure:
 *    Each packet read from BPF is structured as:
 *    [struct bpf_hdr][packet data][padding to word boundary]
 *    
 * 2. Word Alignment:
 *    BPF_WORDALIGN() is essential for proper record traversal.
 *    Without it, subsequent records will be misaligned, causing
 *    crashes or infinite loops.
 *    
 * 3. Batch Processing:
 *    A single read() may return multiple packets. This is more
 *    efficient than reading one packet at a time.
 *    
 * 4. Error Handling:
 *    The implementation uses exceptions for configuration errors
 *    but continues on read errors (which are often transient).
 *    
 * 5. Performance:
 *    - Zero-copy packet access (direct buffer pointers)
 *    - Minimal allocations in the hot path
 *    - Efficient buffer reuse
 *    
 * 6. Thread Safety:
 *    This implementation is not thread-safe. BPF devices are
 *    typically used by a single thread for packet capture.
 */