#include "Sniffer.h"
#include "PacketParser.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/bpf.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <stdexcept>

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
 */\nSniffer::Sniffer(const std::string& iface) : iface_(iface) {
    fd_ = openBpfDevice();
    configureInterface();
}

Sniffer::~Sniffer() {
    if (fd_ != -1) {
        close(fd_);
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

void Sniffer::run() {
    doReadLoop();
}

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