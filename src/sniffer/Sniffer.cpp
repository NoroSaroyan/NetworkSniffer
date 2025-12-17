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

            if (server_fd_ != -1) {
                PacketParser::parseToJSON(packet, bh->bh_caplen, tv, nullptr);
            } else {
                PacketParser::parseAndPrint(packet, bh->bh_caplen, tv);
            }

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
    hello["interface"] = iface_;

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
    size_t total = 0;
    while (total < len) {
        ssize_t n = read(fd, (char*)buf + total, len - total);
        if (n <= 0) return false;
        total += n;
    }
    return true;
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