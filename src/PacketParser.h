/**
 * @file PacketParser.h
 * @brief Network protocol parsing and packet analysis utilities
 * 
 * This header defines the PacketParser class which provides comprehensive
 * network protocol parsing capabilities. It handles multiple layers of the
 * network stack including Ethernet (Layer 2), IPv4 (Layer 3), and TCP/UDP
 * (Layer 4) protocols.
 * 
 * The parser performs defensive parsing with bounds checking to prevent
 * buffer overruns and handles variable-length headers correctly. All parsing
 * functions are static to enable efficient packet processing without object
 * instantiation overhead.
 * 
 * Protocol Support:
 * - Ethernet (IEEE 802.3) frames
 * - IPv4 (RFC 791) packets with variable header lengths
 * - TCP (RFC 793) segments with connection information
 * - UDP (RFC 768) datagrams
 * - ICMP (RFC 792) messages for network diagnostics
 * 
 * Output Format:
 * YYYY-MM-DD HH:MM:SS.UUUUUU src_ip:port -> dst_ip:port PROTOCOL len=bytes
 */

#pragma once

#include <sys/time.h>  // For struct timeval timestamp handling
#include <cstddef>     // For size_t type definitions

/**
 * @class PacketParser
 * @brief Static utility class for network packet parsing and analysis
 * 
 * PacketParser provides a comprehensive set of static methods for analyzing
 * network packets captured from BPF devices. It implements a layered parsing
 * approach that follows the OSI network model:
 * 
 * 1. Link Layer (Ethernet) - MAC addresses and protocol identification
 * 2. Network Layer (IPv4) - IP addressing and protocol determination  
 * 3. Transport Layer (TCP/UDP/ICMP) - Port numbers, connection info, and diagnostics
 * 
 * Key Features:
 * - Defensive parsing with comprehensive bounds checking
 * - Support for variable-length headers (IPv4 options, TCP options)
 * - Microsecond-precision timestamp formatting
 * - Clean, readable output format for packet analysis
 * - Zero-allocation parsing for high-performance packet processing
 * 
 * Thread Safety: All methods are thread-safe as they operate only on
 * input parameters and local variables.
 */
class PacketParser {
private:
    // ANSI color codes for traffic type visualization
    static constexpr const char* COLOR_TCP = "\033[34m";    // Blue for TCP
    static constexpr const char* COLOR_UDP = "\033[32m";    // Green for UDP
    static constexpr const char* COLOR_ICMP = "\033[33m";   // Yellow for ICMP
    static constexpr const char* COLOR_RESET = "\033[0m";   // Reset to default

public:
    /**
     * @brief Main entry point for packet parsing and display
     * 
     * This is the primary interface for packet analysis. It performs initial
     * validation and dispatches to appropriate protocol-specific parsers based
     * on the packet contents. Currently supports Ethernet frames containing
     * IPv4 packets.
     * 
     * @param packet Pointer to raw packet data from BPF device
     * @param caplen Number of bytes captured (may be less than actual packet size)
     * @param timestamp Precise capture timestamp from kernel (microsecond accuracy)
     * 
     * @note Performs bounds checking before accessing packet data
     * @note Silently ignores packets that are too small or malformed
     * @note Non-IPv4 packets (ARP, IPv6, etc.) are currently ignored
     * 
     * @see parseEthernet(), struct bpf_hdr for timestamp source
     */
    static void parseAndPrint(const unsigned char* packet, size_t caplen, const struct timeval& timestamp);

private:
    /**
     * @brief Parses Ethernet (Layer 2) frame headers
     * 
     * Analyzes the Ethernet frame structure to extract MAC addresses and
     * determine the next-layer protocol. Currently focuses on IPv4 traffic
     * but can be extended to support IPv6, ARP, and other protocols.
     * 
     * Ethernet Frame Structure (14 bytes):
     * - Destination MAC (6 bytes)
     * - Source MAC (6 bytes)  
     * - EtherType (2 bytes) - Protocol identifier
     * 
     * @param packet Pointer to start of Ethernet frame
     * @param caplen Total captured packet length
     * @param timestamp Packet capture timestamp
     * 
     * @note Validates minimum Ethernet header size before parsing
     * @see struct ether_header, ETHERTYPE_IP constant
     */
    static void parseEthernet(const unsigned char* packet, size_t caplen, const struct timeval& timestamp);
    
    /**
     * @brief Parses IPv4 (Layer 3) packet headers
     * 
     * Extracts IPv4 header information including source/destination addresses,
     * protocol identification, and header length. Handles variable-length IPv4
     * headers with options correctly.
     * 
     * IPv4 Header Structure (20-60 bytes):
     * - Version/Header Length (1 byte)
     * - Type of Service (1 byte)
     * - Total Length (2 bytes)
     * - Identification, Flags, Fragment Offset (4 bytes)
     * - TTL, Protocol, Checksum (4 bytes)
     * - Source IP Address (4 bytes)
     * - Destination IP Address (4 bytes)
     * - Options (0-40 bytes, variable)
     * 
     * @param packet Pointer to start of complete packet
     * @param offset Byte offset to start of IPv4 header
     * @param caplen Total captured packet length
     * @param timestamp Packet capture timestamp
     * 
     * @note Calculates header length from ip_hl field (words to bytes)
     * @note Validates header length and packet bounds
     * @see struct ip, IPPROTO_TCP, IPPROTO_UDP constants
     */
    static void parseIPv4(const unsigned char* packet, size_t offset, size_t caplen, const struct timeval& timestamp);
    
    /**
     * @brief Parses TCP (Layer 4) segment headers
     * 
     * Extracts TCP connection information including source/destination ports,
     * sequence numbers, and control flags. Provides detailed connection state
     * information for TCP traffic analysis.
     * 
     * TCP Header Structure (20-60 bytes):
     * - Source Port (2 bytes)
     * - Destination Port (2 bytes)
     * - Sequence Number (4 bytes)
     * - Acknowledgment Number (4 bytes)
     * - Header Length/Flags (2 bytes)
     * - Window Size (2 bytes)
     * - Checksum/Urgent Pointer (4 bytes)
     * - Options (0-40 bytes, variable)
     * 
     * @param packet Pointer to start of complete packet
     * @param offset Byte offset to start of TCP header
     * @param caplen Total captured packet length
     * @param src_ip Source IP address as formatted string
     * @param dst_ip Destination IP address as formatted string
     * @param timestamp Packet capture timestamp
     * 
     * @note Validates TCP header size before parsing
     * @see struct tcphdr, TCP flag definitions
     */
    static void parseTCP(const unsigned char* packet, size_t offset, size_t caplen, 
                        const char* src_ip, const char* dst_ip, const struct timeval& timestamp);
    
    /**
     * @brief Parses UDP (Layer 4) datagram headers
     * 
     * Extracts UDP datagram information including source/destination ports
     * and payload length. UDP is connectionless, so parsing is simpler than TCP.
     * 
     * UDP Header Structure (8 bytes):
     * - Source Port (2 bytes)
     * - Destination Port (2 bytes)
     * - Length (2 bytes) - Header + data length
     * - Checksum (2 bytes)
     * 
     * @param packet Pointer to start of complete packet
     * @param offset Byte offset to start of UDP header
     * @param caplen Total captured packet length
     * @param src_ip Source IP address as formatted string
     * @param dst_ip Destination IP address as formatted string
     * @param timestamp Packet capture timestamp
     * 
     * @note UDP header is fixed 8 bytes (simpler than TCP)
     * @see struct udphdr, UDP protocol characteristics
     */
    static void parseUDP(const unsigned char* packet, size_t offset, size_t caplen,
                        const char* src_ip, const char* dst_ip, const struct timeval& timestamp);
    
    /**
     * @brief Parses ICMP (Layer 4) message headers
     * 
     * Extracts ICMP message information including message type, code, and
     * type-specific data. ICMP is used for network diagnostics and error reporting.
     * 
     * ICMP Header Structure (8 bytes minimum):
     * - Type (1 byte) - Message type (ping, unreachable, etc.)
     * - Code (1 byte) - Subtype within message type
     * - Checksum (2 bytes)
     * - Type-specific data (4 bytes) - Varies by message type
     * 
     * Common ICMP Types:
     * - 0: Echo Reply (ping response)
     * - 3: Destination Unreachable
     * - 5: Redirect Message
     * - 8: Echo Request (ping)
     * - 11: Time Exceeded
     * 
     * @param packet Pointer to start of complete packet
     * @param offset Byte offset to start of ICMP header
     * @param caplen Total captured packet length
     * @param src_ip Source IP address as formatted string
     * @param dst_ip Destination IP address as formatted string
     * @param timestamp Packet capture timestamp
     * 
     * @note ICMP header is fixed 8 bytes but payload varies by type
     * @see RFC 792 - Internet Control Message Protocol
     */
    static void parseICMP(const unsigned char* packet, size_t offset, size_t caplen,
                         const char* src_ip, const char* dst_ip, const struct timeval& timestamp);
    
    /**
     * @brief Formats kernel timestamps into human-readable strings
     * 
     * Converts struct timeval timestamps (seconds + microseconds since epoch)
     * into formatted date/time strings with microsecond precision. Uses local
     * system timezone for display.
     * 
     * Output Format: "YYYY-MM-DD HH:MM:SS.UUUUUU"
     * Example: "2025-11-01 14:30:25.123456"
     * 
     * @param timestamp Kernel timestamp from BPF packet header
     * @param buffer Output buffer for formatted timestamp string
     * @param bufsize Size of output buffer (should be at least 32 bytes)
     * 
     * @note Uses localtime() for timezone conversion
     * @note Microsecond precision preserved from kernel timestamp
     * @see strftime(3), struct timeval, struct bpf_hdr
     */
    static void formatTimestamp(const struct timeval& timestamp, char* buffer, size_t bufsize);
};