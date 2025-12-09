/**
 * @file PacketParser.cpp
 * @brief Implementation of network protocol parsing and packet analysis
 * 
 * This file implements comprehensive network protocol parsing for multiple
 * layers of the TCP/IP stack. It provides defensive parsing with bounds
 * checking and handles variable-length headers correctly.
 * 
 * Protocol Stack Coverage:
 * - Layer 2 (Data Link): Ethernet frames (IEEE 802.3)
 * - Layer 3 (Network): IPv4 packets (RFC 791) with options support
 * - Layer 4 (Transport): TCP segments (RFC 793) and UDP datagrams (RFC 768)
 * 
 * Key Design Principles:
 * - Defensive programming: Always validate buffer bounds before access
 * - Zero-allocation parsing: Use direct pointer arithmetic for performance
 * - Clear output format: Human-readable packet summaries
 * - Extensible design: Easy to add support for additional protocols
 */

#include "PacketParser.h"  // Class interface definition

// Network protocol header definitions
#include <netinet/in.h>        // Internet address family (AF_INET, INADDR_*)
#include <netinet/if_ether.h>  // Ethernet header structures and constants
#include <netinet/ip.h>        // IPv4 header structure and protocol constants
#include <netinet/tcp.h>       // TCP header structure and flag definitions
#include <netinet/udp.h>       // UDP header structure
#include <netinet/ip_icmp.h>   // ICMP header structure and type definitions
#include <arpa/inet.h>         // Network address conversion (inet_ntop, ntohs)
#include <iostream>            // Standard output for packet display
#include <cstring>             // String manipulation (strlen, strncat)
#include <ctime>               // Time formatting (localtime, strftime)

// Main entry point for packet parsing and analysis
void PacketParser::parseAndPrint(const unsigned char* packet, size_t caplen, const struct timeval& timestamp) {
    //Initial Validation
    
    // Ensure we have at least enough data for an Ethernet header (14 bytes)
    // This is the minimum required for any meaningful packet analysis
    if (caplen < sizeof(struct ether_header)) {
        // Silently ignore runt packets - they're either corrupted or
        // incomplete captures (e.g., during interface initialization)
        return;
    }
    
    //Begin Protocol Analysis
    
    // Start parsing at Layer 2 (Ethernet) and work our way up the stack
    // The Ethernet parser will determine the next-layer protocol and
    // dispatch to appropriate Layer 3 parsers (IPv4, IPv6, ARP, etc.)
    parseEthernet(packet, caplen, timestamp);
}

/**
 * @brief Parse Ethernet (Layer 2) frame header
 * 
 * Analyzes the Ethernet frame structure to extract MAC addresses and determine
 * the next-layer protocol. Validates frame structure and dispatches to appropriate
 * Layer 3 protocol parsers based on EtherType field.
 * 
 * @param packet Pointer to the start of the Ethernet frame in memory.
 *               Must point to a valid memory location containing at least
 *               14 bytes of Ethernet header data. The packet pointer should
 *               come directly from the BPF buffer after validation.
 * 
 * @param caplen Total number of bytes captured for this packet. Used for
 *               bounds checking to ensure we don't read beyond the captured
 *               data. Must be at least sizeof(struct ether_header) = 14 bytes.
 *               This value comes from the BPF header's bh_caplen field.
 * 
 * @param timestamp Precise packet capture timestamp from the kernel BPF subsystem.
 *                  Contains both seconds (tv_sec) and microseconds (tv_usec)
 *                  since Unix epoch. Used for accurate packet timing analysis
 *                  and passed down to lower-layer parsers for display.
 * 
 * @note This function assumes the packet pointer points to the start of an
 *       Ethernet frame. It performs no additional bounds checking beyond
 *       what was done in parseAndPrint().
 * 
 * @see parseIPv4(), struct ether_header, ETHERTYPE_IP
 */
void PacketParser::parseEthernet(const unsigned char* packet, size_t caplen, const struct timeval& timestamp) {
    //Ethernet Frame Structure (14 bytes total)
    // Bytes 0-5:   Destination MAC address
    // Bytes 6-11:  Source MAC address  
    // Bytes 12-13: EtherType (protocol identifier)
    
    // Cast raw packet data to Ethernet header structure
    // We've already validated that we have at least 14 bytes in parseAndPrint()
    const auto* eth = reinterpret_cast<const struct ether_header*>(packet);
    
    // Extract the EtherType field and convert from network byte order
    // EtherType identifies the next-layer protocol (IPv4, IPv6, ARP, etc.)
    uint16_t ethertype = ntohs(eth->ether_type);
    
    //Protocol Dispatch
    
    // Currently we only handle IPv4 traffic (0x0800)
    // This could be extended to support:
    // - IPv6 (0x86DD)
    // - ARP (0x0806)
    // - VLAN tags (0x8100)
    // - etc.
    if (ethertype == ETHERTYPE_IP) {
        // IPv4 packet detected - parse the IP header
        // Pass offset to skip the Ethernet header (14 bytes)
        parseIPv4(packet, sizeof(struct ether_header), caplen, timestamp);
    }
    // Note: Non-IPv4 packets are silently ignored
    // In a more complete implementation, we might log unknown EtherTypes
}

/**
 * @brief Parse IPv4 (Layer 3) packet header
 * 
 * Extracts IPv4 header information including source/destination addresses,
 * protocol identification, and header length. Handles variable-length IPv4
 * headers with options and dispatches to appropriate transport layer parsers.
 * 
 * @param packet Pointer to the start of the complete packet buffer (including
 *               Ethernet header). The IPv4 header begins at (packet + offset).
 *               This allows the function to access the complete packet context
 *               while parsing only the IPv4 portion.
 * 
 * @param offset Byte offset from the start of packet where the IPv4 header begins.
 *               Typically 14 bytes (sizeof ether_header) for standard Ethernet
 *               frames. This offset accounts for any preceding headers that
 *               have already been processed.
 * 
 * @param caplen Total number of bytes captured for the entire packet, starting
 *               from the packet pointer. Used for comprehensive bounds checking
 *               to ensure we don't read beyond captured data, including when
 *               processing variable-length IPv4 options.
 * 
 * @param timestamp Precise packet capture timestamp from kernel BPF subsystem.
 *                  Passed through from parseEthernet() and forwarded to
 *                  transport layer parsers (TCP/UDP) for consistent timing
 *                  throughout the protocol stack analysis.
 * 
 * @note This function handles IPv4 headers with variable lengths due to
 *       optional fields. It validates both the minimum header size (20 bytes)
 *       and the actual header size specified in the ip_hl field.
 * 
 * @see parseTCP(), parseUDP(), struct ip, inet_ntop()
 */
void PacketParser::parseIPv4(const unsigned char* packet, size_t offset, size_t caplen, const struct timeval& timestamp) {
    //Initial IPv4 Header Validation
    
    // Ensure we have at least the minimum IPv4 header (20 bytes)
    if (offset + sizeof(struct ip) > caplen) {
        // Truncated IPv4 header - packet is malformed or capture was incomplete
        return;
    }
    
    //IPv4 Header Structure (20-60 bytes)
    // Byte 0:      Version (4 bits) + Header Length (4 bits)
    // Byte 1:      Type of Service / DSCP
    // Bytes 2-3:   Total Length
    // Bytes 4-7:   Identification, Flags, Fragment Offset
    // Bytes 8-11:  TTL, Protocol, Header Checksum
    // Bytes 12-15: Source IP Address
    // Bytes 16-19: Destination IP Address
    // Bytes 20+:   Options (0-40 bytes, variable length)
    
    // Cast to IPv4 header structure
    const struct ip* ip_hdr = reinterpret_cast<const struct ip*>(packet + offset);
    
    //Handle Variable-Length IPv4 Header
    
    // IPv4 headers can include options, making them variable length
    // ip_hl field contains header length in 32-bit words (minimum 5 = 20 bytes)
    int ip_hdr_len = ip_hdr->ip_hl * 4;  // Convert words to bytes
    
    // Validate that we have the complete IPv4 header including any options
    if (offset + ip_hdr_len > caplen) {
        // IPv4 header with options is truncated
        return;
    }
    
    //Extract IPv4 Addresses
    
    // Convert 32-bit IP addresses to human-readable dotted decimal notation
    char src_ip[INET_ADDRSTRLEN];  // Buffer for source IP ("xxx.xxx.xxx.xxx")
    char dst_ip[INET_ADDRSTRLEN];  // Buffer for destination IP
    
    // inet_ntop() converts binary IP addresses to presentation format
    // AF_INET specifies IPv4 address family
    inet_ntop(AF_INET, &ip_hdr->ip_src, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip_hdr->ip_dst, dst_ip, INET_ADDRSTRLEN);
    
    //Calculate Transport Layer Offset
    
    // The transport layer (TCP/UDP) starts after the IPv4 header
    // This accounts for any IPv4 options that may be present
    size_t transport_offset = offset + ip_hdr_len;
    
    //Protocol Dispatch to Transport Layer
    
    // The IPv4 Protocol field identifies the next-layer protocol
    // Most common values: 1=ICMP, 6=TCP, 17=UDP
    switch (ip_hdr->ip_p) {
        case IPPROTO_ICMP:  // Protocol 1 - Internet Control Message Protocol
            parseICMP(packet, transport_offset, caplen, src_ip, dst_ip, timestamp);
            break;
        case IPPROTO_TCP:  // Protocol 6 - Transmission Control Protocol
            parseTCP(packet, transport_offset, caplen, src_ip, dst_ip, timestamp);
            break;
        case IPPROTO_UDP:  // Protocol 17 - User Datagram Protocol
            parseUDP(packet, transport_offset, caplen, src_ip, dst_ip, timestamp);
            break;
            
        default:
            // Handle other protocols (IGMP, etc.)
            // For now, we just display basic information
            char time_str[64];
            formatTimestamp(timestamp, time_str, sizeof(time_str));
            std::cout << time_str << " " << src_ip << " -> " << dst_ip 
                     << " PROTO=" << static_cast<int>(ip_hdr->ip_p) 
                     << " len=" << ntohs(ip_hdr->ip_len) << std::endl;
            break;
    }
}

/**
 * @brief Parse TCP (Layer 4) segment header
 * 
 * Extracts TCP connection information including source/destination ports,
 * sequence numbers, and control flags. Provides detailed connection state
 * information for TCP traffic analysis and displays formatted output.
 * 
 * @param packet Pointer to the start of the complete packet buffer. The TCP
 *               header begins at (packet + offset). Maintaining access to the
 *               complete packet allows for potential future enhancements like
 *               payload inspection or TCP option analysis.
 * 
 * @param offset Byte offset from packet start where the TCP header begins.
 *               Calculated as Ethernet header size + IPv4 header size (including
 *               any IPv4 options). Typically 34 bytes for standard headers
 *               (14 Ethernet + 20 IPv4), but varies with IPv4 options.
 * 
 * @param caplen Total captured packet length from the packet pointer start.
 *               Essential for bounds checking to prevent reading beyond
 *               captured data. TCP headers can also be variable length due
 *               to TCP options (20-60 bytes).
 * 
 * @param src_ip Source IP address as a null-terminated string in dotted
 *               decimal notation (e.g., "192.168.1.100"). Pre-formatted
 *               by parseIPv4() using inet_ntop() for direct display output.
 *               Buffer must remain valid for the duration of this function.
 * 
 * @param dst_ip Destination IP address as a null-terminated string in dotted
 *               decimal notation (e.g., "10.0.0.1"). Pre-formatted by
 *               parseIPv4() for immediate use in output formatting. Buffer
 *               must remain valid throughout function execution.
 * 
 * @param timestamp Precise packet capture timestamp from kernel, propagated
 *                  through the entire parsing chain. Used for generating
 *                  human-readable timestamp strings in the final output
 *                  display. Maintains timing consistency across all protocol
 *                  layers.
 * 
 * @note TCP headers can include options making them variable length (20-60 bytes).
 *       This implementation validates the minimum header size but could be
 *       enhanced to parse TCP options for more detailed analysis.
 * 
 * @see struct tcphdr, ntohs(), formatTimestamp()
 */
void PacketParser::parseTCP(const unsigned char* packet, size_t offset, size_t caplen,
                           const char* src_ip, const char* dst_ip, const struct timeval& timestamp) {
    //TCP Header Validation
    
    // Ensure we have at least the minimum TCP header (20 bytes)
    // TCP headers can be larger due to options, but 20 bytes is the minimum
    if (offset + sizeof(struct tcphdr) > caplen) {
        // Truncated TCP header - can't safely parse
        return;
    }
    
    //TCP Header Structure (20-60 bytes)
    // Bytes 0-1:   Source Port
    // Bytes 2-3:   Destination Port
    // Bytes 4-7:   Sequence Number
    // Bytes 8-11:  Acknowledgment Number
    // Bytes 12-13: Header Length (4 bits) + Reserved (3 bits) + Flags (9 bits)
    // Bytes 14-15: Window Size
    // Bytes 16-17: Checksum
    // Bytes 18-19: Urgent Pointer
    // Bytes 20+:   Options (0-40 bytes, variable)
    
    // Cast to TCP header structure
    const struct tcphdr* tcp_hdr = reinterpret_cast<const struct tcphdr*>(packet + offset);
    
    //Extract Port Information
    
    // Convert port numbers from network byte order (big-endian) to host byte order
    // Port numbers identify the application/service (HTTP=80, HTTPS=443, SSH=22, etc.)
    uint16_t src_port = ntohs(tcp_hdr->th_sport);  // Source port
    uint16_t dst_port = ntohs(tcp_hdr->th_dport);  // Destination port
    
    //Format and Display TCP Connection Information
    
    // Generate timestamp string for this packet
    char time_str[64];
    formatTimestamp(timestamp, time_str, sizeof(time_str));
    
    // Display TCP connection: timestamp src_ip:port -> dst_ip:port TCP len=bytes
    // This format makes it easy to track TCP connections and data flow
    std::cout << time_str << " " << src_ip << ":" << src_port 
             << " -> " << dst_ip << ":" << dst_port 
             << " TCP len=" << (caplen - offset) << std::endl;
    
    // Note: We could extend this to show TCP flags (SYN, ACK, FIN, etc.)
    // and sequence numbers for detailed connection analysis
}

/**
 * @brief Parse UDP (Layer 4) datagram header
 * 
 * Extracts UDP datagram information including source/destination ports and
 * payload length. UDP parsing is simpler than TCP due to its connectionless
 * nature and fixed header size, but still provides valuable network analysis.
 * 
 * @param packet Pointer to the start of the complete packet buffer. The UDP
 *               header begins at (packet + offset). While UDP headers are
 *               fixed size, maintaining complete packet access enables
 *               potential future payload analysis or application-layer
 *               protocol identification.
 * 
 * @param offset Byte offset from packet start where the UDP header begins.
 *               Calculated as Ethernet header size + IPv4 header size.
 *               For standard headers: 34 bytes (14 Ethernet + 20 IPv4),
 *               but varies if IPv4 options are present. Always validated
 *               by bounds checking.
 * 
 * @param caplen Total captured packet length from the packet pointer start.
 *               Used for bounds checking to ensure the complete UDP header
 *               (8 bytes) is available. Unlike TCP, UDP headers are always
 *               exactly 8 bytes with no variable-length options.
 * 
 * @param src_ip Source IP address as a null-terminated string in standard
 *               dotted decimal notation (e.g., "203.0.113.1"). Pre-converted
 *               from binary format by parseIPv4() using inet_ntop() for
 *               immediate display use. Must remain valid during function
 *               execution.
 * 
 * @param dst_ip Destination IP address as a null-terminated string in dotted
 *               decimal format (e.g., "198.51.100.1"). Pre-formatted by
 *               the IPv4 parser for direct inclusion in output. The string
 *               buffer must remain accessible throughout this function's
 *               execution.
 * 
 * @param timestamp Precise kernel-provided packet capture timestamp,
 *                  propagated through all parsing layers. Contains both
 *                  seconds and microseconds components for high-precision
 *                  timing analysis. Used to generate consistent timestamp
 *                  strings across all protocol parsers.
 * 
 * @note UDP is connectionless, so no connection state tracking is performed.
 *       Each datagram is independent. The uh_ulen field includes both the
 *       8-byte UDP header and the payload length.
 * 
 * @see struct udphdr, ntohs(), formatTimestamp()
 */
void PacketParser::parseUDP(const unsigned char* packet, size_t offset, size_t caplen,
                           const char* src_ip, const char* dst_ip, const struct timeval& timestamp) {
    //UDP Header Validation
    
    // Ensure we have the complete UDP header (always 8 bytes - fixed size)
    // Unlike TCP, UDP headers are always the same size (no options)
    if (offset + sizeof(struct udphdr) > caplen) {
        // Truncated UDP header - can't safely parse
        return;
    }
    
    // UDP Header Structure (8 bytes fixed) 
    // Bytes 0-1: Source Port
    // Bytes 2-3: Destination Port
    // Bytes 4-5: Length (header + data)
    // Bytes 6-7: Checksum
    
    // Cast to UDP header structure
    const struct udphdr* udp_hdr = reinterpret_cast<const struct udphdr*>(packet + offset);
    
    //Extract Port Information
    
    // Convert port numbers from network byte order to host byte order
    // Common UDP ports: DNS=53, DHCP=67/68, SNMP=161, NTP=123
    uint16_t src_port = ntohs(udp_hdr->uh_sport);  // Source port
    uint16_t dst_port = ntohs(udp_hdr->uh_dport);  // Destination port
    
    //Format and Display UDP Datagram Information
    
    // Generate timestamp string for this packet
    char time_str[64];
    formatTimestamp(timestamp, time_str, sizeof(time_str));
    
    // Display UDP datagram: timestamp src_ip:port -> dst_ip:port UDP len=bytes
    // Use the UDP header's length field which includes header + payload
    std::cout << time_str << " " << src_ip << ":" << src_port 
             << " -> " << dst_ip << ":" << dst_port 
             << " UDP len=" << ntohs(udp_hdr->uh_ulen) << std::endl;
    
    // Note: UDP is connectionless, so no connection state to track
    // Each datagram is independent
}

/**
 * @brief Parse ICMP (Internet Control Message Protocol) header
 * 
 * Analyzes ICMP messages for network diagnostics and error reporting.
 * ICMP is used by network devices to communicate error conditions and
 * provide diagnostic information (like ping responses).
 * 
 * @param packet Complete packet buffer starting from Ethernet header
 * @param offset Byte position where ICMP header begins within the packet
 * @param caplen Total number of bytes captured from the network interface
 * @param src_ip Source IP address as null-terminated string in dotted decimal
 * @param dst_ip Destination IP address as null-terminated string
 * @param timestamp Precise packet capture time with microsecond resolution
 */
void PacketParser::parseICMP(const unsigned char* packet, size_t offset, size_t caplen,
                            const char* src_ip, const char* dst_ip, const struct timeval& timestamp) {
    //Bounds Checking
    
    // Ensure we have enough data for a complete ICMP header
    // ICMP header is 8 bytes minimum: type(1) + code(1) + checksum(2) + data(4)
    if (offset + sizeof(struct icmp) > caplen) {
        return;  // Incomplete ICMP packet, silently ignore
    }
    
    //Parse ICMP Header
    
    // Cast packet data to ICMP header structure for field access
    // This provides access to type, code, checksum, and type-specific data
    const struct icmp* icmp_hdr = reinterpret_cast<const struct icmp*>(packet + offset);
    
    //Format Timestamp for Display
    
    char time_str[64];  // Buffer for formatted timestamp string
    formatTimestamp(timestamp, time_str, sizeof(time_str));
    
    //Determine ICMP Message Type and Format Output
    
    // ICMP messages have different meanings based on the type field
    // Common types include ping (echo request/reply), unreachable, redirects
    const char* message_type;
    switch (icmp_hdr->icmp_type) {
        case ICMP_ECHOREPLY:      // Type 0 - Echo Reply (ping response)
            message_type = "Echo Reply (ping response)";
            break;
        case ICMP_UNREACH:        // Type 3 - Destination Unreachable
            message_type = "Destination Unreachable";
            break;
        case ICMP_SOURCEQUENCH:   // Type 4 - Source Quench (deprecated)
            message_type = "Source Quench";
            break;
        case ICMP_REDIRECT:       // Type 5 - Redirect Message
            message_type = "Redirect";
            break;
        case ICMP_ECHO:           // Type 8 - Echo Request (ping)
            message_type = "Echo Request (ping)";
            break;
        case ICMP_TIMXCEED:       // Type 11 - Time Exceeded (TTL expired)
            message_type = "Time Exceeded";
            break;
        case ICMP_PARAMPROB:      // Type 12 - Parameter Problem
            message_type = "Parameter Problem";
            break;
        case ICMP_TSTAMP:         // Type 13 - Timestamp Request
            message_type = "Timestamp Request";
            break;
        case ICMP_TSTAMPREPLY:    // Type 14 - Timestamp Reply
            message_type = "Timestamp Reply";
            break;
        default:
            message_type = "Unknown ICMP";
            break;
    }
    
    //Display Parsed ICMP Information
    
    // Output format: timestamp src_ip -> dst_ip ICMP message_type (type=X, code=Y) len=Z
    std::cout << time_str << " " << src_ip << " -> " << dst_ip 
             << " ICMP " << message_type 
             << " (type=" << static_cast<int>(icmp_hdr->icmp_type) 
             << ", code=" << static_cast<int>(icmp_hdr->icmp_code) << ")";
    
    // For ping packets, show additional identifier and sequence information
    if (icmp_hdr->icmp_type == ICMP_ECHO || icmp_hdr->icmp_type == ICMP_ECHOREPLY) {
        std::cout << " id=" << ntohs(icmp_hdr->icmp_id) 
                 << " seq=" << ntohs(icmp_hdr->icmp_seq);
    }
    
    std::cout << " len=" << (caplen - offset) << std::endl;
    
    // Note: ICMP checksum verification could be added here for packet validation
    // The checksum field is icmp_hdr->icmp_cksum (already in network byte order)
}

/**
 * @brief Convert kernel timestamp to human-readable format
 * 
 * Transforms high-precision kernel timestamps into human-readable date/time
 * strings with microsecond precision. Handles timezone conversion and provides
 * consistent formatting across all packet displays for easy analysis.
 * 
 * @param timestamp High-precision timestamp structure from the kernel BPF
 *                  subsystem. Contains tv_sec (seconds since Unix epoch) and
 *                  tv_usec (microseconds 0-999999). This timestamp represents
 *                  the exact moment the packet was captured by the network
 *                  interface, providing accurate timing for network analysis.
 * 
 * @param buffer Output buffer where the formatted timestamp string will be
 *               written. Must be allocated by the caller and remain valid
 *               throughout the function execution. The buffer will contain
 *               a null-terminated string in the format:
 *               "YYYY-MM-DD HH:MM:SS.UUUUUU" (26 characters + null terminator).
 * 
 * @param bufsize Size of the output buffer in bytes, including space for the
 *                null terminator. Must be at least 32 bytes to accommodate
 *                the full timestamp string (26 chars) plus null terminator
 *                and provide safety margin. Used for bounds checking to
 *                prevent buffer overflows during string operations.
 * 
 * @note The function uses localtime() for timezone conversion, so timestamps
 *       are displayed in the system's local timezone. The microsecond precision
 *       is critical for network timing analysis and troubleshooting.
 * 
 * @warning The buffer must be large enough to hold the complete formatted
 *          timestamp. Insufficient buffer size may result in truncated output.
 * 
 * @see struct timeval, localtime(), strftime(), snprintf()
 */
void PacketParser::formatTimestamp(const struct timeval& timestamp, char* buffer, size_t bufsize) {
    //Convert Seconds to Date/Time
    
    // timestamp.tv_sec contains seconds since Unix epoch (January 1, 1970)
    // localtime() converts this to broken-down time in local timezone
    struct tm* tm_info = localtime(&timestamp.tv_sec);
    
    // Format the date and time portion: "YYYY-MM-DD HH:MM:SS"
    // This provides human-readable date and time down to seconds
    strftime(buffer, bufsize, "%Y-%m-%d %H:%M:%S", tm_info);
    
    //Add Microsecond Precision
    
    // timestamp.tv_usec contains microseconds (0-999999)
    // This provides sub-second timing precision critical for network analysis
    char usec_str[16];
    snprintf(usec_str, sizeof(usec_str), ".%06d", static_cast<int>(timestamp.tv_usec));
    
    // Append microseconds to the timestamp: "YYYY-MM-DD HH:MM:SS.UUUUUU"
    // Use strncat for safe string concatenation with bounds checking
    strncat(buffer, usec_str, bufsize - strlen(buffer) - 1);
    
    // Final format example: "2025-11-01 14:30:25.123456"
    // This precision allows analysis of packet timing and network latency
}