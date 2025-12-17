/**
 * @file Protocol.h
 * @brief Binary protocol specification for network sniffer communication
 *
 * Defines the binary frame format and message types used for communication
 * between sniffer clients, the central server, and GUI clients.
 *
 * ## Frame Format
 *
 * All messages use a consistent binary frame envelope:
 * ```
 * [Version:1][Type:1][Length:2 BE][Payload:N][Terminator:1]
 * ```
 *
 * - **Version** (1 byte): Protocol version (currently 0x01)
 * - **Type** (1 byte): Message type (CLIENT_HELLO, SERVER_HELLO, etc.)
 * - **Length** (2 bytes, big-endian): Payload size in bytes
 * - **Payload** (N bytes): JSON-encoded message data
 * - **Terminator** (1 byte): Frame end marker (0x0A)
 *
 * ## Message Types
 *
 * - **CLIENT_HELLO (0x01)**: Client introduces itself on connection
 *   - Sniffer: `{"hostname":"...", "interface":"eth0"}`
 *   - GUI: `{"type":"gui", "hostname":"..."}`
 *
 * - **SERVER_HELLO (0x02)**: Server acknowledges client and assigns SSID
 *   - `{"ssid":1, "ip":"192.168.1.1", "registered":true}`
 *
 * - **TRAFFIC_LOG (0x03)**: Sniffer sends captured packet data
 *   - `{packet JSON with "timestamp", "protocol", "src", "dst", ...}`
 *
 * - **FORWARD_LOG (0x04)**: Server broadcasts logs to GUI clients
 *   - `{"ssid":1, "log":{packet JSON}}`
 *
 * - **ERROR (0x05)**: Error notification
 *   - `{"error":"description"}`
 *
 * ## Example Frame
 *
 * ```
 * Hex: 01 01 00 25 7B226e616d65223a227465737422 7D 0A
 *      |  |  |  |  |                           |  |
 *      V  V  V  V  V                           V  V
 *      |  |  |  |  Payload: {"name":"test"}   |  Terminator
 *      |  |  |  Length: 0x0025 (37 bytes)     |
 *      |  |  Type: 0x01 (CLIENT_HELLO)
 *      |  Version: 0x01
 * ```
 *
 * @see server.cpp for server-side implementation
 * @see SnifferClient.h for GUI client implementation
 * @see Sniffer.h for sniffer client implementation
 */

#pragma once

#include <cstdint>
#include <string>

/**
 * @namespace Protocol
 * @brief Binary protocol definitions for sniffer communication
 */
namespace Protocol {

    // ========================================================================
    // Frame Format Constants
    // ========================================================================

    /// Protocol version byte
    constexpr uint8_t VERSION = 0x01;

    /// Frame terminator byte (line feed)
    constexpr uint8_t TERM_BYTE = 0x0A;

    /// Maximum payload size in bytes
    constexpr size_t MAX_PAYLOAD_SIZE = 1024;

    // ========================================================================
    // Message Types
    // ========================================================================

    /// Message type enumeration
    enum MessageType : uint8_t {
        /// Client introduces itself (sniffer or GUI)
        CLIENT_HELLO = 0x01,

        /// Server responds with assigned SSID
        SERVER_HELLO = 0x02,

        /// Sniffer sends captured packet data
        TRAFFIC_LOG = 0x03,

        /// Server forwards logs to GUI clients
        FORWARD_LOG = 0x04,

        /// Error notification
        ERROR = 0x05
    };

    // ========================================================================
    // Frame Structure
    // ========================================================================

    /**
     * @struct Frame
     * @brief Represents a parsed binary protocol frame
     *
     * This struct is used after a binary frame has been parsed from
     * the byte stream. It separates the message type from the payload
     * for easier handling by application code.
     */
    struct Frame {
        /// Message type (see MessageType enum)
        uint8_t type;

        /// JSON payload as UTF-8 string
        std::string payload;
    };

    // ========================================================================
    // Sniffer Session ID (SSID)
    // ========================================================================

    /// Special SSID value indicating unassigned client
    constexpr uint32_t SSID_UNASSIGNED = 0;

} // namespace Protocol
