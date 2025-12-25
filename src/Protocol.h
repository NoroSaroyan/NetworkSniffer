
#pragma once

#include <cstdint>
#include <string>

/**
 * @namespace Protocol
 * @brief Binary protocol definitions for sniffer communication
 * @file Protocol.h
 *
 *
 *
 * @brief Binary protocol specification for network sniffer communication
 *
 * Defines the binary frame format and message types used for communication
 * between sniffer clients, the central server, and GUI clients.
 *
 * Frame Format
 *
 * All messages use a consistent binary frame envelope:
 * ```
 * [Version:1][Type:1][Length:2 BE][Payload:N][Terminator:1]
 * ```
 *
 * - **Version** (1 byte): Protocol version (currently 0x01)
 *   * Enables future protocol upgrades (0x02, 0x03, etc.)
 *   * Server can reject incompatible clients
 *   * Future-proofs against version mismatches
 *
 * - **Type** (1 byte): Message type (CLIENT_HELLO, SERVER_HELLO, etc.)
 *   * Discriminator for different message kinds
 *   * Server knows how to route based on type
 *   * Extensible: can add new types without breaking old clients
 *
 * - **Length** (2 bytes, big-endian): Payload size in bytes
 *   * WHY 2 bytes (16-bit)? Max value = 65535
 *   * We limit to 1024, so could use 1 byte, but:
 *     - 2 bytes standard for network protocols (TCP, HTTP, etc.)
 *     - Easier to extend later if needed
 *     - Network byte order (big-endian) is standard
 *   * WHY big-endian? (network byte order)
 *     - TCP/IP standard (internet uses big-endian)
 *     - htons(), ntohs() functions convert to/from native order
 *     - Portable across architectures
 *
 * - **Payload** (N bytes): JSON-encoded message data
 *   * Human-readable debugging (can print JSON easily)
 *   * Flexible structure (no strict binary layout needed)
 *   * Trade-off: larger than pure binary encoding
 *   * Alternative protocols: Protocol Buffers, MessagePack (more compact)
 *
 * - **Terminator** (1 byte): Frame end marker (0x0A, ASCII line feed)
 *   * DEFENSE-IN-DEPTH: validates frame boundaries
 *   * Provides redundant checking alongside Length field
 *   * If Length corrupted: terminator check catches corruption
 *   * If terminator missing: parser knows frame is incomplete
 *   * WHY 0x0A not 0x00?
 *     - 0x00 (null) could appear in JSON strings
 *     - 0x0A (LF) unlikely in JSON payload (JSON uses \n escape)
 *     - Also human-readable: \n matches typical line endings
 *
 * ## Frame Design Philosophy
 *
 * ### Redundant Validation
 * Both Length field and Terminator byte validate frame boundaries:
 * - Length tells exact payload size
 * - Terminator marks frame end
 * If either is corrupted, parsing detects it and fails safely
 *
 * ### Extensibility
 * New message types can be added without breaking old code:
 * - Unknown type codes are simply ignored
 * - New fields in JSON are optional
 * - Version byte allows breaking changes if needed
 *
 * ### Robustness
 * The design handles common network failures:
 * - Partial reads: readExact() loops until frame complete
 * - Corruption: version, length, and terminator checks
 * - Alignment: binary format avoids struct packing issues
 * - Endianness: explicit big-endian avoids architecture differences
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
 *   - Sent for EVERY captured packet (per-packet granularity)
 *
 * - **FORWARD_LOG (0x04)**: Server broadcasts logs to GUI clients
 *   - `{"ssid":1, "log":{packet JSON}}`
 *   - Wraps TRAFFIC_LOG with sniffer SSID for GUI identification
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
 *      |  |  |  |  Payload: {"name":"test"}   |  Terminator (0x0A)
 *      |  |  |  Length: 0x0025 (37 bytes)     |
 *      |  |  Type: 0x01 (CLIENT_HELLO)        |
 *      |  Version: 0x01                        |
 *      Total frame: 5 (header) + 37 (payload) + 1 (terminator) = 43 bytes
 * ```
 *
 * @see server.cpp for server-side implementation
 * @see SnifferClient.h for GUI client implementation
 * @see Sniffer.h for sniffer client implementation
 */
namespace Protocol {

    // ========================================================================
    // Frame Format Constants
    // ========================================================================

    /// Protocol version byte (0x01)
    /// Value 0x01 is arbitrary - could be any number.
    /// Changing this number forces protocol version bump.
    /// Used to detect version mismatches between clients and server.
    /// Servers should reject frames with VERSION != 0x01
    /// When protocol design changes (e.g., new field structure),
    /// increment to 0x02, 0x03, etc. for forward compatibility.
    constexpr uint8_t VERSION = 0x01;

    /// Frame terminator byte (0x0A = ASCII line feed '\n')
    /// Marks end of frame for defense-in-depth validation.
    /// Provides redundancy alongside the Length field.
    /// Chosen as 0x0A because:
    /// - Rare in UTF-8 JSON (appears as \\n escape, not raw byte)
    /// - Human-readable: line feed has semantic meaning
    /// - Standard in text protocols (HTTP uses \r\n)
    /// Without this byte: single Length field corruption breaks parser.
    /// With this byte: parser detects missing/corrupt terminator.
    constexpr uint8_t TERM_BYTE = 0x0A;

    /// Maximum payload size in bytes (1024 = 1 KB)
    /// This is a DESIGN CHOICE with trade-offs:
    /// - Simplicity: fixed 1KB limit avoids unbounded allocations
    /// - Safety: prevents DoS via huge payloads
    /// - Sufficient: JSON-serialized packet ~150-300 bytes
    /// - Conservative: could likely increase to 8KB or 64KB
    /// Trade-off: Cannot send single frame >1KB (would need fragmentation)
    /// In practice: Each captured packet is <1500 bytes,
    /// JSON overhead is ~100-200 bytes, so 1024 is comfortable.
    /// If you needed larger payloads, would need:
    /// 1. Increase this constant
    /// 2. Change Length field from 2 bytes (16-bit) to 3-4 bytes if >64KB needed
    /// 3. Update all frame parsing code
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
