/**
 * @file SnifferClient.h
 * @brief Qt GUI client for receiving network traffic logs from sniffer server
 *
 * SnifferClient connects to a running SnifferServer instance and receives
 * FORWARD_LOG frames containing network traffic data captured by remote
 * packet sniffers. This client is used by the Qt GUI (MainWindow) to display
 * real-time network traffic organized by Sniffer Session ID (SSID).
 *
 * ## Protocol Communication
 *
 * The client follows this sequence:
 * 1. Connect to server via connectToServer()
 * 2. On connection, automatically send CLIENT_HELLO to identify as GUI
 * 3. Receive SERVER_HELLO with assigned SSID
 * 4. Continuously receive FORWARD_LOG frames from sniffers
 * 5. Emit forwardLogReceived() signal for each log
 *
 * ## Binary Frame Format
 *
 * All messages use: [Version:1][Type:1][Length:2][Payload:N][Terminator:1]
 *
 * Message Types:
 * - 0x01 CLIENT_HELLO: Introduce GUI client to server (sent by client)
 * - 0x02 SERVER_HELLO: Server acknowledgment with SSID (received by client)
 * - 0x04 FORWARD_LOG: Traffic log from sniffer (received by client)
 * - 0x05 ERROR: Error notification (received by client)
 *
 * ## Example Usage
 *
 * ```cpp
 * SnifferClient* client = new SnifferClient(this);
 * connect(client, &SnifferClient::forwardLogReceived, this, &MyClass::onLogReceived);
 * client->connectToServer("127.0.0.1", 9090);
 * ```
 *
 * @see MainWindow for GUI integration example
 */

#pragma once

#include <QObject>
#include <QTcpSocket>
#include <QByteArray>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

/**
 * @class SnifferClient
 * @brief Qt client for receiving filtered network traffic logs from sniffer server
 *
 * This is an asynchronous Qt client that connects to a SnifferServer instance
 * and continuously receives FORWARD_LOG frames containing network traffic data.
 * All communication is handled through Qt signals and slots, making it suitable
 * for GUI applications.
 *
 * The client automatically handles the protocol handshake (CLIENT_HELLO and
 * SERVER_HELLO) upon connection.
 */
class SnifferClient : public QObject {
    Q_OBJECT

public:
    /**
     * @brief Construct a new SnifferClient instance
     * @param parent Qt parent object (for automatic memory management)
     */
    explicit SnifferClient(QObject* parent = nullptr);

    /**
     * @brief Destructor - ensures socket is properly disconnected
     *
     * Automatically disconnects from server if connected and cleans up resources.
     */
    ~SnifferClient() override;

    /**
     * @brief Initiate connection to sniffer server
     *
     * Asynchronously connects to the specified server. When the connection
     * is established, the onConnected() slot is triggered, which automatically
     * sends a CLIENT_HELLO frame to identify this as a GUI client.
     *
     * @param host Server hostname or IP address (e.g., "127.0.0.1" or "localhost")
     * @param port Server port number (typically 9090)
     *
     * @see connected() - emitted when connection is established
     * @see connectionError() - emitted if connection fails
     */
    void connectToServer(const QString& host, quint16 port);

    /**
     * @brief Disconnect from the sniffer server
     *
     * Gracefully disconnects from the server if currently connected.
     * Triggers the disconnected() signal and clears the read buffer.
     *
     * @see disconnected() - emitted when disconnection is complete
     */
    void disconnect();

    /**
     * @brief Check if currently connected to server
     * @return true if socket is in ConnectedState, false otherwise
     */
    bool isConnected() const;

signals:
    /**
     * @brief Emitted when successfully connected to server
     *
     * This signal is emitted after TCP connection is established and the
     * CLIENT_HELLO handshake has been sent. The server responds with SERVER_HELLO
     * containing the assigned SSID.
     */
    void connected();

    /**
     * @brief Emitted when disconnected from server
     *
     * This signal is emitted after the TCP connection has been closed or lost.
     * The read buffer is cleared before this signal is emitted.
     */
    void disconnected();

    /**
     * @brief Emitted when a connection error occurs
     * @param error Human-readable error message describing what went wrong
     *
     * Possible errors include:
     * - "Connection refused" - server not running on specified port
     * - "Network unreachable" - host not reachable
     * - "Connection reset by peer" - server disconnected unexpectedly
     */
    void connectionError(const QString& error);

    /**
     * @brief Emitted when a FORWARD_LOG frame is received from a sniffer
     *
     * This signal carries a complete network traffic log parsed from FORWARD_LOG.
     * The JSON log contains fields like:
     * - timestamp: When packet was captured
     * - src: Source IP address
     * - dst: Destination IP address
     * - src_port: Source port (if applicable)
     * - dst_port: Destination port (if applicable)
     * - protocol: Protocol name (TCP, UDP, ICMP, etc.)
     * - length: Packet size in bytes
     *
     * @param ssid Sniffer Session ID - unique identifier for the source sniffer
     * @param log JSON object containing the traffic data
     *
     * @see MainWindow::onForwardLogReceived() for GUI integration example
     */
    void forwardLogReceived(uint32_t ssid, const json& log);

private slots:
    /**
     * @brief [Qt Slot] Called when TCP connection is successfully established
     *
     * This slot is called automatically by Qt when the TCP socket transitions
     * to ConnectedState. It performs the following:
     * 1. Constructs CLIENT_HELLO JSON with type="gui"
     * 2. Wraps it in binary frame format
     * 3. Sends to server for registration
     * 4. Emits connected() signal
     *
     * @internal
     * @note This is an internal Qt slot, not meant to be called directly
     */
    void onConnected();

    /**
     * @brief [Qt Slot] Called when disconnected from server
     *
     * Clears the read buffer and emits the disconnected() signal.
     *
     * @internal
     * @note This is an internal Qt slot, not meant to be called directly
     */
    void onDisconnected();

    /**
     * @brief [Qt Slot] Called when data is available to read from socket
     *
     * Reads all available data from socket, appends to read buffer, and attempts
     * to parse complete frames. For each valid frame parsed, calls processFrame().
     *
     * @internal
     * @note This is an internal Qt slot, not meant to be called directly
     */
    void onReadyRead();

    /**
     * @brief [Qt Slot] Called when a socket error occurs
     * @param error Qt socket error enum value
     *
     * Converts the error to a human-readable string and emits connectionError() signal.
     *
     * @internal
     * @note This is an internal Qt slot, not meant to be called directly
     */
    void onError(QAbstractSocket::SocketError error);

private:
    /**
     * @struct Frame
     * @brief Parsed binary frame received from server socket
     *
     * Represents a single complete frame after parsing from the binary format.
     */
    struct Frame {
        uint8_t type;           ///< Message type (SERVER_HELLO, FORWARD_LOG, ERROR, etc.)
        QByteArray payload;     ///< Raw payload data (typically JSON string)
    };

    /**
     * @brief Parse a complete binary frame from read buffer
     *
     * Attempts to read one complete frame from read_buffer_. A complete frame is:
     * [Version:1][Type:1][Length:2][Payload:N][Terminator:1]
     *
     * Validates:
     * - Protocol version matches PROTOCOL_VERSION
     * - Payload size is reasonable (< 1024 bytes)
     * - Frame is properly terminated with TERM_BYTE
     *
     * If a valid frame is found, it's removed from read_buffer_ and parsed into frame.
     *
     * @param[out] frame Parsed frame (populated on success)
     * @return true if a valid complete frame was parsed, false if incomplete or invalid
     *
     * @internal
     */
    bool readFrame(Frame& frame);

    /**
     * @brief Process a parsed frame received from server
     *
     * Dispatches frame based on type:
     * - TYPE_SERVER_HELLO: Acknowledgment of CLIENT_HELLO (not typically used by GUI)
     * - TYPE_FORWARD_LOG: Traffic log from sniffer - parse JSON and emit forwardLogReceived()
     * - TYPE_ERROR: Error message from server - log to debug output
     * - Others: Log and ignore
     *
     * @param frame Parsed frame to process
     *
     * @internal
     */
    void processFrame(const Frame& frame);

    QTcpSocket* socket_;            ///< TCP socket for server communication
    QByteArray read_buffer_;        ///< Accumulator for partial frame data

    // Protocol constants - must match server.cpp definitions
    static constexpr uint8_t PROTOCOL_VERSION = 0x01;   ///< Current protocol version
    static constexpr uint8_t TYPE_CLIENT_HELLO = 0x01;  ///< Client introduction message
    static constexpr uint8_t TYPE_SERVER_HELLO = 0x02;  ///< Server acknowledgment with SSID
    static constexpr uint8_t TYPE_TRAFFIC_LOG = 0x03;   ///< Traffic data from sniffer
    static constexpr uint8_t TYPE_FORWARD_LOG = 0x04;   ///< Forwarded log to GUI client
    static constexpr uint8_t TYPE_ERROR = 0x05;         ///< Error notification
    static constexpr uint8_t TERM_BYTE = 0x0A;          ///< Frame terminator (newline)
};
