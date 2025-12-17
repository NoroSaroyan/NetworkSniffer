/**
 * @file SnifferClient.cpp
 * @brief Implementation of Qt GUI client for receiving network traffic logs
 *
 * This implementation handles:
 * - Asynchronous TCP socket management via Qt signals/slots
 * - Binary frame parsing and validation
 * - Protocol handshake (CLIENT_HELLO/SERVER_HELLO)
 * - Reception and processing of FORWARD_LOG frames containing traffic data
 */

#include "SnifferClient.h"
#include <QDebug>
#include <stdexcept>
#include <sys/socket.h>

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

/**
 * @brief Construct SnifferClient and connect all signals/slots
 *
 * Initializes the QTcpSocket and connects its signals to our slots:
 * - QTcpSocket::connected -> onConnected() - triggers CLIENT_HELLO handshake
 * - QTcpSocket::disconnected -> onDisconnected() - cleanup on disconnect
 * - QTcpSocket::readyRead -> onReadyRead() - parse incoming frames
 * - QTcpSocket::errorOccurred -> onError() - handle socket errors
 *
 * @param parent Qt parent object for memory management
 */
SnifferClient::SnifferClient(QObject* parent)
    : QObject(parent), socket_(new QTcpSocket(this)) {

    connect(socket_, &QTcpSocket::connected, this, &SnifferClient::onConnected);
    connect(socket_, &QTcpSocket::disconnected, this, &SnifferClient::onDisconnected);
    connect(socket_, &QTcpSocket::readyRead, this, &SnifferClient::onReadyRead);
    connect(socket_, QOverload<QAbstractSocket::SocketError>::of(&QAbstractSocket::errorOccurred),
            this, &SnifferClient::onError);
}

/**
 * @brief Destructor - ensures graceful disconnect
 *
 * If socket is currently connected, sends a disconnect request to the server.
 * Qt will automatically delete the socket_ member (since it's a child of this).
 */
SnifferClient::~SnifferClient() {
    if (socket_->state() == QAbstractSocket::ConnectedState) {
        socket_->disconnectFromHost();
    }
}

// ============================================================================
// PUBLIC INTERFACE
// ============================================================================

/**
 * @brief Initiate asynchronous connection to sniffer server
 *
 * Starts a non-blocking TCP connection attempt. When the connection succeeds,
 * the Qt event loop will call onConnected(), which sends CLIENT_HELLO.
 * If connection fails, onError() is called.
 *
 * @param host Server hostname/IP (e.g., "127.0.0.1", "localhost", "192.168.1.1")
 * @param port Server port number (typically 9090)
 *
 * @example
 * ```cpp
 * client->connectToServer("127.0.0.1", 9090);
 * // Later: connected() signal emitted, then frames start arriving
 * ```
 *
 * @see onConnected() - called automatically on successful connection
 * @see connectionError() - emitted if connection fails
 */
void SnifferClient::connectToServer(const QString& host, quint16 port) {
    qDebug() << "Connecting to" << host << ":" << port;
    socket_->connectToHost(host, port);
}

/**
 * @brief Disconnect from sniffer server
 *
 * If currently connected, sends disconnect request to server and clears
 * the read buffer. The disconnected() signal will be emitted when complete.
 */
void SnifferClient::disconnect() {
    if (socket_->state() == QAbstractSocket::ConnectedState) {
        socket_->disconnectFromHost();
    }
}

/**
 * @brief Check connection status
 * @return true if socket is in ConnectedState, false otherwise
 */
bool SnifferClient::isConnected() const {
    return socket_->state() == QAbstractSocket::ConnectedState;
}

// ============================================================================
// QT SLOTS (Signal Handlers)
// ============================================================================

/**
 * @brief [Qt Slot] Handle successful TCP connection to server
 *
 * Called automatically by Qt when TCP socket reaches ConnectedState.
 * Performs the CLIENT_HELLO handshake:
 *
 * 1. Construct CLIENT_HELLO JSON with type="gui" and hostname="Qt GUI Client"
 * 2. Encode into binary frame: [Protocol::VERSION][Protocol::CLIENT_HELLO][Length][Payload][Protocol::TERM_BYTE]
 * 3. Write frame to socket
 * 4. Flush socket to ensure data is sent
 * 5. Emit connected() signal
 *
 * After this, server will respond with SERVER_HELLO containing the assigned SSID,
 * and then begin sending FORWARD_LOG frames.
 *
 * @see onReadyRead() - called when server sends frames back
 */
void SnifferClient::onConnected() {
    qDebug() << "[GUI] Connected to server";

    // ================================================================
    // STEP 1: Construct CLIENT_HELLO payload
    // ================================================================
    json hello;
    hello["type"] = "gui";
    hello["hostname"] = "Qt GUI Client";
    std::string payload = hello.dump();

    // ================================================================
    // STEP 2: Build binary frame header
    // ================================================================
    // Frame format: [Version:1][Type:1][Length:2][Payload:N][Terminator:1]
    uint8_t header[4];
    header[0] = Protocol::VERSION;
    header[1] = Protocol::CLIENT_HELLO;
    header[2] = (payload.length() >> 8) & 0xFF;  // High byte of length
    header[3] = payload.length() & 0xFF;         // Low byte of length

    // ================================================================
    // STEP 3: Write frame to socket
    // ================================================================
    qint64 bytes_written = 0;
    bytes_written += socket_->write(QByteArray((const char*)header, 4));
    bytes_written += socket_->write(QByteArray(payload.c_str(), payload.length()));
    bytes_written += socket_->write(QByteArray((const char*)&Protocol::TERM_BYTE, 1));

    qDebug() << "[GUI] Sent CLIENT_HELLO, bytes written:" << bytes_written;
    socket_->flush();

    emit connected();
}

/**
 * @brief [Qt Slot] Handle disconnect from server
 *
 * Called automatically by Qt when socket disconnects (gracefully or due to error).
 * Clears the read buffer (partial frames are discarded) and emits disconnected() signal.
 */
void SnifferClient::onDisconnected() {
    qDebug() << "Disconnected from server";
    read_buffer_.clear();
    emit disconnected();
}

/**
 * @brief [Qt Slot] Handle incoming data from server socket
 *
 * Called automatically by Qt when data arrives on the socket. Performs:
 * 1. Read all available data from socket
 * 2. Append to read_buffer_ accumulator
 * 3. Loop: Try to parse complete frames from read_buffer_
 * 4. For each complete frame: call processFrame()
 *
 * The loop continues while readFrame() returns true (complete frame available).
 * When read_buffer_ has partial data (incomplete frame), readFrame() returns false
 * and we wait for more data.
 */
void SnifferClient::onReadyRead() {
    QByteArray data = socket_->readAll();
    qDebug() << "[GUI] Received" << data.size() << "bytes from server";
    read_buffer_.append(data);

    // ================================================================
    // Process all complete frames in buffer
    // ================================================================
    Frame frame;
    int frame_count = 0;
    while (readFrame(frame)) {
        frame_count++;
        qDebug() << "[GUI] Processing frame" << frame_count << "type:" << (int)frame.type;
        processFrame(frame);
    }
}

/**
 * @brief [Qt Slot] Handle socket error
 *
 * Called automatically by Qt when a socket error occurs (connection refused,
 * network unreachable, connection reset, etc.). Converts error to human-readable
 * string and emits connectionError() signal for GUI to display to user.
 *
 * @param error Qt socket error code
 */
void SnifferClient::onError(QAbstractSocket::SocketError error) {
    QString errorString = socket_->errorString();
    qDebug() << "Socket error:" << errorString;
    emit connectionError(errorString);
}

// ============================================================================
// PRIVATE METHODS
// ============================================================================

/**
 * @brief Parse a single complete binary frame from read_buffer_
 *
 * Binary frame format: [Version:1][Type:1][Length:2][Payload:N][Terminator:1]
 *
 * Returns false if:
 * - Buffer has fewer than HEADER_SIZE (4) bytes (incomplete frame)
 * - Protocol version doesn't match Protocol::VERSION (protocol mismatch)
 * - Payload length > 1024 (invalid/corrupted)
 * - Buffer has fewer bytes than needed for complete frame (still incomplete)
 * - Terminator byte doesn't match Protocol::TERM_BYTE (corrupted)
 *
 * On success:
 * - Parses frame.type and frame.payload
 * - Removes parsed frame from read_buffer_
 * - Returns true
 *
 * On failure:
 * - If malformed (bad version, too large, bad terminator), clears buffer
 * - If incomplete, leaves buffer intact for more data
 * - Returns false
 *
 * @param[out] frame Parsed frame (populated on success)
 * @return true if a valid complete frame was parsed, false if incomplete/invalid
 */
bool SnifferClient::readFrame(Frame& frame) {
    const int HEADER_SIZE = 4;

    // ================================================================
    // STEP 1: Check if we have enough data for header
    // ================================================================
    if (read_buffer_.size() < HEADER_SIZE) {
        return false;  // Incomplete - wait for more data
    }

    // ================================================================
    // STEP 2: Validate protocol version
    // ================================================================
    uint8_t version = static_cast<uint8_t>(read_buffer_[0]);
    if (version != Protocol::VERSION) {
        qWarning() << "Invalid protocol version:" << version;
        read_buffer_.clear();  // Corrupted - discard everything
        return false;
    }

    // ================================================================
    // STEP 3: Extract frame type and payload length
    // ================================================================
    frame.type = static_cast<uint8_t>(read_buffer_[1]);
    uint16_t length = (static_cast<uint8_t>(read_buffer_[2]) << 8) |
                      static_cast<uint8_t>(read_buffer_[3]);

    // ================================================================
    // STEP 4: Validate payload length
    // ================================================================
    if (length > 1024) {
        qWarning() << "Payload too large:" << length;
        read_buffer_.clear();  // Corrupted - discard everything
        return false;
    }

    // ================================================================
    // STEP 5: Check if we have the complete frame (header + payload + terminator)
    // ================================================================
    int total_size = HEADER_SIZE + length + 1;  // +1 for Protocol::TERM_BYTE
    if (read_buffer_.size() < total_size) {
        return false;  // Incomplete - wait for more data
    }

    // ================================================================
    // STEP 6: Extract payload
    // ================================================================
    frame.payload = read_buffer_.mid(HEADER_SIZE, length);

    // ================================================================
    // STEP 7: Validate terminator byte
    // ================================================================
    uint8_t term = static_cast<uint8_t>(read_buffer_[HEADER_SIZE + length]);
    if (term != Protocol::TERM_BYTE) {
        qWarning() << "Invalid terminator byte:" << term;
        read_buffer_.clear();  // Corrupted - discard everything
        return false;
    }

    // ================================================================
    // STEP 8: Remove parsed frame from buffer and return success
    // ================================================================
    read_buffer_.remove(0, total_size);
    return true;
}

/**
 * @brief Dispatch a parsed frame to appropriate handler based on type
 *
 * Frame types:
 * - Protocol::FORWARD_LOG (0x04): Traffic log from sniffer for GUI display
 *   - Parses JSON containing ssid and log fields
 *   - Emits forwardLogReceived() signal
 *   - GUI will organize logs by ssid in tabs
 *
 * - Protocol::SERVER_HELLO (0x02): Server acknowledgment (usually handled by server)
 *   - Contains assigned SSID for this connection
 *   - Logged but not used by GUI
 *
 * - Protocol::ERROR (0x05): Error message from server
 *   - Logged as warning
 *   - Payload contains error description
 *
 * - Others: Logged and ignored
 *
 * @param frame Parsed frame to process
 *
 * @note Exceptions during JSON parsing are caught and logged
 */
void SnifferClient::processFrame(const Frame& frame) {
    try {
        qDebug() << "Received frame type:" << (int)frame.type;

        if (frame.type == Protocol::FORWARD_LOG) {
            // ================================================================
            // FORWARD_LOG: Traffic log from sniffer for GUI display
            // ================================================================
            qDebug() << "Processing FORWARD_LOG frame";
            json payload = json::parse(frame.payload.toStdString());

            if (payload.contains("ssid") && payload.contains("log")) {
                uint32_t ssid = payload["ssid"];
                json log = payload["log"];

                qDebug() << "Emitting log for SSID:" << ssid;
                emit forwardLogReceived(ssid, log);
            } else {
                qDebug() << "Frame missing ssid or log fields";
            }
        } else if (frame.type == Protocol::ERROR) {
            // ================================================================
            // ERROR: Error notification from server
            // ================================================================
            qWarning() << "Received error frame:" << frame.payload;
        } else {
            // ================================================================
            // OTHER: Unexpected frame type
            // ================================================================
            qDebug() << "Received frame type:" << (int)frame.type << "(not FORWARD_LOG)";
        }
    } catch (const std::exception& e) {
        qWarning() << "Error processing frame:" << e.what();
    }
}
