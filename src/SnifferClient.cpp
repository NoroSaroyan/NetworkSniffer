#include "SnifferClient.h"
#include <QDebug>
#include <stdexcept>

SnifferClient::SnifferClient(QObject* parent)
    : QObject(parent), socket_(new QTcpSocket(this)) {

    connect(socket_, &QTcpSocket::connected, this, &SnifferClient::onConnected);
    connect(socket_, &QTcpSocket::disconnected, this, &SnifferClient::onDisconnected);
    connect(socket_, &QTcpSocket::readyRead, this, &SnifferClient::onReadyRead);
    connect(socket_, QOverload<QAbstractSocket::SocketError>::of(&QAbstractSocket::errorOccurred),
            this, &SnifferClient::onError);
}

SnifferClient::~SnifferClient() {
    if (socket_->state() == QAbstractSocket::ConnectedState) {
        socket_->disconnectFromHost();
    }
}

void SnifferClient::connectToServer(const QString& host, quint16 port) {
    qDebug() << "Connecting to" << host << ":" << port;
    socket_->connectToHost(host, port);
}

void SnifferClient::disconnect() {
    if (socket_->state() == QAbstractSocket::ConnectedState) {
        socket_->disconnectFromHost();
    }
}

bool SnifferClient::isConnected() const {
    return socket_->state() == QAbstractSocket::ConnectedState;
}

void SnifferClient::onConnected() {
    qDebug() << "[GUI] Connected to server";

    // Send CLIENT_HELLO to identify as GUI client
    json hello;
    hello["type"] = "gui";
    hello["hostname"] = "Qt GUI Client";

    std::string payload = hello.dump();

    uint8_t header[4];
    header[0] = PROTOCOL_VERSION;
    header[1] = TYPE_CLIENT_HELLO;
    header[2] = (payload.length() >> 8) & 0xFF;
    header[3] = payload.length() & 0xFF;

    qint64 bytes_written = 0;
    bytes_written += socket_->write(QByteArray((const char*)header, 4));
    bytes_written += socket_->write(QByteArray(payload.c_str(), payload.length()));
    bytes_written += socket_->write(QByteArray((const char*)&TERM_BYTE, 1));

    qDebug() << "[GUI] Sent CLIENT_HELLO, bytes written:" << bytes_written;
    socket_->flush();

    emit connected();
}

void SnifferClient::onDisconnected() {
    qDebug() << "Disconnected from server";
    read_buffer_.clear();
    emit disconnected();
}

void SnifferClient::onReadyRead() {
    QByteArray data = socket_->readAll();
    qDebug() << "[GUI] Received" << data.size() << "bytes from server";
    read_buffer_.append(data);

    Frame frame;
    int frame_count = 0;
    while (readFrame(frame)) {
        frame_count++;
        qDebug() << "[GUI] Processing frame" << frame_count << "type:" << (int)frame.type;
        processFrame(frame);
    }
}

void SnifferClient::onError(QAbstractSocket::SocketError error) {
    QString errorString = socket_->errorString();
    qDebug() << "Socket error:" << errorString;
    emit connectionError(errorString);
}

bool SnifferClient::readFrame(Frame& frame) {
    const int HEADER_SIZE = 4;

    if (read_buffer_.size() < HEADER_SIZE) {
        return false;
    }

    uint8_t version = static_cast<uint8_t>(read_buffer_[0]);
    if (version != PROTOCOL_VERSION) {
        qWarning() << "Invalid protocol version:" << version;
        read_buffer_.clear();
        return false;
    }

    frame.type = static_cast<uint8_t>(read_buffer_[1]);
    uint16_t length = (static_cast<uint8_t>(read_buffer_[2]) << 8) |
                      static_cast<uint8_t>(read_buffer_[3]);

    if (length > 1024) {
        qWarning() << "Payload too large:" << length;
        read_buffer_.clear();
        return false;
    }

    int total_size = HEADER_SIZE + length + 1;
    if (read_buffer_.size() < total_size) {
        return false;
    }

    frame.payload = read_buffer_.mid(HEADER_SIZE, length);

    uint8_t term = static_cast<uint8_t>(read_buffer_[HEADER_SIZE + length]);
    if (term != TERM_BYTE) {
        qWarning() << "Invalid terminator byte:" << term;
        read_buffer_.clear();
        return false;
    }

    read_buffer_.remove(0, total_size);
    return true;
}

void SnifferClient::processFrame(const Frame& frame) {
    try {
        qDebug() << "Received frame type:" << (int)frame.type;

        if (frame.type == TYPE_FORWARD_LOG) {
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
        } else if (frame.type == TYPE_ERROR) {
            qWarning() << "Received error frame:" << frame.payload;
        } else {
            qDebug() << "Received frame type:" << (int)frame.type << "(not FORWARD_LOG)";
        }
    } catch (const std::exception& e) {
        qWarning() << "Error processing frame:" << e.what();
    }
}
