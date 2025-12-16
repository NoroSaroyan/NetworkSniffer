#pragma once

#include <QObject>
#include <QTcpSocket>
#include <QByteArray>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

class SnifferClient : public QObject {
    Q_OBJECT

public:
    explicit SnifferClient(QObject* parent = nullptr);
    ~SnifferClient() override;

    void connectToServer(const QString& host, quint16 port);
    void disconnect();
    bool isConnected() const;

signals:
    void connected();
    void disconnected();
    void connectionError(const QString& error);
    void forwardLogReceived(uint32_t ssid, const json& log);

private slots:
    void onConnected();
    void onDisconnected();
    void onReadyRead();
    void onError(QAbstractSocket::SocketError error);

private:
    struct Frame {
        uint8_t type;
        QByteArray payload;
    };

    bool readFrame(Frame& frame);
    void processFrame(const Frame& frame);

    QTcpSocket* socket_;
    QByteArray read_buffer_;

    static constexpr uint8_t PROTOCOL_VERSION = 0x01;
    static constexpr uint8_t TYPE_CLIENT_HELLO = 0x01;
    static constexpr uint8_t TYPE_SERVER_HELLO = 0x02;
    static constexpr uint8_t TYPE_TRAFFIC_LOG = 0x03;
    static constexpr uint8_t TYPE_FORWARD_LOG = 0x04;
    static constexpr uint8_t TYPE_ERROR = 0x05;
    static constexpr uint8_t TERM_BYTE = 0x0A;
};
