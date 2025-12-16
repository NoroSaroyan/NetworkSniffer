#include "MainWindow.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QMessageBox>
#include <QDateTime>
#include <QFont>

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent), client_(new SnifferClient(this)) {

    setupUI();

    connect(client_, &SnifferClient::connected, this, &MainWindow::onClientConnected);
    connect(client_, &SnifferClient::disconnected, this, &MainWindow::onClientDisconnected);
    connect(client_, &SnifferClient::connectionError, this, &MainWindow::onConnectionError);
    connect(client_, &SnifferClient::forwardLogReceived, this, &MainWindow::onForwardLogReceived);
}

MainWindow::~MainWindow() = default;

void MainWindow::setupUI() {
    setWindowTitle("Network Sniffer Monitor");
    resize(1200, 800);

    QWidget* centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);

    QVBoxLayout* mainLayout = new QVBoxLayout(centralWidget);

    // Connection Panel
    QGroupBox* connectionGroup = new QGroupBox("Server Connection", this);
    QHBoxLayout* connectionLayout = new QHBoxLayout(connectionGroup);

    connectionLayout->addWidget(new QLabel("Host:", this));
    hostEdit_ = new QLineEdit("127.0.0.1", this);
    hostEdit_->setFixedWidth(120);
    connectionLayout->addWidget(hostEdit_);

    connectionLayout->addWidget(new QLabel("Port:", this));
    portSpinBox_ = new QSpinBox(this);
    portSpinBox_->setRange(1, 65535);
    portSpinBox_->setValue(9090);
    portSpinBox_->setFixedWidth(80);
    connectionLayout->addWidget(portSpinBox_);

    connectButton_ = new QPushButton("Connect", this);
    connect(connectButton_, &QPushButton::clicked, this, &MainWindow::onConnectClicked);
    connectionLayout->addWidget(connectButton_);

    disconnectButton_ = new QPushButton("Disconnect", this);
    disconnectButton_->setEnabled(false);
    connect(disconnectButton_, &QPushButton::clicked, this, &MainWindow::onDisconnectClicked);
    connectionLayout->addWidget(disconnectButton_);

    connectionLayout->addStretch();

    statusLabel_ = new QLabel("Disconnected", this);
    statusLabel_->setStyleSheet("QLabel { color: red; font-weight: bold; }");
    connectionLayout->addWidget(statusLabel_);

    mainLayout->addWidget(connectionGroup);

    // Tab Widget for SSID logs
    tabWidget_ = new QTabWidget(this);
    tabWidget_->setTabsClosable(false);
    mainLayout->addWidget(tabWidget_);

    // Status Bar
    statusBar()->showMessage("Ready");
}

void MainWindow::onConnectClicked() {
    QString host = hostEdit_->text();
    quint16 port = static_cast<quint16>(portSpinBox_->value());

    if (host.isEmpty()) {
        QMessageBox::warning(this, "Invalid Input", "Please enter a server host.");
        return;
    }

    connectButton_->setEnabled(false);
    hostEdit_->setEnabled(false);
    portSpinBox_->setEnabled(false);
    updateConnectionStatus("Connecting...");

    client_->connectToServer(host, port);
}

void MainWindow::onDisconnectClicked() {
    client_->disconnect();
}

void MainWindow::onClientConnected() {
    connectButton_->setEnabled(false);
    disconnectButton_->setEnabled(true);
    hostEdit_->setEnabled(false);
    portSpinBox_->setEnabled(false);
    updateConnectionStatus("Connected");
    statusBar()->showMessage("Connected to server");
}

void MainWindow::onClientDisconnected() {
    connectButton_->setEnabled(true);
    disconnectButton_->setEnabled(false);
    hostEdit_->setEnabled(true);
    portSpinBox_->setEnabled(true);
    updateConnectionStatus("Disconnected");
    statusBar()->showMessage("Disconnected from server");
}

void MainWindow::onConnectionError(const QString& error) {
    connectButton_->setEnabled(true);
    disconnectButton_->setEnabled(false);
    hostEdit_->setEnabled(true);
    portSpinBox_->setEnabled(true);
    updateConnectionStatus("Error");
    statusBar()->showMessage("Connection error: " + error);
    QMessageBox::critical(this, "Connection Error", "Failed to connect to server:\n" + error);
}

void MainWindow::onForwardLogReceived(uint32_t ssid, const json& log) {
    qDebug() << "onForwardLogReceived - SSID:" << ssid;
    QTextEdit* textEdit = getOrCreateTabForSSID(ssid);
    appendLogToTab(textEdit, log);
}

QTextEdit* MainWindow::getOrCreateTabForSSID(uint32_t ssid) {
    if (ssidTabs_.contains(ssid)) {
        return ssidTabs_[ssid];
    }

    QTextEdit* textEdit = new QTextEdit(this);
    textEdit->setReadOnly(true);
    textEdit->setFont(QFont("Courier", 10));
    textEdit->setLineWrapMode(QTextEdit::NoWrap);

    QString tabName = QString("Sniffer %1 (SSID: %2)").arg(ssidTabs_.size() + 1).arg(ssid);
    tabWidget_->addTab(textEdit, tabName);

    ssidTabs_[ssid] = textEdit;

    return textEdit;
}

void MainWindow::appendLogToTab(QTextEdit* textEdit, const json& log) {
    QString logLine;

    try {
        QString timestamp = log.contains("timestamp") ?
            QString::fromStdString(log["timestamp"].get<std::string>()) :
            QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss.zzz");

        QString protocol = log.contains("protocol") ?
            QString::fromStdString(log["protocol"].get<std::string>()) : "UNKNOWN";

        QString src = log.contains("src") ?
            QString::fromStdString(log["src"].get<std::string>()) : "?";

        QString dst = log.contains("dst") ?
            QString::fromStdString(log["dst"].get<std::string>()) : "?";

        int length = log.contains("length") ? log["length"].get<int>() : 0;

        QString srcPort, dstPort;
        if (log.contains("src_port")) {
            srcPort = QString(":%1").arg(log["src_port"].get<int>());
        }
        if (log.contains("dst_port")) {
            dstPort = QString(":%1").arg(log["dst_port"].get<int>());
        }

        logLine = QString("%1 | %2 | %3%4 -> %5%6 | len=%7")
            .arg(timestamp)
            .arg(protocol, -6)
            .arg(src, -15)
            .arg(srcPort, -6)
            .arg(dst, -15)
            .arg(dstPort, -6)
            .arg(length);

    } catch (const std::exception& e) {
        logLine = QString("Error parsing log: %1").arg(e.what());
    }

    textEdit->append(logLine);
}

void MainWindow::updateConnectionStatus(const QString& status) {
    statusLabel_->setText(status);

    if (status == "Connected") {
        statusLabel_->setStyleSheet("QLabel { color: green; font-weight: bold; }");
    } else if (status == "Connecting...") {
        statusLabel_->setStyleSheet("QLabel { color: orange; font-weight: bold; }");
    } else {
        statusLabel_->setStyleSheet("QLabel { color: red; font-weight: bold; }");
    }
}
