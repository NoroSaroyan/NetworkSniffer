#pragma once

#include <QMainWindow>
#include <QTabWidget>
#include <QTextEdit>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QStatusBar>
#include <QLabel>
#include <QMap>
#include <nlohmann/json.hpp>
#include "SnifferClient.h"

using json = nlohmann::json;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

private slots:
    void onConnectClicked();
    void onDisconnectClicked();
    void onClientConnected();
    void onClientDisconnected();
    void onConnectionError(const QString& error);
    void onForwardLogReceived(uint32_t ssid, const json& log);

private:
    void setupUI();
    QTextEdit* getOrCreateTabForSSID(uint32_t ssid);
    void appendLogToTab(QTextEdit* textEdit, const json& log);
    void updateConnectionStatus(const QString& status);

    // Network
    SnifferClient* client_;

    // UI Components - Connection Panel
    QLineEdit* hostEdit_;
    QSpinBox* portSpinBox_;
    QPushButton* connectButton_;
    QPushButton* disconnectButton_;
    QLabel* statusLabel_;

    // UI Components - Content
    QTabWidget* tabWidget_;
    QMap<uint32_t, QTextEdit*> ssidTabs_;
};
