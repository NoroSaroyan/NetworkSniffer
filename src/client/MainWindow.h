/**
 * @file MainWindow.h
 * @brief Main GUI window for network sniffer monitoring application
 *
 * Provides a tabbed interface for monitoring network traffic captured by
 * remote sniffers. Each sniffer connection gets its own tab with a table
 * displaying captured packets with sortable/filterable columns.
 */

#pragma once

#include <QMainWindow>
#include <QTabWidget>
#include <QTableWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QStatusBar>
#include <QLabel>
#include <QMap>
#include <nlohmann/json.hpp>
#include "SnifferClient.h"
#include "StatsWidget.h"
#include <QSplitter>

using json = nlohmann::json;

/**
 * @class MainWindow
 * @brief Main application window with tabbed log display
 *
 * Features:
 * - Connection management (host/port input)
 * - Tab per sniffer (organized by SSID)
 * - Structured table view with sortable columns
 * - Real-time traffic log updates
 * - Connection status indicator
 */
class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    /**
     * @brief Construct main window
     * @param parent Qt parent widget
     */
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

    /**
     * @brief Get existing table for SSID or create new one
     * @param ssid Sniffer Session ID
     * @return QTableWidget for this SSID
     */
    QTableWidget* getOrCreateTabForSSID(uint32_t ssid);

    /**
     * @brief Add a log entry as a row in the table
     * @param table Target table widget
     * @param log JSON traffic log data
     */
    void addLogRowToTable(QTableWidget* table, const json& log);

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
    QMap<uint32_t, QTableWidget*> ssidTabs_;  ///< Maps SSID to its table widget
    QMap<uint32_t, StatsWidget*> ssidStats_;  ///< Maps SSID to its stats widget

    // Filter components
    QLineEdit* filterProtocol_;
    QLineEdit* filterSource_;
    QLineEdit* filterDest_;

    /**
     * @brief Apply filter to current table
     *
     * Hides rows that don't match filter criteria.
     */
    void applyFilter();

    /**
     * @brief [Qt Slot] Handle filter text change
     */
    void onFilterChanged();

    /**
     * @brief Update statistics for current SSID
     */
    void updateStatsForCurrentTab();

    // Statistics tracking per SSID
    struct SSIDStats {
        uint32_t totalPackets = 0;
        uint64_t totalBytes = 0;
        QMap<QString, uint32_t> protocolCounts;
    };
    QMap<uint32_t, SSIDStats> ssidStatsData_;

    // Table configuration
    static constexpr int MAX_ROWS = 1000;  ///< Maximum rows before trimming old entries
    static constexpr int TRIM_ROWS = 100;  ///< Number of rows to remove when at max
};
