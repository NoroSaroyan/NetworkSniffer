/**
 * @file StatsWidget.h
 * @brief Real-time statistics display widget for network traffic
 *
 * Shows live packet statistics, protocol breakdown, and network metrics.
 */

#pragma once

#include <QWidget>
#include <QLabel>
#include <QMap>
#include <QString>

class StatsWidget : public QWidget {
    Q_OBJECT

public:
    explicit StatsWidget(QWidget* parent = nullptr);

    /**
     * @brief Update statistics for a sniffer tab
     * @param totalPackets Total packets captured
     * @param protocolCounts Map of protocol name to count
     * @param totalBytes Total bytes captured
     */
    void updateStats(uint32_t totalPackets, const QMap<QString, uint32_t>& protocolCounts, uint64_t totalBytes);

    /**
     * @brief Reset statistics
     */
    void reset();

private:
    void setupUI();
    QString formatBytes(uint64_t bytes);

    // Stat labels
    QLabel* packetsLabel_;
    QLabel* tcpLabel_;
    QLabel* udpLabel_;
    QLabel* icmpLabel_;
    QLabel* bytesLabel_;
};
