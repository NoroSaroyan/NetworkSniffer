/**
 * @file StatsWidget.cpp
 * @brief Implementation of real-time statistics display widget
 */

#include "StatsWidget.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>

StatsWidget::StatsWidget(QWidget* parent)
    : QWidget(parent) {
    setupUI();
}

void StatsWidget::setupUI() {
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(12);

    // ====================================================================
    // OVERALL STATS SECTION
    // ====================================================================
    QGroupBox* overallGroup = new QGroupBox("Network Statistics", this);
    QHBoxLayout* overallLayout = new QHBoxLayout(overallGroup);
    overallLayout->setSpacing(20);

    // Packets
    QVBoxLayout* packetsBox = new QVBoxLayout();
    QLabel* packetsTitle = new QLabel("Packets Captured");
    packetsTitle->setStyleSheet("color: #00d4ff; font-weight: bold;");
    packetsLabel_ = new QLabel("0");
    packetsLabel_->setStyleSheet("color: #e0e0e0; font-size: 14px; font-weight: bold;");
    packetsBox->addWidget(packetsTitle);
    packetsBox->addWidget(packetsLabel_);
    overallLayout->addLayout(packetsBox);

    // Bytes
    QVBoxLayout* bytesBox = new QVBoxLayout();
    QLabel* bytesTitle = new QLabel("Total Data");
    bytesTitle->setStyleSheet("color: #00d4ff; font-weight: bold;");
    bytesLabel_ = new QLabel("0 B");
    bytesLabel_->setStyleSheet("color: #e0e0e0; font-size: 14px; font-weight: bold;");
    bytesBox->addWidget(bytesTitle);
    bytesBox->addWidget(bytesLabel_);
    overallLayout->addLayout(bytesBox);

    overallLayout->addStretch();
    mainLayout->addWidget(overallGroup);

    // ====================================================================
    // PROTOCOL BREAKDOWN SECTION
    // ====================================================================
    QGroupBox* protocolGroup = new QGroupBox("Protocol Breakdown", this);
    QHBoxLayout* protocolLayout = new QHBoxLayout(protocolGroup);
    protocolLayout->setSpacing(20);

    // TCP
    QVBoxLayout* tcpBox = new QVBoxLayout();
    QLabel* tcpTitle = new QLabel("TCP");
    tcpTitle->setStyleSheet("color: #FF6B6B; font-weight: bold;");
    tcpLabel_ = new QLabel("0");
    tcpLabel_->setStyleSheet("color: #e0e0e0; font-size: 14px; font-weight: bold;");
    tcpBox->addWidget(tcpTitle);
    tcpBox->addWidget(tcpLabel_);
    protocolLayout->addLayout(tcpBox);

    // UDP
    QVBoxLayout* udpBox = new QVBoxLayout();
    QLabel* udpTitle = new QLabel("UDP");
    udpTitle->setStyleSheet("color: #4ECDC4; font-weight: bold;");
    udpLabel_ = new QLabel("0");
    udpLabel_->setStyleSheet("color: #e0e0e0; font-size: 14px; font-weight: bold;");
    udpBox->addWidget(udpTitle);
    udpBox->addWidget(udpLabel_);
    protocolLayout->addLayout(udpBox);

    // ICMP
    QVBoxLayout* icmpBox = new QVBoxLayout();
    QLabel* icmpTitle = new QLabel("ICMP");
    icmpTitle->setStyleSheet("color: #FFE66D; font-weight: bold;");
    icmpLabel_ = new QLabel("0");
    icmpLabel_->setStyleSheet("color: #e0e0e0; font-size: 14px; font-weight: bold;");
    icmpBox->addWidget(icmpTitle);
    icmpBox->addWidget(icmpLabel_);
    protocolLayout->addLayout(icmpBox);

    protocolLayout->addStretch();
    mainLayout->addWidget(protocolGroup);

    mainLayout->addStretch();
}

void StatsWidget::updateStats(uint32_t totalPackets, const QMap<QString, uint32_t>& protocolCounts, uint64_t totalBytes) {
    // Update total packets
    packetsLabel_->setText(QString::number(totalPackets));

    // Update total bytes
    bytesLabel_->setText(formatBytes(totalBytes));

    // Update protocol counts
    tcpLabel_->setText(QString::number(protocolCounts.value("TCP", 0)));
    udpLabel_->setText(QString::number(protocolCounts.value("UDP", 0)));
    icmpLabel_->setText(QString::number(protocolCounts.value("ICMP", 0)));
}

void StatsWidget::reset() {
    packetsLabel_->setText("0");
    bytesLabel_->setText("0 B");
    tcpLabel_->setText("0");
    udpLabel_->setText("0");
    icmpLabel_->setText("0");
}

QString StatsWidget::formatBytes(uint64_t bytes) {
    if (bytes < 1024) return QString::number(bytes) + " B";
    if (bytes < 1024 * 1024) return QString::number(bytes / 1024.0, 'f', 2) + " KB";
    if (bytes < 1024 * 1024 * 1024) return QString::number(bytes / (1024.0 * 1024.0), 'f', 2) + " MB";
    return QString::number(bytes / (1024.0 * 1024.0 * 1024.0), 'f', 2) + " GB";
}
