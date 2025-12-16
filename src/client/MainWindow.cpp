/**
 * @file MainWindow.cpp
 * @brief Implementation of main GUI window with tabbed table-based log display
 *
 * Provides tabbed interface where each sniffer/SSID gets its own table
 * displaying captured network traffic with sortable columns.
 */

#include "MainWindow.h"
#include "ModernStyle.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QMessageBox>
#include <QDateTime>
#include <QFont>
#include <QHeaderView>
#include <QSplitter>
#include <QApplication>

/**
 * @brief Construct main window and set up UI
 *
 * Initializes SnifferClient and connects all signals/slots.
 *
 * @param parent Qt parent widget
 */
MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent), client_(new SnifferClient(this)) {

    setupUI();

    // Apply modern dark theme
    qApp->setStyle("Fusion");
    qApp->setStyleSheet(ModernStyle::getDarkStylesheet());

    connect(client_, &SnifferClient::connected, this, &MainWindow::onClientConnected);
    connect(client_, &SnifferClient::disconnected, this, &MainWindow::onClientDisconnected);
    connect(client_, &SnifferClient::connectionError, this, &MainWindow::onConnectionError);
    connect(client_, &SnifferClient::forwardLogReceived, this, &MainWindow::onForwardLogReceived);
}

/**
 * @brief Destructor - cleanup handled automatically by Qt
 */
MainWindow::~MainWindow() = default;

/**
 * @brief Set up the main UI layout
 *
 * Creates:
 * 1. Connection panel with host/port input and status indicator
 * 2. Tab widget container for per-SSID tables
 * 3. Status bar at bottom
 */
void MainWindow::setupUI() {
    setWindowTitle("Network Sniffer Monitor");
    resize(1400, 900);

    QWidget* centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);

    QVBoxLayout* mainLayout = new QVBoxLayout(centralWidget);

    // ====================================================================
    // CONNECTION PANEL
    // ====================================================================
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

    // ====================================================================
    // FILTER PANEL
    // ====================================================================
    QGroupBox* filterGroup = new QGroupBox("Filter", this);
    QHBoxLayout* filterLayout = new QHBoxLayout(filterGroup);

    filterLayout->addWidget(new QLabel("Protocol:", this));
    filterProtocol_ = new QLineEdit(this);
    filterProtocol_->setPlaceholderText("TCP, UDP, ICMP, ...");
    filterProtocol_->setMaximumWidth(100);
    connect(filterProtocol_, &QLineEdit::textChanged, this, &MainWindow::onFilterChanged);
    filterLayout->addWidget(filterProtocol_);

    filterLayout->addWidget(new QLabel("Source IP:", this));
    filterSource_ = new QLineEdit(this);
    filterSource_->setPlaceholderText("192.168...");
    filterSource_->setMaximumWidth(150);
    connect(filterSource_, &QLineEdit::textChanged, this, &MainWindow::onFilterChanged);
    filterLayout->addWidget(filterSource_);

    filterLayout->addWidget(new QLabel("Dest IP:", this));
    filterDest_ = new QLineEdit(this);
    filterDest_->setPlaceholderText("192.168...");
    filterDest_->setMaximumWidth(150);
    connect(filterDest_, &QLineEdit::textChanged, this, &MainWindow::onFilterChanged);
    filterLayout->addWidget(filterDest_);

    filterLayout->addStretch();

    mainLayout->addWidget(filterGroup);

    // ====================================================================
    // TAB WIDGET FOR SNIFFER TABLES
    // ====================================================================
    tabWidget_ = new QTabWidget(this);
    tabWidget_->setTabsClosable(false);
    mainLayout->addWidget(tabWidget_);

    // Status Bar
    statusBar()->showMessage("Ready");
}

/**
 * @brief [Qt Slot] Handle connect button click
 *
 * Validates input and initiates connection to server.
 */
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

/**
 * @brief [Qt Slot] Handle disconnect button click
 *
 * Disconnects from server.
 */
void MainWindow::onDisconnectClicked() {
    client_->disconnect();
}

/**
 * @brief [Qt Slot] Handle successful server connection
 *
 * Updates UI to reflect connected state.
 */
void MainWindow::onClientConnected() {
    connectButton_->setEnabled(false);
    disconnectButton_->setEnabled(true);
    hostEdit_->setEnabled(false);
    portSpinBox_->setEnabled(false);
    updateConnectionStatus("Connected");
    statusBar()->showMessage("Connected to server");
}

/**
 * @brief [Qt Slot] Handle server disconnection
 *
 * Updates UI to reflect disconnected state.
 */
void MainWindow::onClientDisconnected() {
    connectButton_->setEnabled(true);
    disconnectButton_->setEnabled(false);
    hostEdit_->setEnabled(true);
    portSpinBox_->setEnabled(true);
    updateConnectionStatus("Disconnected");
    statusBar()->showMessage("Disconnected from server");
}

/**
 * @brief [Qt Slot] Handle connection error
 *
 * Shows error message to user and resets UI.
 *
 * @param error Error description
 */
void MainWindow::onConnectionError(const QString& error) {
    connectButton_->setEnabled(true);
    disconnectButton_->setEnabled(false);
    hostEdit_->setEnabled(true);
    portSpinBox_->setEnabled(true);
    updateConnectionStatus("Error");
    statusBar()->showMessage("Connection error: " + error);
    QMessageBox::critical(this, "Connection Error", "Failed to connect to server:\n" + error);
}

/**
 * @brief [Qt Slot] Handle forwarded log from sniffer
 *
 * Gets or creates table for this SSID and adds log as a new row.
 * Also updates statistics for this SSID.
 *
 * @param ssid Sniffer Session ID identifying the source sniffer
 * @param log JSON traffic log containing packet data
 */
void MainWindow::onForwardLogReceived(uint32_t ssid, const json& log) {
    qDebug() << "onForwardLogReceived - SSID:" << ssid;
    QTableWidget* table = getOrCreateTabForSSID(ssid);
    addLogRowToTable(table, log);

    // ====================================================================
    // UPDATE STATISTICS
    // ====================================================================
    if (!ssidStatsData_.contains(ssid)) {
        ssidStatsData_[ssid] = SSIDStats();
    }

    SSIDStats& stats = ssidStatsData_[ssid];

    // Count packet
    stats.totalPackets++;

    // Add to protocol count
    QString protocol = log.contains("protocol") ?
        QString::fromStdString(log["protocol"].get<std::string>()) : "OTHER";
    stats.protocolCounts[protocol]++;

    // Add to byte count
    int length = log.contains("length") ? log["length"].get<int>() : 0;
    stats.totalBytes += length;

    // Update stats widget if visible
    if (ssidStats_.contains(ssid)) {
        ssidStats_[ssid]->updateStats(stats.totalPackets, stats.protocolCounts, stats.totalBytes);
    }
}

/**
 * @brief Get or create a table for the given SSID
 *
 * If a table already exists for this SSID, return it. Otherwise, create
 * a new QTableWidget with appropriate columns (Timestamp, Protocol, Source,
 * Destination, Src Port, Dst Port, Length) and add it as a new tab with
 * a statistics panel.
 *
 * @param ssid Sniffer Session ID
 * @return QTableWidget for this SSID
 */
QTableWidget* MainWindow::getOrCreateTabForSSID(uint32_t ssid) {
    if (ssidTabs_.contains(ssid)) {
        return ssidTabs_[ssid];
    }

    // ====================================================================
    // CREATE CONTAINER WITH STATS AND TABLE
    // ====================================================================
    QWidget* tabContent = new QWidget(this);
    QVBoxLayout* tabLayout = new QVBoxLayout(tabContent);
    tabLayout->setContentsMargins(0, 0, 0, 0);

    // Create stats widget
    StatsWidget* statsWidget = new StatsWidget(this);
    ssidStats_[ssid] = statsWidget;

    // Create table widget
    QTableWidget* table = new QTableWidget(this);

    // Set column headers
    QStringList headers;
    headers << "Timestamp" << "Protocol" << "Source" << "Dest" << "Src Port" << "Dst Port" << "Length";
    table->setColumnCount(headers.size());
    table->setHorizontalHeaderLabels(headers);

    // Configure table behavior
    table->horizontalHeader()->setStretchLastSection(false);
    table->setColumnWidth(0, 180);  // Timestamp
    table->setColumnWidth(1, 70);   // Protocol
    table->setColumnWidth(2, 120);  // Source
    table->setColumnWidth(3, 120);  // Destination
    table->setColumnWidth(4, 80);   // Src Port
    table->setColumnWidth(5, 80);   // Dst Port
    table->setColumnWidth(6, 80);   // Length

    // Enable sorting and selection
    table->setSortingEnabled(true);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->setAlternatingRowColors(true);

    // Add stats panel and table to layout
    tabLayout->addWidget(statsWidget, 0);
    tabLayout->addWidget(table, 1);

    // Add tab with content
    QString tabName = QString("Sniffer %1 (SSID: %2)").arg(ssidTabs_.size() + 1).arg(ssid);
    tabWidget_->addTab(tabContent, tabName);

    ssidTabs_[ssid] = table;

    return table;
}

/**
 * @brief Add a traffic log entry as a new row in the table
 *
 * Extracts relevant fields from JSON log and inserts a row with:
 * - Timestamp
 * - Protocol (TCP, UDP, ICMP, etc.)
 * - Source IP
 * - Destination IP
 * - Source Port (if applicable)
 * - Destination Port (if applicable)
 * - Packet Length
 *
 * When table reaches MAX_ROWS, oldest TRIM_ROWS entries are removed to
 * prevent memory exhaustion.
 *
 * @param table Target table widget
 * @param log JSON traffic log from packet parser
 */
void MainWindow::addLogRowToTable(QTableWidget* table, const json& log) {
    try {
        // ================================================================
        // EXTRACT FIELDS FROM JSON LOG
        // ================================================================
        QString timestamp = log.contains("timestamp") ?
            QString::fromStdString(log["timestamp"].get<std::string>()) :
            QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss.zzz");

        QString protocol = log.contains("protocol") ?
            QString::fromStdString(log["protocol"].get<std::string>()) : "UNKNOWN";

        QString src = log.contains("src") ?
            QString::fromStdString(log["src"].get<std::string>()) : "?";

        QString dst = log.contains("dst") ?
            QString::fromStdString(log["dst"].get<std::string>()) : "?";

        QString srcPort = (log.contains("src_port")) ?
            QString::number(log["src_port"].get<int>()) : "";

        QString dstPort = (log.contains("dst_port")) ?
            QString::number(log["dst_port"].get<int>()) : "";

        int length = log.contains("length") ? log["length"].get<int>() : 0;

        // ================================================================
        // TRIM TABLE IF NECESSARY
        // ================================================================
        if (table->rowCount() >= MAX_ROWS) {
            for (int i = 0; i < TRIM_ROWS; ++i) {
                table->removeRow(0);  // Remove oldest entries from top
            }
        }

        // ================================================================
        // INSERT NEW ROW AT TOP
        // ================================================================
        table->insertRow(0);

        // Column 0: Timestamp
        table->setItem(0, 0, new QTableWidgetItem(timestamp));

        // Column 1: Protocol
        table->setItem(0, 1, new QTableWidgetItem(protocol));

        // Column 2: Source IP
        table->setItem(0, 2, new QTableWidgetItem(src));

        // Column 3: Destination IP
        table->setItem(0, 3, new QTableWidgetItem(dst));

        // Column 4: Source Port
        table->setItem(0, 4, new QTableWidgetItem(srcPort));

        // Column 5: Destination Port
        table->setItem(0, 5, new QTableWidgetItem(dstPort));

        // Column 6: Length
        QTableWidgetItem* lengthItem = new QTableWidgetItem(QString::number(length));
        lengthItem->setTextAlignment(Qt::AlignRight);
        table->setItem(0, 6, lengthItem);

    } catch (const std::exception& e) {
        qWarning() << "Error adding row to table:" << e.what();
    }
}

/**
 * @brief Update connection status display with color coding
 *
 * - "Connected": Green
 * - "Connecting...": Orange
 * - "Disconnected"/"Error": Red
 *
 * @param status Status message to display
 */
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

// ============================================================================
// FILTERING
// ============================================================================

/**
 * @brief [Qt Slot] Handle filter field text change
 *
 * Called when any filter field is modified. Applies current filter criteria
 * to the active table.
 */
void MainWindow::onFilterChanged() {
    applyFilter();
}

/**
 * @brief Apply current filter criteria to active table
 *
 * Hides rows that don't match ANY of the active filter fields:
 * - Protocol: Matches if row protocol column contains filter text (case-insensitive)
 * - Source IP: Matches if row source column contains filter text
 * - Dest IP: Matches if row dest column contains filter text
 *
 * Empty filter fields are ignored (match all). All filters are AND'd together.
 */
void MainWindow::applyFilter() {
    // Get current table
    int currentIndex = tabWidget_->currentIndex();
    if (currentIndex < 0) return;

    QTableWidget* table = qobject_cast<QTableWidget*>(tabWidget_->currentWidget());
    if (!table) return;

    // ====================================================================
    // GET FILTER CRITERIA
    // ====================================================================
    QString protocolFilter = filterProtocol_->text().toUpper();
    QString sourceFilter = filterSource_->text();
    QString destFilter = filterDest_->text();

    // ====================================================================
    // APPLY FILTER TO ALL ROWS
    // ====================================================================
    for (int row = 0; row < table->rowCount(); ++row) {
        bool show = true;

        // Filter by protocol (column 1)
        if (!protocolFilter.isEmpty()) {
            QString protocol = table->item(row, 1)->text().toUpper();
            if (!protocol.contains(protocolFilter)) {
                show = false;
            }
        }

        // Filter by source IP (column 2)
        if (show && !sourceFilter.isEmpty()) {
            QString source = table->item(row, 2)->text();
            if (!source.contains(sourceFilter)) {
                show = false;
            }
        }

        // Filter by destination IP (column 3)
        if (show && !destFilter.isEmpty()) {
            QString dest = table->item(row, 3)->text();
            if (!dest.contains(destFilter)) {
                show = false;
            }
        }

        table->setRowHidden(row, !show);
    }
}
