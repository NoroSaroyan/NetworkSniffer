/**
 * @file ModernStyle.h
 * @brief Modern stylesheet and UI theme for the network sniffer GUI
 *
 * Provides a professional dark theme with modern styling for all Qt widgets.
 */

#pragma once

#include <QString>

class ModernStyle {
public:
    /**
     * @brief Get the modern dark theme stylesheet
     * @return Complete QSS stylesheet string
     */
    static QString getDarkStylesheet() {
        return R"(
            /* ================================================================
               GLOBAL APPLICATION STYLE
               ================================================================ */
            QMainWindow, QWidget {
                background-color: #1a1a2e;
                color: #e0e0e0;
            }

            /* ================================================================
               WINDOWS & DIALOGS
               ================================================================ */
            QMainWindow {
                background-color: #0f0f1e;
            }

            /* ================================================================
               BUTTONS
               ================================================================ */
            QPushButton {
                background-color: #00d4ff;
                color: #000;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
                font-size: 11px;
            }

            QPushButton:hover {
                background-color: #00f0ff;
            }

            QPushButton:pressed {
                background-color: #00a8cc;
            }

            QPushButton:disabled {
                background-color: #404050;
                color: #606070;
            }

            /* ================================================================
               LINE EDITS & INPUT
               ================================================================ */
            QLineEdit {
                background-color: #16213e;
                color: #e0e0e0;
                border: 2px solid #0f3460;
                border-radius: 6px;
                padding: 8px 12px;
                font-size: 11px;
            }

            QLineEdit:focus {
                border: 2px solid #00d4ff;
                background-color: #1a2e4a;
            }

            QLineEdit::placeholder {
                color: #606070;
            }

            /* ================================================================
               SPINBOX
               ================================================================ */
            QSpinBox {
                background-color: #16213e;
                color: #e0e0e0;
                border: 2px solid #0f3460;
                border-radius: 6px;
                padding: 6px;
                font-size: 11px;
            }

            QSpinBox:focus {
                border: 2px solid #00d4ff;
            }

            QSpinBox::up-button, QSpinBox::down-button {
                background-color: #0f3460;
                border: none;
                width: 20px;
            }

            /* ================================================================
               GROUP BOX
               ================================================================ */
            QGroupBox {
                color: #e0e0e0;
                border: 2px solid #0f3460;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
                font-weight: bold;
                font-size: 12px;
            }

            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0px 3px 0px 3px;
            }

            /* ================================================================
               LABELS
               ================================================================ */
            QLabel {
                color: #e0e0e0;
                font-size: 11px;
            }

            QLabel[role="status"] {
                font-weight: bold;
                font-size: 12px;
            }

            /* ================================================================
               TABS
               ================================================================ */
            QTabWidget::pane {
                border: 2px solid #0f3460;
                background-color: #16213e;
            }

            QTabBar::tab {
                background-color: #0f3460;
                color: #b0b0c0;
                padding: 10px 20px;
                margin: 2px 2px 0px 0px;
                border-radius: 6px 6px 0px 0px;
                font-weight: bold;
                font-size: 11px;
            }

            QTabBar::tab:selected {
                background-color: #00d4ff;
                color: #000;
            }

            QTabBar::tab:hover {
                background-color: #1a4d6d;
            }

            /* ================================================================
               TABLE WIDGET
               ================================================================ */
            QTableWidget {
                background-color: #16213e;
                alternate-background-color: #1a2e4a;
                gridline-color: #0f3460;
                border: none;
                font-size: 11px;
            }

            QTableWidget::item {
                padding: 6px;
                color: #e0e0e0;
            }

            QTableWidget::item:selected {
                background-color: #00d4ff;
                color: #000;
            }

            QHeaderView::section {
                background-color: #0f3460;
                color: #e0e0e0;
                padding: 8px;
                border: none;
                font-weight: bold;
                font-size: 11px;
            }

            QHeaderView::section:hover {
                background-color: #1a4d6d;
            }

            /* ================================================================
               SCROLLBARS
               ================================================================ */
            QScrollBar:vertical {
                background-color: #16213e;
                width: 12px;
                border: none;
            }

            QScrollBar::handle:vertical {
                background-color: #0f3460;
                border-radius: 6px;
                min-height: 20px;
            }

            QScrollBar::handle:vertical:hover {
                background-color: #00d4ff;
            }

            QScrollBar:horizontal {
                background-color: #16213e;
                height: 12px;
                border: none;
            }

            QScrollBar::handle:horizontal {
                background-color: #0f3460;
                border-radius: 6px;
                min-width: 20px;
            }

            QScrollBar::handle:horizontal:hover {
                background-color: #00d4ff;
            }

            QScrollBar::add-line, QScrollBar::sub-line {
                border: none;
                background: none;
            }

            /* ================================================================
               STATUSBAR
               ================================================================ */
            QStatusBar {
                background-color: #0f1419;
                color: #e0e0e0;
                border-top: 1px solid #0f3460;
                font-size: 11px;
            }

            /* ================================================================
               MESSAGE BOXES
               ================================================================ */
            QMessageBox {
                background-color: #1a1a2e;
            }

            QMessageBox QLabel {
                color: #e0e0e0;
            }

            QMessageBox QPushButton {
                min-width: 60px;
            }
        )";
    }

    /**
     * @brief Get protocol color for table highlighting
     * @param protocol Protocol name (TCP, UDP, ICMP, etc.)
     * @return Color hex string
     */
    static QString getProtocolColor(const QString& protocol) {
        QString proto = protocol.toUpper();
        if (proto == "TCP") return "#FF6B6B";      // Red
        if (proto == "UDP") return "#4ECDC4";      // Teal
        if (proto == "ICMP") return "#FFE66D";     // Yellow
        if (proto == "ARP") return "#95E1D3";      // Mint
        if (proto == "DNS") return "#C7CEEA";      // Purple
        return "#B0B0C0";                          // Default gray
    }
};
