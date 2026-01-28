# -*- coding: utf-8 -*-

# Clean dark theme tuned for spacing + readable controls
DARK_QSS = r"""
QWidget {
    background: #1e1e1e;
    color: #e6e6e6;
    font-family: "Segoe UI";
    font-size: 10pt;
}

QLabel {
    color: #e6e6e6;
}

QGroupBox {
    border: 1px solid #3a3a3a;
    border-radius: 8px;
    margin-top: 12px;
    padding: 10px;
}

QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 6px 0 6px;
    color: #d7d7d7;
    font-weight: 600;
}

QLineEdit, QTextEdit, QComboBox, QDateTimeEdit, QListWidget {
    background: #252526;
    border: 1px solid #3a3a3a;
    border-radius: 6px;
    padding: 6px 8px;
    selection-background-color: #264f78;
    selection-color: #ffffff;
}

QTextEdit {
    padding: 10px;
}

QComboBox::drop-down {
    border: none;
    width: 26px;
}

QComboBox QAbstractItemView {
    background: #252526;
    border: 1px solid #3a3a3a;
    selection-background-color: #264f78;
}

QPushButton {
    background: #333333;
    border: 1px solid #444444;
    border-radius: 8px;
    padding: 8px 12px;
}

QPushButton:hover {
    background: #3a3a3a;
}

QPushButton:pressed {
    background: #2a2a2a;
}

QHeaderView::section {
    background: #2b2b2b;
    border: 1px solid #3a3a3a;
    padding: 6px 8px;
    font-weight: 600;
}

QTableWidget {
    background: #252526;
    border: 1px solid #3a3a3a;
    gridline-color: #333333;
}

QTableWidget::item:selected {
    background: #264f78;
    color: #ffffff;
}

QScrollBar:vertical, QScrollBar:horizontal {
    background: #1e1e1e;
}

QStatusBar {
    background: #1e1e1e;
    color: #bdbdbd;
}
"""
