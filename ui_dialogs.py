# ui_dialogs.py
from __future__ import annotations

from PyQt6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QGridLayout,
    QLabel,
    QLineEdit,
    QComboBox,
    QTextEdit,
    QDialogButtonBox,
    QSizePolicy,
    QWidget,
)


class EditEntryDialog(QDialog):
    """
    Dialog for editing an incident entry.
    Supports LARGE multiline editing and manual timestamp edits.
    """

    def __init__(
        self,
        parent=None,
        time: str = "",
        user: str = "",
        etype: str = "",
        text: str = "",
    ):
        super().__init__(parent)
        self.setWindowTitle("Edit Entry")

        # ---- Size & behavior ----
        self.setMinimumSize(800, 520)
        self.resize(900, 650)
        self.setSizeGripEnabled(True)

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(12)

        # =====================
        # Metadata row
        # =====================
        meta = QWidget()
        grid = QGridLayout(meta)
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(8)

        self.time_edit = QLineEdit(time)
        self.time_edit.setPlaceholderText("YYYY-MM-DD HH:MM:SS")

        self.user_edit = QLineEdit(user)

        self.type_combo = QComboBox()
        types = [
            "Observation",
            "Action",
            "Mitigation",
            "Escalation",
            "Resolution",
            "Communication",
        ]
        self.type_combo.addItems(types)
        if etype:
            self.type_combo.setCurrentText(etype)

        grid.addWidget(QLabel("Time:"), 0, 0)
        grid.addWidget(self.time_edit, 0, 1)

        grid.addWidget(QLabel("User:"), 0, 2)
        grid.addWidget(self.user_edit, 0, 3)

        grid.addWidget(QLabel("Type:"), 1, 0)
        grid.addWidget(self.type_combo, 1, 1)

        grid.setColumnStretch(1, 1)
        grid.setColumnStretch(3, 1)

        root.addWidget(meta)

        # =====================
        # Multiline editor
        # =====================
        root.addWidget(QLabel("Entry (multiline):"))

        self.text_edit = QTextEdit()
        self.text_edit.setReadOnly(False)  # 🔑 CRITICAL
        self.text_edit.setAcceptRichText(False)
        self.text_edit.setPlainText(text or "")
        self.text_edit.setMinimumHeight(300)

        # Proper expansion + scroll
        self.text_edit.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Expanding,
        )

        root.addWidget(self.text_edit, stretch=1)

        # =====================
        # Buttons
        # =====================
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save
            | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        root.addWidget(buttons)

        # 🔑 Force focus so typing works immediately
        self.text_edit.setFocus()

    def get_values(self) -> tuple[str, str, str, str]:
        return (
            self.time_edit.text().strip(),
            self.user_edit.text().strip(),
            self.type_combo.currentText().strip(),
            self.text_edit.toPlainText().rstrip(),
        )
