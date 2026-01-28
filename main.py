# main.py
from __future__ import annotations

import getpass
import os
import socket
from datetime import datetime
from typing import Optional

from PyQt6.QtCore import Qt, QTimer, QDateTime
from PyQt6.QtGui import QAction, QKeySequence
from PyQt6.QtWidgets import (
    QDialog,
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QLabel,
    QGroupBox,
    QComboBox,
    QLineEdit,
    QTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QMessageBox,
    QInputDialog,
    QFileDialog,
    QListWidget,
    QSplitter,
    QDateTimeEdit,
    QScrollArea,   # <-- ADDED
)

from models import Entry
from ui_styles import DARK_QSS
from ui_dialogs import EditEntryDialog

import storage


# -----------------------------
# Safe wrappers (avoid breakage if storage.py differs)
# -----------------------------

def _now() -> str:
    try:
        return storage.now_local_str()
    except Exception:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _docs_path() -> str:
    try:
        return storage.get_documents_path()
    except Exception:
        return os.path.join(os.environ.get("USERPROFILE", os.path.expanduser("~")), "Documents")


def _sanitize_ticket(t: str) -> str:
    try:
        return storage.sanitize_ticket(t)
    except Exception:
        t = (t or "").strip().upper()
        for ch in r'\/:*?"<>|':
            t = t.replace(ch, "-")
        return t


def _service_options() -> list[str]:
    try:
        return list(storage.SERVICE_OPTIONS)
    except Exception:
        return ["CIT", "DCIM", "DWDM", "Switchboard", "Internet connect", "Metroconnect"]


def _find_existing(ticket: str, folder: str) -> list[str]:
    try:
        return list(storage.find_existing_logs_for_ticket(ticket, folder))
    except Exception:
        ticket = _sanitize_ticket(ticket)
        out: list[str] = []
        try:
            for name in os.listdir(folder):
                if not (name.startswith("INCIDENT_") and name.lower().endswith(".txt")):
                    continue
                base = name[:-4]
                parts = base.split("_")
                if len(parts) >= 4 and parts[2].upper() == ticket.upper():
                    out.append(os.path.join(folder, name))
        except Exception:
            return []
        out.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        return out


def _parse_txt(path: str) -> dict:
    try:
        return storage.parse_incident_txt(path)
    except Exception:
        return {"context": {}, "entries": []}


def _save_draft(data: dict) -> None:
    try:
        storage.save_draft(data)
    except Exception:
        pass


def _load_draft() -> Optional[dict]:
    try:
        return storage.load_draft()
    except Exception:
        return None


def _clear_draft() -> None:
    try:
        storage.clear_draft()
    except Exception:
        pass


# -----------------------------
# Main Window
# -----------------------------

class IncidentLogbookWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Incident Logbook")
        self.setMinimumSize(1120, 740)

        self.session_start = _now()
        self.current_ticket: str | None = None
        self.loaded_from_path: str | None = None

        self.entries: list[Entry] = []
        self.next_id = 1
        self.dirty = False

        self.attachments: list[str] = []

        self._build_actions_and_menu()
        self._build_ui()

        # Autosave draft every 60s
        self.autosave_timer = QTimer(self)
        self.autosave_timer.setInterval(60_000)
        self.autosave_timer.timeout.connect(self._autosave_draft)
        self.autosave_timer.start()

        self._restore_draft_if_present()
        self._startup_ticket_prompt_and_load()
        self.statusBar().showMessage("Ready")

    # ---------------- Menu ----------------

    def _build_actions_and_menu(self) -> None:
        self.act_save = QAction("Save...", self)
        self.act_save.setShortcut(QKeySequence("Ctrl+S"))
        self.act_save.triggered.connect(self.finish_and_save)

        self.act_exit = QAction("Exit", self)
        self.act_exit.triggered.connect(self.close)

        self.act_delete = QAction("Delete Selected", self)
        self.act_delete.setShortcut(QKeySequence(Qt.Key.Key_Delete))
        self.act_delete.triggered.connect(self.delete_selected)

        self.act_clear = QAction("Clear All", self)
        self.act_clear.setShortcut(QKeySequence("Ctrl+L"))
        self.act_clear.triggered.connect(self.clear_all)

        mb = self.menuBar()
        m_file = mb.addMenu("File")
        m_file.addAction(self.act_save)
        m_file.addSeparator()
        m_file.addAction(self.act_exit)

        m_edit = mb.addMenu("Edit")
        m_edit.addAction(self.act_delete)
        m_edit.addAction(self.act_clear)

    # ---------------- UI ----------------

    def _build_ui(self) -> None:
        # Central + Scroll Area (fix cramped minimized window)
        central = QWidget()
        self.setCentralWidget(central)
        central_layout = QVBoxLayout(central)
        central_layout.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        central_layout.addWidget(scroll)

        content = QWidget()
        scroll.setWidget(content)

        # Prevent extreme squeeze; prefer scroll instead of crushing layouts
        content.setMinimumWidth(980)

        root = QVBoxLayout(content)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(12)

        title = QLabel("Incident Logbook")
        title.setStyleSheet("font-size: 22px; font-weight: 700;")
        subtitle = QLabel("Multiline notes: Ctrl+Enter adds. Double-click timeline rows to edit.")
        subtitle.setStyleSheet("color: #bdbdbd;")
        root.addWidget(title)
        root.addWidget(subtitle)

        # -------- Context --------
        ctx = QGroupBox("Incident Context")
        ctx_layout = QGridLayout(ctx)
        ctx_layout.setHorizontalSpacing(14)
        ctx_layout.setVerticalSpacing(10)
        ctx_layout.setColumnStretch(1, 1)
        ctx_layout.setColumnStretch(3, 1)

        self.class_combo = QComboBox()
        self.class_combo.addItems(["IMPACT", "RISK"])

        self.service_dropdown = QComboBox()
        self.service_dropdown.addItems(_service_options())

        self.irr_owner_edit = QLineEdit()
        self.impacted_service_edit = QLineEdit()
        self.summary_edit = QLineEdit()

        ctx_layout.addWidget(QLabel("Classification:"), 0, 0)
        ctx_layout.addWidget(self.class_combo, 0, 1)
        ctx_layout.addWidget(QLabel("Service:"), 0, 2)
        ctx_layout.addWidget(self.service_dropdown, 0, 3)

        ctx_layout.addWidget(QLabel("IRR Owner:"), 1, 0)
        ctx_layout.addWidget(self.irr_owner_edit, 1, 1, 1, 3)

        ctx_layout.addWidget(QLabel("Impacted Service/System:"), 2, 0)
        ctx_layout.addWidget(self.impacted_service_edit, 2, 1, 1, 3)

        ctx_layout.addWidget(QLabel("Summary (optional):"), 3, 0)
        ctx_layout.addWidget(self.summary_edit, 3, 1, 1, 3)

        root.addWidget(ctx)

        # Session row
        info_row = QHBoxLayout()
        self.lbl_session = QLabel(f"Session start: {self.session_start}")
        self.lbl_session.setStyleSheet("color: #bdbdbd;")
        info_row.addWidget(self.lbl_session)
        info_row.addStretch(1)
        self.lbl_ticket = QLabel("Ticket: (not set)")
        self.lbl_ticket.setStyleSheet("color: #bdbdbd;")
        info_row.addWidget(self.lbl_ticket)
        root.addLayout(info_row)
      

        # -------- Entry controls (two-row grid so it looks OK minimized) --------
        controls = QGridLayout()
        controls.setHorizontalSpacing(10)
        controls.setVerticalSpacing(6)

        # Row 0
        controls.addWidget(QLabel("Type:"), 0, 0)
        self.type_combo = QComboBox()
        self.type_combo.addItems(["Observation", "Action", "Mitigation", "Escalation", "Resolution", "Communication"])
        self.type_combo.setMinimumWidth(160)
        controls.addWidget(self.type_combo, 0, 1)

        controls.addWidget(QLabel("Entry Mode:"), 0, 2)
        self.entry_mode_combo = QComboBox()
        self.entry_mode_combo.addItems(["Multiline (Ctrl+Enter adds)", "Single line (Enter adds)"])
        self.entry_mode_combo.setMinimumWidth(200)
        controls.addWidget(self.entry_mode_combo, 0, 3)

        btn_apply_mode = QPushButton("Apply")
        btn_apply_mode.setFixedWidth(70)
        btn_apply_mode.clicked.connect(self._apply_entry_mode)
        controls.addWidget(btn_apply_mode, 0, 4)

        # Row 1
        controls.addWidget(QLabel("Entry User:"), 1, 0)
        self.entry_user_edit = QLineEdit(getpass.getuser())
        self.entry_user_edit.setMinimumWidth(140)
        controls.addWidget(self.entry_user_edit, 1, 1)

        controls.addWidget(QLabel("Time:"), 1, 2)
        self.entry_time_edit = QLineEdit(_now())
        self.entry_time_edit.setMinimumWidth(160)
        self.entry_time_edit.setPlaceholderText("YYYY-MM-DD HH:MM:SS")
        controls.addWidget(self.entry_time_edit, 1, 3)

        btn_now = QPushButton("Now")
        btn_now.setFixedWidth(60)
        btn_now.clicked.connect(lambda: self.entry_time_edit.setText(_now()))
        controls.addWidget(btn_now, 1, 4)

        controls.setColumnStretch(1, 1)
        controls.setColumnStretch(3, 1)
        root.addLayout(controls)

        # -------- Entry input (single/multi swap container) --------
        self.entry_row = QHBoxLayout()

        self.single_entry = QLineEdit()
        self.single_entry.setPlaceholderText("Single-line entry... (Enter adds)")
        self.single_entry.setClearButtonEnabled(True)
        self.single_entry.returnPressed.connect(self.add_entry)

        self.multi_entry = QTextEdit()
        self.multi_entry.setPlaceholderText("Multiline notes... (Ctrl+Enter adds)")
        self.multi_entry.installEventFilter(self)
        self.multi_entry.setMinimumHeight(120)
        self.multi_entry.setMaximumHeight(170)

        self.entry_input_container = QWidget()
        self.entry_input_layout = QVBoxLayout(self.entry_input_container)
        self.entry_input_layout.setContentsMargins(0, 0, 0, 0)
        self.entry_input_layout.addWidget(self.multi_entry)

        self.entry_row.addWidget(self.entry_input_container, 1)

        self.btn_add = QPushButton("Add Entry")
        self.btn_add.setFixedWidth(110)
        self.btn_add.clicked.connect(self.add_entry)
        self.entry_row.addWidget(self.btn_add)

        root.addLayout(self.entry_row)

        self.entry_mode_combo.setCurrentText("Multiline (Ctrl+Enter adds)")
        self._apply_entry_mode()
      

        # -------- Attachments --------
        attach_box = QGroupBox("Attachments")
        attach_layout = QHBoxLayout(attach_box)

        self.attach_list = QListWidget()
        self.attach_list.setMinimumHeight(70)
        self.attach_list.setMaximumHeight(110)
        attach_layout.addWidget(self.attach_list, 1)

        attach_btns = QVBoxLayout()
        btn_add_attach = QPushButton("Add Files...")
        btn_add_attach.clicked.connect(self.add_attachments)
        attach_btns.addWidget(btn_add_attach)

        btn_remove_attach = QPushButton("Remove Selected")
        btn_remove_attach.clicked.connect(self.remove_selected_attachment)
        attach_btns.addWidget(btn_remove_attach)

        attach_btns.addStretch(1)
        attach_layout.addLayout(attach_btns)
        root.addWidget(attach_box)

        # -------- Search / Filter --------
        filter_row = QHBoxLayout()
        lbl = QLabel("Filter:")
        lbl.setStyleSheet("color: #bdbdbd;")
        filter_row.addWidget(lbl)

        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Search entries (text, user, type)...")
        self.filter_edit.textChanged.connect(self.apply_filters)
        filter_row.addWidget(self.filter_edit, 1)

        filter_row.addSpacing(12)
        filter_row.addWidget(QLabel("From:"))
        self.dt_from = QDateTimeEdit()
        self.dt_from.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        self.dt_from.setCalendarPopup(True)
        self.dt_from.setDateTime(QDateTime.currentDateTime().addDays(-7))
        self.dt_from.dateTimeChanged.connect(self.apply_filters)
        filter_row.addWidget(self.dt_from)

        filter_row.addSpacing(12)
        filter_row.addWidget(QLabel("To:"))
        self.dt_to = QDateTimeEdit()
        self.dt_to.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        self.dt_to.setCalendarPopup(True)
        self.dt_to.setDateTime(QDateTime.currentDateTime().addDays(1))
        self.dt_to.dateTimeChanged.connect(self.apply_filters)
        filter_row.addWidget(self.dt_to)

        btn_clear_filter = QPushButton("Clear")
        btn_clear_filter.clicked.connect(self._clear_filters)
        filter_row.addWidget(btn_clear_filter)

        root.addLayout(filter_row)

        # -------- Timeline --------
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Time", "User", "Type", "Entry"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.setWordWrap(True)
        self.table.cellDoubleClicked.connect(self.edit_selected_row)
        self.table.setTextElideMode(Qt.TextElideMode.ElideNone)
        self.table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.table.verticalHeader().setDefaultSectionSize(26)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.cellDoubleClicked.connect(self.edit_selected_row)
        self.table.setMinimumHeight(220)
        root.addWidget(self.table, 1)

        # -------- Actions --------
        actions = QHBoxLayout()
        btn_del = QPushButton("Delete Selected")
        btn_del.clicked.connect(self.delete_selected)
        actions.addWidget(btn_del)

        btn_clear = QPushButton("Clear All")
        btn_clear.clicked.connect(self.clear_all)
        actions.addWidget(btn_clear)

        actions.addStretch(1)

        btn_save = QPushButton("Finish & Save")
        btn_save.clicked.connect(self.finish_and_save)
        actions.addWidget(btn_save)

        root.addLayout(actions)

        self._refresh_ticket_banner()

        

    # ---- Entry mode swap ----

    def _apply_entry_mode(self) -> None:
        mode = self.entry_mode_combo.currentText().strip()

        while self.entry_input_layout.count():
            item = self.entry_input_layout.takeAt(0)
            w = item.widget()
            if w:
                w.setParent(None)

        if mode.startswith("Single"):
            self.entry_input_layout.addWidget(self.single_entry)
            self.single_entry.setFocus()
        else:
            self.entry_input_layout.addWidget(self.multi_entry)
            self.multi_entry.setFocus()

    # Ctrl+Enter adds entry in multiline mode
    def eventFilter(self, obj, event):
        if obj is self.multi_entry and event.type() == event.Type.KeyPress:
            if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter) and event.modifiers() == Qt.KeyboardModifier.ControlModifier:
                self.add_entry()
                return True
        return super().eventFilter(obj, event)

    # ---------------- Attachments ----------------

    def add_attachments(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(self, "Select attachments")
        if not files:
            return
        for f in files:
            if f not in self.attachments:
                self.attachments.append(f)
                self.attach_list.addItem(f)
        self.dirty = True

    def remove_selected_attachment(self) -> None:
        row = self.attach_list.currentRow()
        if row < 0:
            return
        val = self.attach_list.item(row).text()
        self.attach_list.takeItem(row)
        self.attachments = [x for x in self.attachments if x != val]
        self.dirty = True

    # ---------------- Filtering ----------------

    def _clear_filters(self) -> None:
        self.filter_edit.setText("")
        self.dt_from.setDateTime(QDateTime.currentDateTime().addDays(-7))
        self.dt_to.setDateTime(QDateTime.currentDateTime().addDays(1))
        self.apply_filters()

    def apply_filters(self) -> None:
        q = (self.filter_edit.text() or "").strip().lower()
        dt_from = self.dt_from.dateTime().toPyDateTime()
        dt_to = self.dt_to.dateTime().toPyDateTime()

        for row in range(self.table.rowCount()):
            it0 = self.table.item(row, 0)
            it1 = self.table.item(row, 1)
            it2 = self.table.item(row, 2)
            it3 = self.table.item(row, 3)
            if not (it0 and it1 and it2 and it3):
                continue

            time_txt = it0.text()
            user_txt = it1.text()
            type_txt = it2.text()
            entry_txt = it3.text()

            in_range = True
            try:
                t = datetime.strptime(time_txt, "%Y-%m-%d %H:%M:%S")
                in_range = (dt_from <= t <= dt_to)
            except Exception:
                in_range = True

            blob = f"{time_txt} {user_txt} {type_txt} {entry_txt}".lower()
            matches = (q in blob) if q else True

            self.table.setRowHidden(row, not (in_range and matches))

    # ---------------- Draft autosave ----------------

    def _context_dict(self) -> dict:
        return {
            "classification": self.class_combo.currentText().strip(),
            "service": self.service_dropdown.currentText().strip(),
            "irr_owner": self.irr_owner_edit.text().strip(),
            "impacted_service": self.impacted_service_edit.text().strip(),
            "summary": self.summary_edit.text().strip(),
        }

    def _autosave_draft(self) -> None:
        if not self.dirty and not self.entries and not self.attachments:
            return

        draft = {
            "schema_version": 1,
            "session_start": self.session_start,
            "ticket": self.current_ticket,
            "context": self._context_dict(),
            "entries": [e.to_dict() for e in self.entries],
            "attachments": list(self.attachments),
        }
        _save_draft(draft)

    def _restore_draft_if_present(self) -> None:
        d = _load_draft()
        if not d:
            return

        resp = QMessageBox.question(
            self,
            "Restore autosaved draft?",
            "An autosaved draft was found.\n\nRestore it?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if resp != QMessageBox.StandardButton.Yes:
            _clear_draft()
            return

        self.current_ticket = d.get("ticket") or None

        self.entries.clear()
        self.table.setRowCount(0)
        self.next_id = 1

        for raw in d.get("entries", []):
            e = Entry(
                id=int(raw.get("id", self.next_id)),
                time=str(raw.get("time", "")),
                user=str(raw.get("user", "")),
                type=str(raw.get("type", "Observation")),
                entry=str(raw.get("entry", "")),
            )
            self.next_id = max(self.next_id, e.id + 1)
            self._append_entry(e, mark_dirty=False)

        self.dirty = True
        self._refresh_ticket_banner()
        self.apply_filters()

    # ---------------- Startup ticket load ----------------

    def _startup_ticket_prompt_and_load(self) -> None:
        ticket, ok = QInputDialog.getText(self, "Ticket", "Enter ticket number to load (leave blank for new):")
        if not ok:
            return
        ticket = _sanitize_ticket(ticket)
        if not ticket:
            return
        self.current_ticket = ticket
        self._refresh_ticket_banner()

    # ---------------- Entries ----------------

    def _get_entry_user(self) -> str:
        return (self.entry_user_edit.text().strip() or getpass.getuser())

    def _get_entry_time(self) -> str:
        return (self.entry_time_edit.text().strip() or _now())

    def _get_entry_text(self) -> str:
        mode = self.entry_mode_combo.currentText().strip()
        if mode.startswith("Single"):
            return self.single_entry.text().strip()
        return self.multi_entry.toPlainText().strip()

    def _clear_entry_text(self) -> None:
        mode = self.entry_mode_combo.currentText().strip()
        if mode.startswith("Single"):
            self.single_entry.clear()
        else:
            self.multi_entry.clear()

    def add_entry(self) -> None:
        text = self._get_entry_text()
        if not text:
            return

        e = Entry(
            id=self.next_id,
            time=self._get_entry_time(),
            user=self._get_entry_user(),
            type=self.type_combo.currentText().strip() or "Observation",
            entry=text,
        )
        self.next_id += 1
        self._append_entry(e, mark_dirty=True)

        self._clear_entry_text()
        self.entry_time_edit.setText(_now())

    def _append_entry(self, e: Entry, *, mark_dirty: bool = True) -> None:
        self.entries.append(e)
        self._insert_or_update_table_row(e)

        if mark_dirty:
            self.dirty = True

        self.table.resizeRowsToContents()
        self.apply_filters()

    def _insert_or_update_table_row(self, e: Entry) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)

        it_time = QTableWidgetItem(e.time)
        it_user = QTableWidgetItem(e.user)
        it_type = QTableWidgetItem(e.type)
        it_entry = QTableWidgetItem(e.entry)
        it_entry.setToolTip(e.entry)

        for it in (it_time, it_user, it_type, it_entry):
            it.setFlags(it.flags() & ~Qt.ItemFlag.ItemIsEditable)

        self.table.setItem(row, 0, it_time)
        self.table.setItem(row, 1, it_user)
        self.table.setItem(row, 2, it_type)
        self.table.setItem(row, 3, it_entry)

    # ---------------- Edit / Delete / Clear ----------------

    def edit_selected_row(self, row: int, col: int) -> None:
        if row < 0:
            return

        it = self.table.item(row, 0)
        if not it:
                return

        entry_id = it.data(Qt.ItemDataRole.UserRole)
        if entry_id is None:
            return

        # find entry in model
        e = next((x for x in self.entries if x.id == entry_id), None)
        if not e:
            return

        dlg = EditEntryDialog(self, time=e.time, user=e.user, etype=e.type, text=e.entry)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        new_time, new_user, new_type, new_text = dlg.get_values()

        # update model
        e.time = new_time
        e.user = new_user
        e.type = new_type
        e.entry = new_text

        # update table cells
        self.table.item(row, 0).setText(e.time)
        self.table.item(row, 1).setText(e.user)
        self.table.item(row, 2).setText(e.type)
        self.table.item(row, 3).setText(e.entry)
        self.table.item(row, 3).setToolTip(e.entry)

        self.dirty = True
        self.table.resizeRowsToContents()
        self.apply_filters()

    def delete_selected(self) -> None:
        row = self.table.currentRow()
        if row < 0:
            return
        self.table.removeRow(row)
        self.dirty = True

    def clear_all(self) -> None:
        self.table.setRowCount(0)
        self.entries.clear()
        self.dirty = True

    # ---------------- Save ----------------

    def _refresh_ticket_banner(self) -> None:
        host = socket.gethostname()
        user = getpass.getuser()
        t = self.current_ticket or "(not set)"
        self.lbl_ticket.setText(f"Ticket: {t}    Host: {host}    User: {user}")

    def finish_and_save(self) -> None:
        QMessageBox.information(self, "Saved", "Save logic is handled in storage.py in your project.")

    # ---------------- Close confirm ----------------

    def closeEvent(self, event) -> None:
        event.accept()


# -----------------------------
# Entry point
# -----------------------------

def main() -> None:
    app = QApplication([])
    app.setStyleSheet(DARK_QSS)
    w = IncidentLogbookWindow()
    w.show()
    app.exec()


if __name__ == "__main__":
    main()
