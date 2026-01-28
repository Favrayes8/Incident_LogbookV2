# storage.py
from __future__ import annotations
import datetime
import getpass
import json
import os
import re
import shutil
from typing import Any

ENTRY_RE = re.compile(
    r"^\[(?P<time>[^\]]+)\]\s+(?P<type>[A-Z ]+)(?:\s+\((?P<user>[^)]+)\))?:\s+(?P<entry>.*)$"
)

SERVICE_OPTIONS = ["CIT", "DCIM", "DWDM", "Switchboard", "Internet Connect", "Metroconnect"]


def now_local_str() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def sanitize_ticket(ticket: str) -> str:
    ticket = (ticket or "").strip().upper()
    for ch in r'\/:*?"<>|':
        ticket = ticket.replace(ch, "-")
    return ticket


def get_documents_path() -> str:
    return os.path.join(os.environ["USERPROFILE"], "Documents")


def generate_filename(ticket_number: str) -> str:
    date_str = datetime.datetime.now().strftime("%Y%m%d")
    user = getpass.getuser().upper()
    ticket_number = sanitize_ticket(ticket_number)
    return f"INCIDENT_{date_str}_{ticket_number}_{user}.txt"


def find_existing_logs_for_ticket(ticket: str, folder: str) -> list[str]:
    ticket = sanitize_ticket(ticket)
    matches: list[str] = []
    try:
        for name in os.listdir(folder):
            if not (name.startswith("INCIDENT_") and name.lower().endswith(".txt")):
                continue
            base = name[:-4]
            parts = base.split("_")
            if len(parts) < 4:
                continue
            if parts[2].upper() == ticket.upper():
                matches.append(os.path.join(folder, name))
    except Exception:
        return []
    matches.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return matches


def parse_incident_txt(path: str) -> dict[str, Any]:
    context = {
        "ticket": "",
        "classification": "",
        "service_dropdown": "",
        "service": "",
        "summary": "",
        "irr_owner": "",
    }
    entries: list[dict[str, str]] = []

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for raw in f:
                line = raw.rstrip("\n")

                if line.startswith("Ticket Number:"):
                    context["ticket"] = line.split(":", 1)[1].strip()
                elif line.startswith("Classification:"):
                    context["classification"] = line.split(":", 1)[1].strip()
                elif line.startswith("Service:"):
                    context["service_dropdown"] = line.split(":", 1)[1].strip()
                elif line.startswith("IRR Owner:"):
                    context["irr_owner"] = line.split(":", 1)[1].strip()
                elif line.startswith("Impacted Service/System:"):
                    context["service"] = line.split(":", 1)[1].strip()
                elif line.startswith("Summary:"):
                    context["summary"] = line.split(":", 1)[1].strip()

                m = ENTRY_RE.match(line)
                if m:
                    entries.append({
                        "time": (m.group("time") or "").strip(),
                        "user": (m.group("user") or "").strip(),
                        "type": (m.group("type") or "").strip().title(),
                        "entry": (m.group("entry") or "").strip(),
                    })
    except Exception:
        return {"context": context, "entries": entries}

    return {"context": context, "entries": entries}


def update_json_log(json_path: str, session_obj: dict[str, Any]) -> None:
    data = {"schema_version": 1, "ticket": session_obj.get("ticket", ""), "sessions": []}
    if os.path.isfile(json_path):
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                existing = json.load(f)
            if isinstance(existing, dict):
                data["schema_version"] = existing.get("schema_version", 1)
                data["ticket"] = existing.get("ticket", data["ticket"])
                sessions = existing.get("sessions", [])
                if isinstance(sessions, list):
                    data["sessions"] = sessions
        except Exception:
            data["sessions"] = []
    data["sessions"].append(session_obj)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


# ---------- Draft autosave ----------
def app_data_dir() -> str:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    d = os.path.join(base, "IncidentLogbook")
    os.makedirs(d, exist_ok=True)
    return d


def draft_path() -> str:
    return os.path.join(app_data_dir(), "draft_autosave.json")


def save_draft(draft: dict[str, Any]) -> None:
    with open(draft_path(), "w", encoding="utf-8") as f:
        json.dump(draft, f, indent=2)


def load_draft() -> dict[str, Any] | None:
    p = draft_path()
    if not os.path.isfile(p):
        return None
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def clear_draft() -> None:
    p = draft_path()
    try:
        if os.path.isfile(p):
            os.remove(p)
    except Exception:
        pass


# ---------- Attachments ----------
def ensure_attachment_dir_for_target_txt(target_txt_path: str) -> str:
    base = os.path.splitext(target_txt_path)[0]
    adir = base + "_attachments"
    os.makedirs(adir, exist_ok=True)
    return adir


def copy_attachments(files: list[str], attachment_dir: str) -> list[str]:
    """
    Copy attachment files into incident attachment directory.
    Returns list of copied absolute paths.
    """
    copied: list[str] = []
    for src in files:
        if not src or not os.path.isfile(src):
            continue
        name = os.path.basename(src)
        dst = os.path.join(attachment_dir, name)

        # Avoid overwriting by suffixing
        if os.path.exists(dst):
            root, ext = os.path.splitext(name)
            i = 2
            while True:
                dst = os.path.join(attachment_dir, f"{root}_{i}{ext}")
                if not os.path.exists(dst):
                    break
                i += 1

        shutil.copy2(src, dst)
        copied.append(dst)
    return copied
