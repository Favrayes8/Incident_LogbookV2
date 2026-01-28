# storage.py
from __future__ import annotations

import datetime as _dt
import getpass
import json
import os
import re
import shutil
from typing import Optional, Tuple, Any

# -------------------------------
# Public constants used by main.py
# -------------------------------

SERVICE_OPTIONS = [
    "CIT",
    "DCIM",
    "DWDM",
    "Switchboard",
    "Internet connect",
    "Metroconnect",
    "Security",
    "Compute",
    "Storage",
    "Other",
]

_DRAFT_FILENAME = "Incident_Logbook_DRAFT.json"
ENTRY_RE = re.compile(r"^\[(?P<time>[^\]]+)\]\s+(?P<type>[A-Z ]+):\s+(?P<entry>.*)$")


# -------------------------------
# Time / paths
# -------------------------------

def now_local_str() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_documents_path() -> str:
    home = os.environ.get("USERPROFILE") or os.path.expanduser("~")
    return os.path.join(home, "Documents")


# -------------------------------
# Ticket / filenames
# -------------------------------

def sanitize_ticket(ticket: str) -> str:
    ticket = (ticket or "").strip().upper()
    for ch in r'\/:*?"<>|':
        ticket = ticket.replace(ch, "-")
    return ticket


def generate_filename(ticket_number: str) -> str:
    date_str = _dt.datetime.now().strftime("%Y%m%d")
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
            if len(parts) >= 4 and parts[2].upper() == ticket.upper():
                matches.append(os.path.join(folder, name))
    except Exception:
        return []

    matches.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return matches


# -------------------------------
# Parse TXT
# -------------------------------

def parse_incident_txt(path: str) -> dict:
    context = {
        "ticket": "",
        "classification": "",
        "service": "",
        "irr_owner": "",
        "impacted_service": "",
        "summary": "",
    }
    entries: list[dict] = []

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for raw in f:
                line = raw.rstrip("\n")

                if line.startswith("Ticket Number:"):
                    context["ticket"] = line.split(":", 1)[1].strip()
                elif line.startswith("Classification:"):
                    context["classification"] = line.split(":", 1)[1].strip()
                elif line.startswith("Service:"):
                    context["service"] = line.split(":", 1)[1].strip()
                elif line.startswith("IRR Owner:"):
                    context["irr_owner"] = line.split(":", 1)[1].strip()
                elif line.startswith("Impacted Service/System:"):
                    context["impacted_service"] = line.split(":", 1)[1].strip()
                elif line.startswith("Summary:"):
                    context["summary"] = line.split(":", 1)[1].strip()

                m = ENTRY_RE.match(line)
                if m:
                    entries.append(
                        {
                            "time": m.group("time").strip(),
                            "type": m.group("type").strip().title(),
                            "entry": m.group("entry").strip(),
                        }
                    )
    except Exception:
        return {"context": context, "entries": entries}

    return {"context": context, "entries": entries}


# -------------------------------
# Draft autosave
# -------------------------------

def _draft_path() -> str:
    docs = get_documents_path()
    os.makedirs(docs, exist_ok=True)
    return os.path.join(docs, _DRAFT_FILENAME)


def save_draft(data: dict) -> None:
    try:
        with open(_draft_path(), "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


def load_draft() -> Optional[dict]:
    p = _draft_path()
    if not os.path.isfile(p):
        return None
    try:
        with open(p, "r", encoding="utf-8") as f:
            val = json.load(f)
        return val if isinstance(val, dict) else None
    except Exception:
        return None


def clear_draft() -> None:
    try:
        p = _draft_path()
        if os.path.isfile(p):
            os.remove(p)
    except Exception:
        pass


# -------------------------------
# JSON log
# -------------------------------

def update_json_log(json_path: str, session_obj: dict) -> None:
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


# -------------------------------
# Save / Append
# -------------------------------

def save_incident_log(*args: Any, **kwargs: Any) -> Tuple[str, str]:
    """
    Flexible saver to match different main.py call signatures.

    Accepts ANY of these patterns (and ignores unknown extras):
      - append=True/False
      - append_to="path/to/existing.txt"
      - target_txt_path="path/to/new.txt"
      - txt_path="path/to/new.txt" (alias)
      - ticket=...
      - session_start=..., session_end=...
      - context=dict, entries=list, attachments=list

    Returns (txt_path, json_path)
    """
    # --- normalize common keyword names ---
    ticket = sanitize_ticket(str(kwargs.get("ticket") or ""))
    if not ticket:
        raise ValueError("ticket is required")

    session_start = str(kwargs.get("session_start") or now_local_str())
    session_end = str(kwargs.get("session_end") or now_local_str())

    context = kwargs.get("context") or {}
    entries = kwargs.get("entries") or []
    attachments = kwargs.get("attachments") or []

    # --- append handling (this is what your error screenshot is about) ---
    append_flag = bool(kwargs.get("append", False))
    append_to = kwargs.get("append_to")
    target_txt_path = kwargs.get("target_txt_path") or kwargs.get("txt_path")

    docs = get_documents_path()
    os.makedirs(docs, exist_ok=True)

    if append_to:
        txt_path = str(append_to)
        mode = "a"
    elif append_flag:
        # If append=True but no explicit file, append to newest existing for ticket
        existing = find_existing_logs_for_ticket(ticket, docs)
        if existing:
            txt_path = existing[0]
            mode = "a"
        else:
            # Nothing to append to -> create new
            txt_path = target_txt_path or os.path.join(docs, generate_filename(ticket))
            mode = "w"
    else:
        txt_path = target_txt_path or os.path.join(docs, generate_filename(ticket))
        mode = "w"

    # --- pull context fields safely ---
    user = str(context.get("user") or getpass.getuser()).strip()
    host = str(context.get("host") or os.environ.get("COMPUTERNAME") or "").strip()

    classification = str(context.get("classification") or "IMPACT").strip() or "IMPACT"
    service = str(context.get("service") or "").strip()
    irr_owner = str(context.get("irr_owner") or "").strip()
    impacted_service = str(context.get("impacted_service") or "").strip()
    summary = str(context.get("summary") or "").strip()

    # Build session for JSON
    session_obj = {
        "session_start": session_start,
        "session_end": session_end,
        "ticket": ticket,
        "context": {
            "classification": classification,
            "service": service,
            "irr_owner": irr_owner,
            "impacted_service": impacted_service,
            "summary": summary,
            "user": user,
            "host": host,
        },
        "entries": [
            {
                "time": str(e.get("time", "")).strip(),
                "user": str(e.get("user", "")).strip(),
                "type": str(e.get("type", "")).strip(),
                "entry": str(e.get("entry", "")).strip(),
            }
            for e in entries
            if isinstance(e, dict)
        ],
    }

    # Write TXT
    with open(txt_path, mode, encoding="utf-8") as f:
        if mode == "a":
            f.write("\n\n")
            f.write("#" * 72 + "\n")
            f.write(f"APPENDED SESSION - {session_end}\n")
            f.write("#" * 72 + "\n")

        f.write("Incident Log\n")
        f.write("=" * 72 + "\n")
        f.write(f"Ticket Number: {ticket}\n")
        f.write(f"Classification: {classification}\n")
        if service:
            f.write(f"Service: {service}\n")
        if irr_owner:
            f.write(f"IRR Owner: {irr_owner}\n")
        if impacted_service:
            f.write(f"Impacted Service/System: {impacted_service}\n")
        if summary:
            f.write(f"Summary: {summary}\n")
        if user:
            f.write(f"User: {user}\n")
        if host:
            f.write(f"Host: {host}\n")
        f.write(f"Session Start: {session_start}\n")
        f.write(f"Session End: {session_end}\n")
        f.write("=" * 72 + "\n\n")

        for e in entries:
            if not isinstance(e, dict):
                continue
            t = str(e.get("time", "")).strip()
            ty = str(e.get("type", "Observation")).strip() or "Observation"
            msg = str(e.get("entry", "")).strip()
            if not (t and msg):
                continue
            f.write(f"[{t}] {ty.upper()}: {msg}\n")

    # Copy attachments (best effort)
    if attachments:
        att_dir = os.path.join(os.path.dirname(txt_path), "Attachments")
        os.makedirs(att_dir, exist_ok=True)

        for src in attachments:
            try:
                if not src or not os.path.isfile(src):
                    continue
                base = os.path.basename(src)
                dst = os.path.join(att_dir, base)
                if os.path.exists(dst):
                    root, ext = os.path.splitext(base)
                    i = 1
                    while True:
                        cand = os.path.join(att_dir, f"{root}_{i}{ext}")
                        if not os.path.exists(cand):
                            dst = cand
                            break
                        i += 1
                shutil.copy2(src, dst)
            except Exception:
                pass

    # JSON alongside TXT
    json_path = os.path.splitext(txt_path)[0] + ".json"
    update_json_log(json_path, session_obj)

    return txt_path, json_path
