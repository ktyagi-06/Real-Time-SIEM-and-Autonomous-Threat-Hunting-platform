"""Log parsers: turn raw lines from different sources into normalized Events.

Supported formats (auto-detected per line):
  * Linux syslog (BSD or ISO timestamps): sshd, sudo, useradd/usermod
  * nginx / Apache combined access logs
  * Windows Security events exported as JSON (4624, 4625, 4688, 4720, 4732, 1102 ...)
  * Generic JSON lines, including firewall / flow records
"""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import unquote_plus

from .models import CATEGORIES, Event

SYSLOG_RE = re.compile(
    r"^(?:(?P<ts_old>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})"
    r"|(?P<ts_iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?))"
    r"\s+(?P<host>\S+)\s+(?P<prog>[\w\-./]+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)

SSH_FAIL_RE = re.compile(
    r"Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
)
SSH_OK_RE = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
)
SUDO_RE = re.compile(
    r"^\s*(?P<user>\S+)\s*:\s*(?:TTY=\S+\s*;\s*)?(?:PWD=\S+\s*;\s*)?USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<cmd>.*)$"
)
USERADD_RE = re.compile(r"new user: name=(?P<user>[^,\s]+)")
GROUPADD_RE = re.compile(r"add '(?P<user>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'")

WEB_RE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<method>[A-Z]+) (?P<url>\S+)(?: [^"]*)?" '
    r'(?P<status>\d{3}) (?P<size>\S+)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)

WIN_EVENTS = {
    4624: ("auth_success", "success"),
    4625: ("auth_failure", "failure"),
    4688: ("process_start", None),
    4720: ("account_change", None),
    4728: ("account_change", None),
    4732: ("account_change", None),
    4756: ("account_change", None),
    1102: ("log_clear", None),
    104: ("log_clear", None),
}


# ---------------------------------------------------------------- helpers
def parse_ts(value: Any, ref_time: Optional[float] = None) -> Optional[float]:
    """Best-effort timestamp parsing: epoch numbers, ISO-8601 strings."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        v = float(value)
        return v / 1000.0 if v > 1e11 else v
    s = str(value).strip()
    if not s:
        return None
    if re.fullmatch(r"\d+(\.\d+)?", s):
        return parse_ts(float(s))
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        return None


def _bsd_ts(text: str, ref_time: float) -> float:
    ref = datetime.fromtimestamp(ref_time, tz=timezone.utc)
    dt = datetime.strptime(f"{ref.year} {' '.join(text.split())}", "%Y %b %d %H:%M:%S")
    dt = dt.replace(tzinfo=timezone.utc)
    ts = dt.timestamp()
    if ts > ref_time + 86400:  # "Dec 31" parsed in January -> previous year
        ts = dt.replace(year=dt.year - 1).timestamp()
    return ts


def _clean_ip(value: Any) -> Optional[str]:
    if value is None:
        return None
    s = str(value).strip()
    if s in ("", "-", "::1", "127.0.0.1", "::", "0.0.0.0", "N/A"):
        return None if s in ("", "-", "::", "0.0.0.0", "N/A") else s
    return s.replace("::ffff:", "")


def _basename(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    return re.split(r"[\\/]", path.strip())[-1] or None


# ---------------------------------------------------------------- parsers
def parse_syslog(line: str, ref_time: float, default_host: Optional[str]) -> Optional[Event]:
    m = SYSLOG_RE.match(line)
    if not m:
        return None
    if m.group("ts_old"):
        ts = _bsd_ts(m.group("ts_old"), ref_time)
    else:
        ts = parse_ts(m.group("ts_iso"))
        if ts is None:
            return None
    host, prog, msg = m.group("host"), m.group("prog"), m.group("msg")
    base = dict(ts=ts, host=host or default_host or "unknown", raw=line, message=msg, process=prog)

    if prog == "sshd":
        f = SSH_FAIL_RE.search(msg)
        if f:
            return Event(
                source="auth", category="auth_failure", user=f["user"], src_ip=_clean_ip(f["ip"]),
                outcome="failure", extra={"method": f["method"], "port": int(f["port"]), "service": "ssh"}, **base,
            )
        s = SSH_OK_RE.search(msg)
        if s:
            return Event(
                source="auth", category="auth_success", user=s["user"], src_ip=_clean_ip(s["ip"]),
                outcome="success", extra={"method": s["method"], "port": int(s["port"]), "service": "ssh"}, **base,
            )
    elif prog == "sudo":
        s = SUDO_RE.match(msg)
        if s:
            cmd = s["cmd"].strip()
            return Event(
                source="auth", category="privilege", user=s["user"], command_line=cmd,
                extra={"target_user": s["target"]}, **{**base, "process": _basename(cmd.split()[0]) if cmd else "sudo"},
            )
    elif prog in ("useradd", "adduser", "usermod", "gpasswd"):
        u = USERADD_RE.search(msg)
        if u:
            return Event(
                source="auth", category="account_change", user=u["user"],
                extra={"action": "user_created"}, **base,
            )
        g = GROUPADD_RE.search(msg)
        if g:
            return Event(
                source="auth", category="account_change", user=g["user"],
                extra={"action": "group_member_added", "group": g["group"]}, **base,
            )
    return Event(source="system", category="generic", **base)


def parse_web(line: str, default_host: Optional[str]) -> Optional[Event]:
    m = WEB_RE.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(m["time"], "%d/%b/%Y:%H:%M:%S %z").timestamp()
    except ValueError:
        return None
    url = m["url"]
    status = int(m["status"])
    return Event(
        ts=ts,
        source="web",
        host=default_host or "webserver",
        category="web_request",
        user=None if m["user"] == "-" else m["user"],
        src_ip=_clean_ip(m["ip"]),
        outcome="success" if status < 400 else "failure",
        message=f'{m["method"]} {url} -> {status}',
        raw=line,
        extra={"method": m["method"], "url": url, "status": status, "ua": m["ua"] or "", "bytes": m["size"]},
    )


def _short_member(member: Any) -> Optional[str]:
    if not member:
        return None
    m = re.search(r"CN=([^,]+)", str(member))
    return m.group(1) if m else str(member)


def parse_json_event(line: str, ref_time: float, default_host: Optional[str]) -> Optional[Event]:
    try:
        d = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(d, dict):
        return None

    ts = None
    for key in ("TimeCreated", "timestamp", "ts", "time", "@timestamp", "UtcTime"):
        if key in d:
            ts = parse_ts(d[key])
            if ts is not None:
                break
    if ts is None:
        ts = ref_time

    # ---- Windows security events
    if "EventID" in d:
        try:
            eid = int(d["EventID"])
        except (TypeError, ValueError):
            eid = -1
        host = d.get("Computer") or default_host or "unknown"
        if eid in WIN_EVENTS:
            category, outcome = WIN_EVENTS[eid]
            ev = Event(ts=ts, source="endpoint", host=host, category=category, outcome=outcome, raw=line,
                       extra={"event_id": eid})
            if eid in (4624, 4625):
                ev.source = "auth"
                ev.user = d.get("TargetUserName")
                ev.src_ip = _clean_ip(d.get("IpAddress"))
                ev.extra.update(logon_type=d.get("LogonType"), workstation=d.get("WorkstationName"), service="windows")
                ev.message = f"Logon {'success' if eid == 4624 else 'failure'} for {ev.user}"
            elif eid == 4688:
                ev.user = d.get("SubjectUserName")
                ev.process = _basename(d.get("NewProcessName"))
                ev.command_line = d.get("CommandLine") or d.get("NewProcessName")
                ev.message = f"Process created: {ev.command_line}"
            elif eid == 4720:
                ev.user = d.get("TargetUserName")
                ev.extra.update(action="user_created", actor=d.get("SubjectUserName"))
                ev.message = f"Account {ev.user} created by {d.get('SubjectUserName')}"
            elif eid in (4728, 4732, 4756):
                ev.user = _short_member(d.get("MemberName") or d.get("TargetUserName"))
                ev.extra.update(action="group_member_added", group=d.get("TargetUserName") if d.get("MemberName") else d.get("GroupName"),
                                actor=d.get("SubjectUserName"))
                ev.message = f"{ev.user} added to group {ev.extra.get('group')}"
            else:
                ev.user = d.get("SubjectUserName")
                ev.message = "Audit log cleared"
            return ev
        return Event(ts=ts, source="endpoint", host=host, category="generic", raw=line,
                     message=f"Windows event {eid}", extra={"event_id": eid})

    # ---- flow / firewall records
    host = d.get("host") or d.get("hostname") or default_host or "unknown"
    if d.get("type") == "flow" or ("dst_port" in d and "action" in d):
        action = str(d.get("action", "")).lower()
        port = d.get("dst_port")
        return Event(
            ts=ts, source="network", host=host, category="network_conn", src_ip=_clean_ip(d.get("src_ip")),
            dst_ip=_clean_ip(d.get("dst_ip")), dst_port=int(port) if port not in (None, "") else None,
            outcome=action or None, raw=line,
            message=f"{d.get('src_ip')} -> {d.get('dst_ip')}:{port} {action}",
            extra={k: v for k, v in d.items() if k in ("proto", "bytes", "direction")},
        )

    # ---- generic JSON
    category = d.get("category", "generic")
    if category not in CATEGORIES:
        category = "generic"
    port = d.get("dst_port")
    return Event(
        ts=ts, source=d.get("source", "generic"), host=host, category=category, user=d.get("user"),
        src_ip=_clean_ip(d.get("src_ip")), dst_ip=_clean_ip(d.get("dst_ip")),
        dst_port=int(port) if port not in (None, "") else None,
        process=d.get("process"), command_line=d.get("command_line"), outcome=d.get("outcome"),
        message=str(d.get("message", "")), raw=line, extra=d.get("extra", {}) if isinstance(d.get("extra"), dict) else {},
    )


# ---------------------------------------------------------------- entry point
def parse_line(line: str, ref_time: Optional[float] = None, default_host: Optional[str] = None) -> Optional[Event]:
    line = line.strip()
    if not line:
        return None
    ref_time = ref_time or time.time()
    if line.startswith("{"):
        return parse_json_event(line, ref_time, default_host)
    if SYSLOG_RE.match(line):
        return parse_syslog(line, ref_time, default_host)
    return parse_web(line, default_host)


def parse_lines(
    lines: Iterable[str], ref_time: Optional[float] = None, default_host: Optional[str] = None
) -> Tuple[List[Event], int]:
    """Parse many lines; returns (events, number_of_unparseable_lines)."""
    events: List[Event] = []
    bad = 0
    for line in lines:
        if not line.strip():
            continue
        try:
            ev = parse_line(line, ref_time, default_host)
        except Exception:  # a hostile log line must never break ingestion
            ev = None
        if ev is None:
            bad += 1
        else:
            events.append(ev)
    return events, bad


def decoded_url(url: str) -> str:
    """URL-decode twice so double-encoded payloads are still matched."""
    return unquote_plus(unquote_plus(url))
