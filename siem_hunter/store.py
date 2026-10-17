"""SQLite-backed storage for events, alerts, investigations, response actions and audit log."""
from __future__ import annotations

import hashlib
import json
import shlex
import sqlite3
import threading
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .models import SEV_RANK, AlertDraft, Event

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fp TEXT UNIQUE,
    ts REAL NOT NULL,
    source TEXT, host TEXT, category TEXT, user TEXT,
    src_ip TEXT, dst_ip TEXT, dst_port INTEGER,
    process TEXT, command_line TEXT, outcome TEXT,
    message TEXT, raw TEXT, extra TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_cat_ts ON events(category, ts);
CREATE INDEX IF NOT EXISTS idx_events_src ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(user);
CREATE INDEX IF NOT EXISTS idx_events_host ON events(host);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT, entity TEXT, title TEXT, severity TEXT, sev_rank INTEGER,
    src_ip TEXT, user TEXT, host TEXT,
    first_seen REAL, last_seen REAL,
    event_ids TEXT, event_count INTEGER,
    techniques TEXT, description TEXT,
    status TEXT DEFAULT 'new',
    risk_score INTEGER DEFAULT 0, verdict TEXT DEFAULT '',
    created_at REAL, updated_at REAL, extra TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_id, entity);
CREATE INDEX IF NOT EXISTS idx_alerts_seen ON alerts(last_seen);

CREATE TABLE IF NOT EXISTS investigations (
    alert_id INTEGER PRIMARY KEY, data TEXT, updated_at REAL
);

CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER, type TEXT, target TEXT, reason TEXT, priority TEXT,
    status TEXT, created_at REAL, decided_at REAL, decided_by TEXT,
    executed_at REAL, result TEXT, reverted_at REAL
);
CREATE INDEX IF NOT EXISTS idx_actions_alert ON actions(alert_id);

CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL, actor TEXT, event TEXT, detail TEXT
);

CREATE TABLE IF NOT EXISTS enforcement (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT, target TEXT, action_id INTEGER, active INTEGER DEFAULT 1, created_at REAL
);
"""


def _fingerprint(ev: Event) -> str:
    return hashlib.sha1(f"{ev.ts:.3f}|{ev.host}|{ev.raw}".encode("utf-8", "replace")).hexdigest()


class Store:
    def __init__(self, path: str = ":memory:"):
        self.path = path
        if path != ":memory:":
            import os

            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(SCHEMA)
        self._db.commit()

    # ------------------------------------------------------------ events
    def insert_events(self, events: Iterable[Event]) -> List[Event]:
        """Insert events, skipping exact duplicates. Returns the newly inserted ones (with ids)."""
        inserted: List[Event] = []
        with self._lock:
            cur = self._db.cursor()
            for ev in events:
                cur.execute(
                    "INSERT OR IGNORE INTO events (fp, ts, source, host, category, user, src_ip, dst_ip, dst_port,"
                    " process, command_line, outcome, message, raw, extra) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        _fingerprint(ev), ev.ts, ev.source, ev.host, ev.category, ev.user, ev.src_ip, ev.dst_ip,
                        ev.dst_port, ev.process, ev.command_line, ev.outcome, ev.message[:2000], ev.raw[:4000],
                        json.dumps(ev.extra),
                    ),
                )
                if cur.rowcount:
                    ev.id = cur.lastrowid
                    inserted.append(ev)
            self._db.commit()
        return inserted

    @staticmethod
    def _row_event(r: sqlite3.Row) -> Event:
        return Event(
            id=r["id"], ts=r["ts"], source=r["source"], host=r["host"], category=r["category"], user=r["user"],
            src_ip=r["src_ip"], dst_ip=r["dst_ip"], dst_port=r["dst_port"], process=r["process"],
            command_line=r["command_line"], outcome=r["outcome"], message=r["message"] or "", raw=r["raw"] or "",
            extra=json.loads(r["extra"] or "{}"),
        )

    def events(
        self,
        categories: Optional[List[str]] = None,
        since: Optional[float] = None,
        until: Optional[float] = None,
        src_ips: Optional[Iterable[str]] = None,
        users: Optional[Iterable[str]] = None,
        hosts: Optional[Iterable[str]] = None,
        limit: int = 20000,
        newest_first: bool = False,
    ) -> List[Event]:
        where, args = [], []
        if categories:
            where.append(f"category IN ({','.join('?' * len(categories))})")
            args += list(categories)
        if since is not None:
            where.append("ts >= ?")
            args.append(since)
        if until is not None:
            where.append("ts <= ?")
            args.append(until)
        for col, vals in (("src_ip", src_ips), ("user", users), ("host", hosts)):
            if vals is not None:
                vals = [v for v in vals if v]
                if not vals:
                    return []
                where.append(f"{col} IN ({','.join('?' * len(vals))})")
                args += vals
        sql = "SELECT * FROM events"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += f" ORDER BY ts {'DESC' if newest_first else 'ASC'}, id {'DESC' if newest_first else 'ASC'} LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._db.execute(sql, args).fetchall()
        return [self._row_event(r) for r in rows]

    def events_by_ids(self, ids: List[int]) -> List[Event]:
        if not ids:
            return []
        out: List[Event] = []
        with self._lock:
            for i in range(0, len(ids), 500):
                chunk = ids[i : i + 500]
                rows = self._db.execute(
                    f"SELECT * FROM events WHERE id IN ({','.join('?' * len(chunk))}) ORDER BY ts, id", chunk
                ).fetchall()
                out += [self._row_event(r) for r in rows]
        out.sort(key=lambda e: (e.ts, e.id or 0))
        return out

    def search(self, query: str = "", limit: int = 200, since: Optional[float] = None) -> List[Event]:
        """Tiny query language: free text plus field:value tokens (ip, user, host, category, process, port)."""
        fields = {"ip": "(src_ip=? OR dst_ip=?)", "user": "user=?", "host": "host=?", "category": "category=?",
                  "process": "process=?", "port": "dst_port=?", "outcome": "outcome=?", "source": "source=?"}
        where, args = [], []
        try:
            tokens = shlex.split(query)
        except ValueError:
            tokens = query.split()
        for tok in tokens:
            if ":" in tok and tok.split(":", 1)[0].lower() in fields:
                k, v = tok.split(":", 1)
                k = k.lower()
                where.append(fields[k])
                args += [v, v] if k == "ip" else [v]
            else:
                like = f"%{tok}%"
                where.append("(message LIKE ? OR command_line LIKE ? OR raw LIKE ?)")
                args += [like, like, like]
        if since is not None:
            where.append("ts >= ?")
            args.append(since)
        sql = "SELECT * FROM events" + (" WHERE " + " AND ".join(where) if where else "")
        sql += " ORDER BY ts DESC, id DESC LIMIT ?"
        args.append(min(max(limit, 1), 2000))
        with self._lock:
            rows = self._db.execute(sql, args).fetchall()
        return [self._row_event(r) for r in rows]

    def max_ts(self) -> Optional[float]:
        with self._lock:
            r = self._db.execute("SELECT MAX(ts) AS m FROM events").fetchone()
        return r["m"]

    def count_events(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]

    def counts_by_host_hour(self, since: float, until: float) -> Dict[str, Dict[int, int]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT host, CAST(ts/3600 AS INTEGER) AS hr, COUNT(*) AS c FROM events "
                "WHERE ts BETWEEN ? AND ? GROUP BY host, hr",
                (since, until),
            ).fetchall()
        out: Dict[str, Dict[int, int]] = {}
        for r in rows:
            out.setdefault(r["host"], {})[r["hr"]] = r["c"]
        return out

    def user_hosts_before(self, user: str, ts: float, days: int = 7) -> set:
        """Hosts this account successfully logged in to during the `days` before `ts`."""
        with self._lock:
            rows = self._db.execute(
                "SELECT DISTINCT host FROM events WHERE category='auth_success' AND user=? AND ts < ? AND ts >= ?",
                (user, ts, ts - days * 86400),
            ).fetchall()
        return {r["host"] for r in rows}

    def ip_history(self, ip: str) -> Dict[str, Any]:
        with self._lock:
            r = self._db.execute(
                "SELECT COUNT(*) c, MIN(ts) first, MAX(ts) last, COUNT(DISTINCT host) hosts, COUNT(DISTINCT user) users "
                "FROM events WHERE src_ip=?",
                (ip,),
            ).fetchone()
        return dict(r)

    # ------------------------------------------------------------ alerts
    @staticmethod
    def _row_alert(r: sqlite3.Row) -> Dict[str, Any]:
        d = dict(r)
        d["event_ids"] = json.loads(d["event_ids"] or "[]")
        d["techniques"] = json.loads(d["techniques"] or "[]")
        d["extra"] = json.loads(d["extra"] or "{}")
        d.pop("sev_rank", None)
        return d

    def upsert_alert(self, draft: AlertDraft) -> Tuple[int, bool, bool]:
        """Create the alert, or extend an existing one for the same rule+entity. -> (id, created, changed)."""
        now = time.time()
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM alerts WHERE rule_id=? AND entity=? AND status NOT IN ('resolved','false_positive') "
                "AND last_seen >= ? AND first_seen <= ? ORDER BY last_seen DESC LIMIT 1",
                (draft.rule_id, draft.entity, draft.first_seen - draft.merge_window,
                 draft.last_seen + draft.merge_window),
            ).fetchone()
            if row is None:
                cur = self._db.execute(
                    "INSERT INTO alerts (rule_id, entity, title, severity, sev_rank, src_ip, user, host, first_seen,"
                    " last_seen, event_ids, event_count, techniques, description, status, created_at, updated_at, extra)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,'new',?,?,?)",
                    (
                        draft.rule_id, draft.entity, draft.title, draft.severity, SEV_RANK[draft.severity],
                        draft.src_ip, draft.user, draft.host, draft.first_seen, draft.last_seen,
                        json.dumps(sorted(set(draft.event_ids))), len(set(draft.event_ids)),
                        json.dumps(draft.techniques), draft.description, now, now, json.dumps(draft.extra),
                    ),
                )
                self._db.commit()
                return cur.lastrowid, True, True

            existing = set(json.loads(row["event_ids"] or "[]"))
            merged = existing | set(draft.event_ids)
            changed = len(merged) > len(existing)
            sev = draft.severity if SEV_RANK[draft.severity] > row["sev_rank"] else row["severity"]
            techs = sorted(set(json.loads(row["techniques"] or "[]")) | set(draft.techniques))
            if changed or sev != row["severity"]:
                self._db.execute(
                    "UPDATE alerts SET severity=?, sev_rank=?, first_seen=?, last_seen=?, event_ids=?, event_count=?,"
                    " title=?, description=?, techniques=?, updated_at=?, extra=? WHERE id=?",
                    (
                        sev, SEV_RANK[sev], min(row["first_seen"], draft.first_seen),
                        max(row["last_seen"], draft.last_seen), json.dumps(sorted(merged)), len(merged),
                        draft.title, draft.description, json.dumps(techs), now, json.dumps(draft.extra), row["id"],
                    ),
                )
                self._db.commit()
            return row["id"], False, changed or sev != row["severity"]

    def get_alert(self, alert_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            r = self._db.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        return self._row_alert(r) if r else None

    def list_alerts(
        self, severity: Optional[str] = None, status: Optional[str] = None, limit: int = 200, since: Optional[float] = None
    ) -> List[Dict[str, Any]]:
        where, args = [], []
        if severity:
            where.append("severity=?")
            args.append(severity)
        if status:
            where.append("status=?")
            args.append(status)
        if since is not None:
            where.append("last_seen >= ?")
            args.append(since)
        sql = "SELECT * FROM alerts" + (" WHERE " + " AND ".join(where) if where else "")
        sql += " ORDER BY risk_score DESC, sev_rank DESC, last_seen DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._db.execute(sql, args).fetchall()
        out = []
        for r in rows:
            d = self._row_alert(r)
            d["event_ids"] = d["event_ids"][:0]  # list view stays light
            out.append(d)
        return out

    def all_alerts_between(self, since: float, until: float) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM alerts WHERE last_seen >= ? AND first_seen <= ? ORDER BY first_seen", (since, until)
            ).fetchall()
        return [self._row_alert(r) for r in rows]

    def update_alert(self, alert_id: int, **fields: Any) -> None:
        allowed = {"status", "risk_score", "verdict"}
        sets, args = [], []
        for k, v in fields.items():
            if k in allowed:
                sets.append(f"{k}=?")
                args.append(v)
        if not sets:
            return
        sets.append("updated_at=?")
        args += [time.time(), alert_id]
        with self._lock:
            self._db.execute(f"UPDATE alerts SET {', '.join(sets)} WHERE id=?", args)
            self._db.commit()

    # ------------------------------------------------------------ investigations
    def save_investigation(self, alert_id: int, data: Dict[str, Any]) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO investigations (alert_id, data, updated_at) VALUES (?,?,?) "
                "ON CONFLICT(alert_id) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at",
                (alert_id, json.dumps(data), time.time()),
            )
            self._db.commit()

    def get_investigation(self, alert_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            r = self._db.execute("SELECT data FROM investigations WHERE alert_id=?", (alert_id,)).fetchone()
        return json.loads(r["data"]) if r else None

    # ------------------------------------------------------------ actions
    def add_action(self, alert_id: int, type_: str, target: str, reason: str, priority: str, status: str, result: str = "") -> int:
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO actions (alert_id, type, target, reason, priority, status, created_at, result)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (alert_id, type_, target, reason, priority, status, time.time(), result),
            )
            self._db.commit()
            return cur.lastrowid

    def find_action(self, alert_id: int, type_: str, target: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            r = self._db.execute(
                "SELECT * FROM actions WHERE alert_id=? AND type=? AND target=? AND status != 'reverted' "
                "ORDER BY id DESC LIMIT 1",
                (alert_id, type_, target),
            ).fetchone()
        return dict(r) if r else None

    def find_open_action(self, type_: str, target: str) -> Optional[Dict[str, Any]]:
        """A pending or executed action of this kind on this target, from any alert."""
        with self._lock:
            r = self._db.execute(
                "SELECT * FROM actions WHERE type=? AND target=? AND status IN ('pending','executed') ORDER BY id LIMIT 1",
                (type_, target),
            ).fetchone()
        return dict(r) if r else None

    def get_action(self, action_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            r = self._db.execute("SELECT * FROM actions WHERE id=?", (action_id,)).fetchone()
        return dict(r) if r else None

    def list_actions(self, alert_id: Optional[int] = None, status: Optional[str] = None, limit: int = 200) -> List[Dict[str, Any]]:
        where, args = [], []
        if alert_id is not None:
            where.append("alert_id=?")
            args.append(alert_id)
        if status:
            where.append("status=?")
            args.append(status)
        sql = "SELECT * FROM actions" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            return [dict(r) for r in self._db.execute(sql, args).fetchall()]

    def update_action(self, action_id: int, **fields: Any) -> None:
        allowed = {"status", "decided_at", "decided_by", "executed_at", "result", "reverted_at"}
        sets, args = [], []
        for k, v in fields.items():
            if k in allowed:
                sets.append(f"{k}=?")
                args.append(v)
        if not sets:
            return
        args.append(action_id)
        with self._lock:
            self._db.execute(f"UPDATE actions SET {', '.join(sets)} WHERE id=?", args)
            self._db.commit()

    # ------------------------------------------------------------ enforcement + audit
    def add_enforcement(self, kind: str, target: str, action_id: int) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO enforcement (kind, target, action_id, active, created_at) VALUES (?,?,?,1,?)",
                (kind, target, action_id, time.time()),
            )
            self._db.commit()

    def deactivate_enforcement(self, action_id: int) -> None:
        with self._lock:
            self._db.execute("UPDATE enforcement SET active=0 WHERE action_id=?", (action_id,))
            self._db.commit()

    def list_enforcement(self, active_only: bool = True) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM enforcement" + (" WHERE active=1" if active_only else "") + " ORDER BY id DESC"
        with self._lock:
            return [dict(r) for r in self._db.execute(sql).fetchall()]

    def audit(self, actor: str, event: str, detail: Any = None) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO audit (ts, actor, event, detail) VALUES (?,?,?,?)",
                (time.time(), actor, event, json.dumps(detail) if not isinstance(detail, str) else detail),
            )
            self._db.commit()

    def list_audit(self, limit: int = 200) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]

    # ------------------------------------------------------------ stats
    def stats(self, since: Optional[float] = None, bucket: int = 600) -> Dict[str, Any]:
        with self._lock:
            max_ts = self.max_ts()
            since = since if since is not None else ((max_ts or time.time()) - 6 * 3600)
            total = self._db.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
            by_cat = self._db.execute(
                "SELECT category, COUNT(*) c FROM events WHERE ts >= ? GROUP BY category ORDER BY c DESC", (since,)
            ).fetchall()
            series = self._db.execute(
                "SELECT CAST(ts/? AS INTEGER)*? AS b, COUNT(*) c, "
                "SUM(CASE WHEN category='auth_failure' THEN 1 ELSE 0 END) f FROM events WHERE ts >= ? GROUP BY b ORDER BY b",
                (bucket, bucket, since),
            ).fetchall()
            top_ips = self._db.execute(
                "SELECT src_ip ip, COUNT(*) c FROM events WHERE ts >= ? AND src_ip IS NOT NULL AND "
                "category IN ('auth_failure','web_request','network_conn') GROUP BY src_ip ORDER BY c DESC LIMIT 8",
                (since,),
            ).fetchall()
            sev = self._db.execute("SELECT severity, COUNT(*) c FROM alerts GROUP BY severity").fetchall()
            status = self._db.execute("SELECT status, COUNT(*) c FROM alerts GROUP BY status").fetchall()
            pending = self._db.execute("SELECT COUNT(*) c FROM actions WHERE status='pending'").fetchone()["c"]
            tech_rows = self._db.execute("SELECT techniques FROM alerts").fetchall()
        techs: Dict[str, int] = {}
        for r in tech_rows:
            for t in json.loads(r["techniques"] or "[]"):
                techs[t] = techs.get(t, 0) + 1
        return {
            "total_events": total,
            "latest_event_ts": max_ts,
            "since": since,
            "by_category": [{"category": r["category"], "count": r["c"]} for r in by_cat],
            "series": [{"ts": r["b"], "count": r["c"], "failures": r["f"]} for r in series],
            "top_ips": [{"ip": r["ip"], "count": r["c"]} for r in top_ips],
            "alerts_by_severity": {r["severity"]: r["c"] for r in sev},
            "alerts_by_status": {r["status"]: r["c"] for r in status},
            "pending_actions": pending,
            "techniques": techs,
        }

    def reset(self) -> None:
        with self._lock:
            for t in ("events", "alerts", "investigations", "actions", "audit", "enforcement"):
                self._db.execute(f"DELETE FROM {t}")
            self._db.commit()
