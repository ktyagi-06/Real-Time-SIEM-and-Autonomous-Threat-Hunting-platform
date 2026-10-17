"""Detection rules. Each rule is a function(ctx) -> list[AlertDraft]; the engine runs all of them
over the time window touched by newly ingested events and upserts the results."""
from __future__ import annotations

import logging
import re
import statistics
from collections import defaultdict
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from .config import Config
from .models import AlertDraft, Event
from .parsers import decoded_url
from .store import Store

log = logging.getLogger("siem.detect")


@dataclass
class Ctx:
    events: List[Event]
    cfg: Config
    store: Store
    lo: float
    hi: float

    def cat(self, *cats: str) -> List[Event]:
        return [e for e in self.events if e.category in cats]


# ------------------------------------------------------------------ helpers
def sessionize(events: Sequence[Event], gap: float) -> List[List[Event]]:
    """Split time-sorted events into runs separated by more than `gap` seconds."""
    runs: List[List[Event]] = []
    for ev in events:
        if runs and ev.ts - runs[-1][-1].ts <= gap:
            runs[-1].append(ev)
        else:
            runs.append([ev])
    return runs


def group_by(events: Iterable[Event], key: Callable[[Event], Optional[str]]) -> Dict[str, List[Event]]:
    out: Dict[str, List[Event]] = defaultdict(list)
    for e in events:
        k = key(e)
        if k:
            out[k].append(e)
    return out


def ids(events: Iterable[Event]) -> List[int]:
    return [e.id for e in events if e.id is not None]


def local_hour(ts: float, tz_offset: float) -> int:
    return int(((ts / 3600.0) + tz_offset) % 24)


def fmt_users(users: Iterable[str], n: int = 5) -> str:
    u = sorted({x for x in users if x})
    return ", ".join(u[:n]) + (f" (+{len(u) - n} more)" if len(u) > n else "")


# ------------------------------------------------------------------ authentication
def brute_force(ctx: Ctx) -> List[AlertDraft]:
    cfg, out = ctx.cfg, []
    for ip, evs in group_by(ctx.cat("auth_failure"), lambda e: e.src_ip).items():
        for run in sessionize(evs, cfg.brute_force_gap):
            users = {e.user for e in run if e.user}
            if len(run) < cfg.brute_force_threshold:
                continue
            if len(users) >= cfg.spray_users_threshold:
                continue  # handled by the spray rule
            sev = "high" if len(run) >= cfg.brute_force_threshold * 4 else "medium"
            targets = {e.host for e in run}
            out.append(AlertDraft(
                rule_id="brute_force", entity=ip, severity=sev, src_ip=ip,
                user=run[0].user if len(users) == 1 else None, host=sorted(targets)[0],
                title=f"Brute-force login attempts from {ip}",
                description=(f"{len(run)} failed logins from {ip} against {len(targets)} host(s) "
                             f"(accounts: {fmt_users(users)}) between the first and last attempt."),
                techniques=["T1110.001"], first_seen=run[0].ts, last_seen=run[-1].ts, event_ids=ids(run),
                merge_window=cfg.brute_force_gap,
            ))
    return out


def password_spray(ctx: Ctx) -> List[AlertDraft]:
    cfg, out = ctx.cfg, []
    for ip, evs in group_by(ctx.cat("auth_failure"), lambda e: e.src_ip).items():
        for run in sessionize(evs, cfg.brute_force_gap):
            users = {e.user for e in run if e.user}
            if len(users) < cfg.spray_users_threshold:
                continue
            out.append(AlertDraft(
                rule_id="password_spray", entity=ip, severity="high", src_ip=ip, host=run[0].host,
                title=f"Password spraying from {ip}",
                description=(f"{len(run)} failed logins from {ip} spread across {len(users)} different accounts "
                             f"({fmt_users(users)}) - consistent with password spraying."),
                techniques=["T1110.003"], first_seen=run[0].ts, last_seen=run[-1].ts, event_ids=ids(run),
                merge_window=cfg.brute_force_gap,
            ))
    return out


def compromised_account(ctx: Ctx) -> List[AlertDraft]:
    """A successful login shortly after a burst of failures from the same IP."""
    cfg, out = ctx.cfg, []
    failures = group_by(ctx.cat("auth_failure"), lambda e: e.src_ip)
    for succ in ctx.cat("auth_success"):
        if not succ.src_ip or succ.src_ip not in failures:
            continue
        prior = [f for f in failures[succ.src_ip] if succ.ts - cfg.compromise_window <= f.ts <= succ.ts]
        if len(prior) < cfg.compromise_failures:
            continue
        same_user = [f for f in prior if f.user == succ.user]
        out.append(AlertDraft(
            rule_id="compromised_account", entity=f"{succ.src_ip}>{succ.host}:{succ.user}", severity="critical",
            src_ip=succ.src_ip, user=succ.user, host=succ.host,
            title=f"Possible account compromise: {succ.user}@{succ.host}",
            description=(f"{succ.src_ip} logged in as '{succ.user}' on {succ.host} after {len(prior)} failed attempts "
                         f"({len(same_user)} against this account) in the preceding "
                         f"{int(cfg.compromise_window / 60)} minutes."),
            techniques=["T1110", "T1078"], first_seen=prior[0].ts, last_seen=succ.ts, event_ids=ids(prior + [succ]),
            merge_window=cfg.compromise_window,
        ))
    return out


def lateral_movement(ctx: Ctx) -> List[AlertDraft]:
    """One account reaching many hosts quickly, including hosts it has not used in the past week."""
    out, window, min_hosts, min_novel = [], 600, 3, 2
    for user, evs in group_by(ctx.cat("auth_success"), lambda e: e.user).items():
        i = 0
        best: List[Event] = []
        for j in range(len(evs)):
            while evs[j].ts - evs[i].ts > window:
                i += 1
            win = evs[i : j + 1]
            if len({e.host for e in win}) >= min_hosts and len({e.host for e in win}) >= len({e.host for e in best}):
                best = win
        if not best:
            continue
        hosts = sorted({e.host for e in best})
        known = ctx.store.user_hosts_before(user, best[0].ts)
        novel = [h for h in hosts if h not in known]
        if len(novel) < min_novel:
            continue  # the account routinely uses these hosts
        out.append(AlertDraft(
            rule_id="lateral_movement", entity=user, severity="high", user=user, src_ip=best[0].src_ip, host=hosts[0],
            title=f"Possible lateral movement by '{user}'",
            description=(f"Account '{user}' authenticated to {len(hosts)} hosts ({', '.join(hosts[:6])}) within "
                         f"{window // 60} minutes, {len(novel)} of them new for this account ({', '.join(novel[:4])})."),
            techniques=["T1021", "T1078"], first_seen=best[0].ts, last_seen=best[-1].ts, event_ids=ids(best),
            merge_window=window,
        ))
    return out


def off_hours_login(ctx: Ctx) -> List[AlertDraft]:
    cfg, out = ctx.cfg, []
    risky = [e for e in ctx.cat("auth_success")
             if cfg.offhours_start <= local_hour(e.ts, cfg.tz_offset_hours) < cfg.offhours_end and e.user]
    for user, evs in group_by(risky, lambda e: e.user).items():
        out.append(AlertDraft(
            rule_id="off_hours_login", entity=user, severity="low", user=user, host=evs[0].host, src_ip=evs[0].src_ip,
            title=f"Off-hours login by '{user}'",
            description=(f"{len(evs)} successful login(s) for '{user}' between {cfg.offhours_start:02d}:00 and "
                         f"{cfg.offhours_end:02d}:00 local time, outside normal working hours."),
            techniques=["T1078"], first_seen=evs[0].ts, last_seen=evs[-1].ts, event_ids=ids(evs), merge_window=6 * 3600,
        ))
    return out


# ------------------------------------------------------------------ network & web
def port_scan(ctx: Ctx) -> List[AlertDraft]:
    cfg, out = ctx.cfg, []
    conns = [e for e in ctx.cat("network_conn") if e.src_ip and e.dst_port is not None]
    for ip, evs in group_by(conns, lambda e: e.src_ip).items():
        for run in sessionize(evs, cfg.port_scan_gap):
            pairs = {(e.dst_ip, e.dst_port) for e in run}
            if len(pairs) < cfg.port_scan_threshold:
                continue
            ports = {e.dst_port for e in run}
            targets = {e.dst_ip for e in run if e.dst_ip}
            denied = sum(1 for e in run if (e.outcome or "") in ("deny", "drop", "reject", "blocked"))
            sev = "high" if len(pairs) >= cfg.port_scan_threshold * 4 else "medium"
            out.append(AlertDraft(
                rule_id="port_scan", entity=ip, severity=sev, src_ip=ip, host=run[0].host,
                title=f"Port scan from {ip}",
                description=(f"{ip} probed {len(ports)} distinct port(s) on {len(targets)} target(s) "
                             f"({len(run)} connection attempts, {denied} denied)."),
                techniques=["T1046", "T1595"], first_seen=run[0].ts, last_seen=run[-1].ts, event_ids=ids(run),
                merge_window=cfg.port_scan_gap * 5,
            ))
    return out


WEB_PATTERNS: Dict[str, Tuple[re.Pattern, bool]] = {
    "SQL injection": (re.compile(
        r"(union(\s|\+|/\*.*?\*/)+(all(\s|\+)+)?select|'\s*or\s*'?\d'?\s*=\s*'?\d|sleep\(\s*\d|benchmark\(|"
        r"information_schema|;\s*drop\s+table|\bor\s+1\s*=\s*1)", re.I), True),
    "Path traversal": (re.compile(r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|boot\.ini|win\.ini)", re.I), True),
    "Cross-site scripting": (re.compile(r"(<script|javascript:|onerror\s*=|onload\s*=|<svg[^>]*onload)", re.I), False),
    "Command injection": (re.compile(r"(;|\||`|\$\()\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh|powershell)\b", re.I), True),
    "Sensitive file probe": (re.compile(r"(/\.env\b|/\.git/|/wp-config|/phpmyadmin|/actuator/|/server-status|/\.aws/)", re.I), False),
}
SCANNER_UA = re.compile(r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wpscan|nuclei|acunetix|zgrab|nessus)", re.I)


def web_attack(ctx: Ctx) -> List[AlertDraft]:
    cfg, out = ctx.cfg, []
    hits: List[Tuple[Event, str]] = []
    for e in ctx.cat("web_request"):
        url = decoded_url(e.extra.get("url", ""))
        ua = e.extra.get("ua", "")
        label = next((name for name, (rx, _) in WEB_PATTERNS.items() if rx.search(url)), None)
        if label is None and SCANNER_UA.search(ua):
            label = "Scanner user-agent"
        if label:
            hits.append((e, label))
    by_ip = defaultdict(list)
    for e, label in hits:
        if e.src_ip:
            by_ip[e.src_ip].append((e, label))
    for ip, items in by_ip.items():
        items.sort(key=lambda x: x[0].ts)
        run: List[Tuple[Event, str]] = []
        runs = []
        for item in items:
            if run and item[0].ts - run[-1][0].ts > cfg.web_gap:
                runs.append(run)
                run = []
            run.append(item)
        runs.append(run)
        for run in runs:
            if len(run) < cfg.web_attack_min_hits:
                continue
            labels = sorted({l for _, l in run})
            evs = [e for e, _ in run]
            ok = [e for e, l in run if e.extra.get("status", 500) < 400 and l in WEB_PATTERNS
                  and WEB_PATTERNS[l][1]]
            scanner = any(l == "Scanner user-agent" for _, l in run) or any(SCANNER_UA.search(e.extra.get("ua", "")) for e in evs)
            sev = "high" if ok else "medium"
            techs = ["T1190"] + (["T1595.002"] if scanner else [])
            desc = f"{len(run)} malicious-looking web requests from {ip}: {', '.join(labels)}."
            if ok:
                desc += f" {len(ok)} of them returned a success status - the application may have processed the payload."
            out.append(AlertDraft(
                rule_id="web_attack", entity=ip, severity=sev, src_ip=ip, host=evs[0].host,
                title=f"Web attack activity from {ip}", description=desc, techniques=techs,
                first_seen=evs[0].ts, last_seen=evs[-1].ts, event_ids=ids(evs), merge_window=cfg.web_gap,
                extra={"labels": labels},
            ))
    return out


# ------------------------------------------------------------------ endpoint
PROC_PATTERNS: List[Tuple[str, re.Pattern, str, List[str], str]] = [
    ("encoded_powershell", re.compile(r"powershell(?:\.exe)?\b.*?\s-(?:e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}", re.I),
     "Encoded PowerShell command", ["T1059.001", "T1027"], "high"),
    ("credential_dumping", re.compile(
        r"(mimikatz|sekurlsa|lsass.*(dump|minidump)|procdump.*lsass|comsvcs\.dll.*minidump|/etc/shadow|ntdsutil.*ifm)", re.I),
     "Credential dumping tool or technique", ["T1003"], "critical"),
    ("download_cradle", re.compile(
        r"(invoke-webrequest|\biwr\b|downloadstring|downloadfile|certutil.*-urlcache|bitsadmin.*/transfer)", re.I),
     "Download cradle / ingress tool transfer", ["T1105"], "high"),
    ("pipe_to_shell", re.compile(r"(curl|wget)\b[^|;]*\|\s*(sudo\s+)?(ba|z)?sh\b", re.I),
     "Remote script piped into a shell", ["T1105", "T1059.004"], "high"),
    ("reverse_shell", re.compile(r"(bash\s+-i\s+>&|/dev/tcp/|\bnc(?:at|\.traditional)?\b.*\s-e\s|mkfifo\s+/tmp)", re.I),
     "Reverse shell", ["T1059.004", "T1071"], "critical"),
    ("inhibit_recovery", re.compile(r"(vssadmin.*delete\s+shadows|wbadmin\s+delete|bcdedit.*recoveryenabled\s+no)", re.I),
     "Backup/shadow copy deletion (ransomware precursor)", ["T1490"], "critical"),
    ("local_account_add", re.compile(r"(net1?\s+user\s+\S+\s+\S+\s+/add|net1?\s+localgroup\s+administrators\s+\S+\s+/add|"
                                      r"useradd\b.*-(?:G|g)\s*(?:sudo|wheel|root))", re.I),
     "Local account creation via command line", ["T1136", "T1098"], "high"),
]


def suspicious_process(ctx: Ctx) -> List[AlertDraft]:
    groups: Dict[Tuple[str, str], List[Event]] = defaultdict(list)
    for e in ctx.cat("process_start", "privilege"):
        text = e.command_line or e.message or ""
        for pid, rx, *_ in PROC_PATTERNS:
            if rx.search(text):
                groups[(pid, e.host)].append(e)
    out = []
    meta = {p[0]: p for p in PROC_PATTERNS}
    for (pid, host), evs in groups.items():
        _, _, label, techs, sev = meta[pid]
        users = {e.user for e in evs if e.user}
        sample = (evs[0].command_line or evs[0].message or "")[:140]
        out.append(AlertDraft(
            rule_id=f"proc_{pid}", entity=host, severity=sev, host=host, user=sorted(users)[0] if users else None,
            title=f"{label} on {host}",
            description=f"{len(evs)} matching process event(s) on {host} by {fmt_users(users) or 'unknown'}. Example: {sample}",
            techniques=techs, first_seen=evs[0].ts, last_seen=evs[-1].ts, event_ids=ids(evs), merge_window=3600,
        ))
    return out


ADMIN_GROUPS = re.compile(r"(admin|sudo|wheel|root|domain admins|enterprise admins)", re.I)


def account_persistence(ctx: Ctx) -> List[AlertDraft]:
    out = []
    changes = ctx.cat("account_change")
    for key, evs in group_by(changes, lambda e: f"{e.host}|{e.user}" if e.user else None).items():
        host, user = key.split("|", 1)
        created = [e for e in evs if e.extra.get("action") == "user_created"]
        privileged = [e for e in evs if e.extra.get("action") == "group_member_added"
                      and ADMIN_GROUPS.search(str(e.extra.get("group", "")))]
        if not created and not privileged:
            continue
        if created and privileged:
            sev, label = "critical", "created and added to a privileged group"
            techs = ["T1136", "T1098"]
        elif privileged:
            sev, label = "high", f"added to privileged group '{privileged[0].extra.get('group')}'"
            techs = ["T1098"]
        else:
            sev, label = "medium", "created"
            techs = ["T1136"]
        used = created + privileged
        actors = {e.extra.get("actor") for e in used if e.extra.get("actor")}
        out.append(AlertDraft(
            rule_id="account_persistence", entity=f"{host}:{user}", severity=sev, host=host, user=user,
            title=f"Account '{user}' {label} on {host}",
            description=f"Account change on {host}: '{user}' {label}" + (f" by {fmt_users(actors)}." if actors else "."),
            techniques=techs, first_seen=min(e.ts for e in used), last_seen=max(e.ts for e in used),
            event_ids=ids(used), merge_window=6 * 3600,
        ))
    return out


def log_cleared(ctx: Ctx) -> List[AlertDraft]:
    out = []
    for host, evs in group_by(ctx.cat("log_clear"), lambda e: e.host).items():
        out.append(AlertDraft(
            rule_id="log_cleared", entity=host, severity="high", host=host, user=evs[0].user,
            title=f"Audit logs cleared on {host}",
            description=f"The security/audit log was cleared {len(evs)} time(s) on {host} - a common defense-evasion step.",
            techniques=["T1070.001"], first_seen=evs[0].ts, last_seen=evs[-1].ts, event_ids=ids(evs), merge_window=3600,
        ))
    return out


# ------------------------------------------------------------------ statistical
def volume_anomaly(ctx: Ctx) -> List[AlertDraft]:
    """Flag host-hours whose event volume is far above that host's own baseline."""
    cfg, out = ctx.cfg, []
    hour_lo, hour_hi = int(ctx.lo // 3600), int(ctx.hi // 3600)
    counts = ctx.store.counts_by_host_hour(ctx.lo - 7 * 86400, ctx.hi)
    for host, per_hour in counts.items():
        for h in range(hour_lo, hour_hi + 1):
            c = per_hour.get(h, 0)
            if c < cfg.anomaly_min_count:
                continue
            base = [v for hh, v in per_hour.items() if h - 168 <= hh < h]
            if len(base) < cfg.anomaly_min_baseline_hours:
                continue
            mean = statistics.fmean(base)
            std = max(statistics.pstdev(base), 0.5 * mean, 1.0)
            z = (c - mean) / std
            if z < cfg.anomaly_zscore:
                continue
            evs = ctx.store.events(hosts=[host], since=h * 3600, until=h * 3600 + 3599, limit=200)
            if not evs:
                continue
            out.append(AlertDraft(
                rule_id="volume_anomaly", entity=host, severity="medium", host=host,
                title=f"Unusual event volume on {host}",
                description=(f"{host} produced {c} events in one hour versus a typical {mean:.0f} (z-score {z:.1f}). "
                             "Sudden spikes often accompany scanning, brute-force or data-staging activity."),
                techniques=[], first_seen=evs[0].ts, last_seen=evs[-1].ts, event_ids=ids(evs), merge_window=3600,
                extra={"z": round(z, 1), "count": c, "baseline_mean": round(mean, 1)},
            ))
    return out


RULES: List[Callable[[Ctx], List[AlertDraft]]] = [
    brute_force, password_spray, compromised_account, lateral_movement, off_hours_login, port_scan, web_attack,
    suspicious_process, account_persistence, log_cleared, volume_anomaly,
]


class DetectionEngine:
    def __init__(self, cfg: Config, store: Store):
        self.cfg, self.store = cfg, store

    def run(self, new_events: Optional[List[Event]] = None) -> List[Tuple[int, bool, bool]]:
        """Run every rule over the affected window. Returns [(alert_id, created, changed)]."""
        if new_events is not None:
            if not new_events:
                return []
            lo = min(e.ts for e in new_events) - self.cfg.lookback_seconds
            hi = max(e.ts for e in new_events)
            events = self.store.events(since=lo, until=hi, limit=500000)
        else:
            events = self.store.events(limit=500000)
            if not events:
                return []
            lo, hi = events[0].ts, events[-1].ts
        ctx = Ctx(events=events, cfg=self.cfg, store=self.store, lo=lo, hi=hi)
        results: List[Tuple[int, bool, bool]] = []
        for rule in RULES:
            try:
                drafts = rule(ctx)
            except Exception:  # one broken rule must not stop the others
                log.exception("rule %s failed", rule.__name__)
                continue
            for d in drafts:
                if not d.event_ids:
                    continue
                results.append(self.store.upsert_alert(d))
        return results
