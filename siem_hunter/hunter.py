"""Autonomous threat hunter.

Two jobs:
  * investigate(alert): pivot from an alert's indicators (IP, user, host), pull in related telemetry, look for
    follow-on behaviour (successful logins, new processes, new accounts, lateral movement, log clearing),
    correlate with other alerts, build a timeline + kill chain and compute a risk score and verdict.
  * proactive_hunts(window): hypothesis-driven sweeps that do not wait for a rule to fire (currently
    C2 beaconing detection from connection regularity).
"""
from __future__ import annotations

import ipaddress
import statistics
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set

from . import mitre
from .config import Config
from .detections import PROC_PATTERNS, ADMIN_GROUPS, group_by, ids
from .models import SEV_RANK, AlertDraft, Event
from .store import Store

BASE_RISK = {"info": 8, "low": 20, "medium": 40, "high": 58, "critical": 75}
INTERESTING_ON_HOST = ["process_start", "privilege", "account_change", "log_clear", "auth_success"]


_INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "::1/128", "fc00::/7", "fe80::/10")]


def is_internal(ip: Optional[str]) -> bool:
    """True for RFC1918/loopback/link-local/CGNAT space. (ipaddress.is_private would also match the TEST-NET
    documentation ranges, which are routable-looking 'external' addresses for our purposes.)"""
    if not ip:
        return False
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in net for net in _INTERNAL_NETS if a.version == net.version)


def _fmt_ts(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts)) + "Z"


def _summarize(ev: Event) -> str:
    if ev.category in ("auth_failure", "auth_success"):
        return f"{ev.category.replace('_', ' ')}: {ev.user}@{ev.host} from {ev.src_ip or 'local'}"
    if ev.category in ("process_start", "privilege"):
        return f"{ev.category.replace('_', ' ')}: {(ev.command_line or ev.process or '')[:120]} ({ev.user}@{ev.host})"
    if ev.category == "account_change":
        a = ev.extra.get("action", "change")
        g = f" group={ev.extra.get('group')}" if ev.extra.get("group") else ""
        return f"account {a}: {ev.user}{g} on {ev.host}"
    if ev.category == "log_clear":
        return f"audit log cleared on {ev.host}"
    if ev.category == "web_request":
        return f"web: {ev.message[:110]} from {ev.src_ip}"
    if ev.category == "network_conn":
        return f"net: {ev.src_ip} -> {ev.dst_ip}:{ev.dst_port} {ev.outcome or ''}"
    return ev.message[:110]


class Hunter:
    def __init__(self, cfg: Config, store: Store):
        self.cfg, self.store = cfg, store

    # ------------------------------------------------------------------ investigation
    def investigate(self, alert_id: int) -> Optional[Dict[str, Any]]:
        alert = self.store.get_alert(alert_id)
        if alert is None:
            return None
        cfg = self.cfg
        evidence = self.store.events_by_ids(alert["event_ids"][:5000])
        ev_ids = {e.id for e in evidence}

        ips: Set[str] = {e.src_ip for e in evidence if e.src_ip} | ({alert["src_ip"]} if alert["src_ip"] else set())
        users: Set[str] = {e.user for e in evidence if e.user} | ({alert["user"]} if alert["user"] else set())
        hosts: Set[str] = {e.host for e in evidence if e.host} | ({alert["host"]} if alert["host"] else set())
        if alert["rule_id"] in ("brute_force", "password_spray", "web_attack", "port_scan"):
            users = set(sorted(users)[:25])

        lo = alert["first_seen"] - 1800
        hi = alert["last_seen"] + cfg.hunt_forward_seconds

        pool: Dict[int, Event] = {}
        for e in self.store.events(src_ips=ips, since=lo, until=hi, limit=3000):
            pool[e.id] = e
        for e in self.store.events(users=users, since=lo, until=hi, limit=3000,
                                   categories=["auth_success", "auth_failure", "process_start", "privilege",
                                               "account_change"]):
            pool[e.id] = e
        for e in self.store.events(hosts=hosts, since=lo, until=hi, limit=3000, categories=INTERESTING_ON_HOST):
            pool[e.id] = e
        related = sorted((e for i, e in pool.items() if i not in ev_ids), key=lambda e: (e.ts, e.id))

        findings: List[Dict[str, str]] = []
        compromised: List[Dict[str, Any]] = []
        score_bonus = 0

        # --- who is the source?
        for ip in sorted(ips):
            hist = self.store.ip_history(ip)
            kind = "internal" if is_internal(ip) else "external"
            findings.append({"level": "info", "text": (
                f"Source {ip} ({kind}) is associated with {hist['c']} logged events across {hist['hosts']} host(s) "
                f"and {hist['users']} account(s).")})

        # --- did the attacker get in?
        if alert["rule_id"] == "compromised_account":
            succ = [e for e in evidence if e.category == "auth_success"]
            for s in succ:
                compromised.append({"user": s.user, "host": s.host, "ts": s.ts, "src_ip": s.src_ip})
        else:
            for e in related:
                if e.category == "auth_success" and e.src_ip in ips and e.ts >= alert["first_seen"]:
                    prior = sum(1 for x in evidence if x.category == "auth_failure" and x.ts <= e.ts)
                    if alert["rule_id"] in ("brute_force", "password_spray") and prior >= 1:
                        compromised.append({"user": e.user, "host": e.host, "ts": e.ts, "src_ip": e.src_ip})
        seen = set()
        uniq = []
        for c in compromised:
            k = (c["user"], c["host"])
            if k not in seen:
                seen.add(k)
                uniq.append(c)
        compromised = uniq
        for c in compromised:
            findings.append({"level": "critical", "text": (
                f"{c['src_ip']} authenticated successfully as '{c['user']}' on {c['host']} at {_fmt_ts(c['ts'])} "
                "after failed attempts - treat the account as compromised until proven otherwise.")})
            score_bonus += 12

        # --- post-compromise behaviour
        follow_on: List[Event] = []
        suspicious_follow = 0
        lateral_hosts: Set[str] = set()
        for c in compromised:
            for e in related:
                if e.ts < c["ts"] or e.id in {x.id for x in follow_on}:
                    continue
                on_host = e.host == c["host"] and e.category in ("process_start", "privilege", "account_change", "log_clear")
                by_user = e.user == c["user"] and e.category in ("process_start", "privilege", "account_change")
                if on_host or by_user:
                    follow_on.append(e)
                if e.category == "auth_success" and e.user == c["user"] and e.host != c["host"]:
                    lateral_hosts.add(e.host)
                    follow_on.append(e)
        follow_on.sort(key=lambda e: (e.ts, e.id))
        for e in follow_on:
            text = e.command_line or e.message or ""
            label = next((p[2] for p in PROC_PATTERNS if p[1].search(text)), None)
            if label:
                suspicious_follow += 1
                findings.append({"level": "critical", "text": f"Post-compromise: {label} on {e.host} by {e.user}: {text[:120]}"})
            elif e.category == "account_change":
                suspicious_follow += 1
                findings.append({"level": "high", "text": f"Post-compromise account change on {e.host}: {_summarize(e)}"})
            elif e.category == "log_clear":
                suspicious_follow += 1
                findings.append({"level": "high", "text": f"Post-compromise: audit logs cleared on {e.host}"})
        if lateral_hosts:
            findings.append({"level": "high", "text": (
                f"Compromised account(s) also logged in to other hosts: {', '.join(sorted(lateral_hosts))}.")})
            score_bonus += 8
        if suspicious_follow:
            score_bonus += min(20, 8 + 4 * suspicious_follow)
        elif follow_on:
            findings.append({"level": "medium", "text": f"{len(follow_on)} follow-on event(s) by the compromised account were recorded."})
            score_bonus += 4

        # --- rule-specific context
        if alert["rule_id"] == "web_attack":
            labels = alert["extra"].get("labels", [])
            findings.append({"level": "info", "text": f"Attack techniques observed: {', '.join(labels)}."})
            if "returned a success status" in alert["description"]:
                findings.append({"level": "high", "text": "Some malicious requests returned 2xx/3xx - review the application and its data."})
                score_bonus += 6
            if any(e.category in ("auth_success", "auth_failure") for e in related if e.src_ip in ips):
                findings.append({"level": "high", "text": "The same IP also touched authentication services."})
                score_bonus += 5
        if alert["rule_id"] == "port_scan":
            followed = [e for e in related if e.src_ip in ips and e.category in ("auth_failure", "auth_success", "web_request")]
            if followed:
                findings.append({"level": "high", "text": f"Scanner followed up with {len(followed)} authentication/web event(s) - reconnaissance led to an attack."})
                score_bonus += 8
            else:
                findings.append({"level": "info", "text": "No exploitation activity from the scanner was observed after the scan."})

        # --- other alerts touching the same entities
        others = []
        for a in self.store.all_alerts_between(lo, hi):
            if a["id"] == alert_id:
                continue
            shares = (a["src_ip"] and a["src_ip"] in ips) or (a["user"] and a["user"] in users) or (a["host"] and a["host"] in hosts)
            if shares:
                others.append({"id": a["id"], "title": a["title"], "severity": a["severity"], "rule_id": a["rule_id"],
                               "techniques": a["techniques"]})
        if others:
            findings.append({"level": "high" if len(others) >= 2 else "medium",
                             "text": f"{len(others)} other alert(s) involve the same IP/account/host: "
                                     + "; ".join(f"#{o['id']} {o['title']}" for o in others[:4]) + "."})
            score_bonus += min(12, 4 * len(others))

        # --- kill chain
        techs = set(alert["techniques"])
        for o in others:
            techs.update(o["techniques"])
        for e in follow_on:
            text = e.command_line or ""
            for p in PROC_PATTERNS:
                if p[1].search(text):
                    techs.update(p[3])
        chain = mitre.kill_chain(sorted(techs))
        if len(chain) >= 3:
            score_bonus += 6
            findings.append({"level": "high", "text": f"Activity spans {len(chain)} ATT&CK tactics: "
                                                     + " -> ".join(c["tactic"] for c in chain) + "."})

        # --- risk + verdict
        risk = max(0, min(100, BASE_RISK[alert["severity"]] + score_bonus))
        if compromised:
            verdict = "likely_compromise"
            risk = max(risk, 85)
        elif risk >= 70:
            verdict = "high_risk"
        elif risk >= 45:
            verdict = "suspicious"
        elif risk >= 25:
            verdict = "low_risk"
        else:
            verdict = "informational"
        if not any(f["level"] in ("critical", "high") for f in findings) and alert["severity"] in ("low", "info"):
            findings.append({"level": "info", "text": "No corroborating evidence found; likely benign unless context says otherwise."})

        # --- timeline (evidence compressed, follow-on in full)
        timeline: List[Dict[str, Any]] = []
        if evidence:
            first, last = evidence[0], evidence[-1]
            timeline.append({"ts": first.ts, "kind": "evidence", "host": first.host, "text": _summarize(first)})
            if len(evidence) > 2:
                timeline.append({"ts": first.ts, "kind": "evidence", "host": first.host,
                                 "text": f"... {len(evidence) - 2} more matching events ..."})
            if len(evidence) > 1:
                timeline.append({"ts": last.ts, "kind": "evidence", "host": last.host, "text": _summarize(last)})
        for c in compromised:
            timeline.append({"ts": c["ts"], "kind": "compromise", "host": c["host"],
                             "text": f"Successful login as '{c['user']}' from {c['src_ip']}"})
        for e in follow_on[:40]:
            timeline.append({"ts": e.ts, "kind": "follow_on", "host": e.host, "text": _summarize(e)})
        timeline.sort(key=lambda t: t["ts"])

        inv = {
            "alert_id": alert_id,
            "generated_at": time.time(),
            "window": {"from": lo, "to": hi},
            "indicators": {"ips": sorted(ips), "users": sorted(users)[:25], "hosts": sorted(hosts)},
            "compromised": compromised,
            "findings": findings,
            "timeline": timeline,
            "related_alerts": others,
            "kill_chain": chain,
            "follow_on_count": len(follow_on),
            "risk_score": risk,
            "verdict": verdict,
        }
        inv["summary"] = self._summary(alert, inv)
        self.store.save_investigation(alert_id, inv)
        self.store.update_alert(alert_id, risk_score=risk, verdict=verdict)
        if alert["status"] == "new":
            self.store.update_alert(alert_id, status="investigated")
        return inv

    @staticmethod
    def _summary(alert: Dict[str, Any], inv: Dict[str, Any]) -> str:
        parts = [alert["description"]]
        if inv["compromised"]:
            c = inv["compromised"][0]
            parts.append(f"The attacker succeeded: '{c['user']}' on {c['host']} was accessed from {c['src_ip']}.")
        elif alert["rule_id"] in ("brute_force", "password_spray", "port_scan", "web_attack"):
            parts.append("No successful intrusion was found in the investigated window.")
        if inv["follow_on_count"]:
            parts.append(f"{inv['follow_on_count']} follow-on event(s) were observed after the compromise.")
        if inv["related_alerts"]:
            parts.append(f"{len(inv['related_alerts'])} related alert(s) were correlated.")
        parts.append(f"Risk score {inv['risk_score']}/100 - verdict: {inv['verdict'].replace('_', ' ')}.")
        return " ".join(parts)

    # ------------------------------------------------------------------ proactive hunts
    def proactive_hunts(self, events: List[Event]) -> List[AlertDraft]:
        return self.hunt_beaconing(events)

    def hunt_beaconing(self, events: List[Event], min_conns: int = 8, max_cv: float = 0.15) -> List[AlertDraft]:
        """Regular, machine-like connections from one source to one destination suggest C2 beaconing."""
        conns = [e for e in events if e.category == "network_conn" and e.src_ip and e.dst_ip and e.dst_port is not None
                 and (e.outcome or "allow") in ("allow", "accept", "permit", "allowed")]
        out: List[AlertDraft] = []
        for key, evs in group_by(conns, lambda e: f"{e.src_ip}|{e.dst_ip}|{e.dst_port}").items():
            if len(evs) < min_conns:
                continue
            evs.sort(key=lambda e: e.ts)
            gaps = [b.ts - a.ts for a, b in zip(evs, evs[1:])]
            mean = statistics.fmean(gaps)
            if mean < 10 or mean > 3600:
                continue
            cv = statistics.pstdev(gaps) / mean if mean else 1.0
            if cv > max_cv:
                continue
            src, dst, port = key.split("|")
            ext = not is_internal(dst)
            out.append(AlertDraft(
                rule_id="hunt_beaconing", entity=key, severity="high" if ext else "low", src_ip=src, host=evs[0].host,
                title=f"Beaconing: {src} -> {dst}:{port}",
                description=(f"{src} contacted {dst}:{port} {len(evs)} times at a near-constant interval of "
                             f"{mean:.0f}s (variation {cv * 100:.0f}%). Regular check-ins to {'an external' if ext else 'an internal'} "
                             "address can indicate command-and-control."),
                techniques=["T1071"], first_seen=evs[0].ts, last_seen=evs[-1].ts, event_ids=ids(evs),
                merge_window=3600, extra={"interval": round(mean, 1), "cv": round(cv, 3)},
            ))
        return out
