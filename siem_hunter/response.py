"""Recommended + approval-gated response.

Flow: the hunter's findings -> deterministic recommendations -> policy guardrails -> (optional) auto-approval for
low-regret actions -> execution through an Enforcer -> full audit trail. Executed actions can be reverted.

The default Enforcer is a *simulated* one: it records the enforcement state (blocklist, disabled accounts, isolated
hosts) in the database so the whole workflow is demonstrable and safe. Swap in your own Enforcer subclass (firewall
API, EDR, IAM) to make actions real. LLM output never feeds this module - recommendations come only from rules.
"""
from __future__ import annotations

import ipaddress
import time
from typing import Any, Dict, List, Optional

from .config import Config
from .hunter import is_internal
from .store import Store

EXECUTABLE = {"block_ip", "disable_account", "isolate_host"}


class Enforcer:
    """Interface for taking real action. Return a human-readable result string."""

    def apply(self, type_: str, target: str) -> str:  # pragma: no cover - interface
        raise NotImplementedError

    def revert(self, type_: str, target: str) -> str:  # pragma: no cover - interface
        raise NotImplementedError


class SimulatedEnforcer(Enforcer):
    def apply(self, type_: str, target: str) -> str:
        return {
            "block_ip": f"[simulated] firewall rule added: deny all from {target}",
            "disable_account": f"[simulated] account '{target}' disabled and sessions revoked",
            "isolate_host": f"[simulated] host '{target}' moved to quarantine VLAN",
        }[type_]

    def revert(self, type_: str, target: str) -> str:
        return {
            "block_ip": f"[simulated] firewall rule removed for {target}",
            "disable_account": f"[simulated] account '{target}' re-enabled",
            "isolate_host": f"[simulated] host '{target}' released from quarantine",
        }[type_]


class Responder:
    def __init__(self, cfg: Config, store: Store, enforcer: Optional[Enforcer] = None):
        self.cfg, self.store = cfg, store
        self.enforcer = enforcer or SimulatedEnforcer()

    # ------------------------------------------------------------ policy
    def _allowlisted(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for net in self.cfg.allowlist_ips:
            try:
                if addr in ipaddress.ip_network(net, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def policy_check(self, type_: str, target: str) -> Optional[str]:
        """Return a reason string if the action must NOT be taken automatically, else None."""
        if type_ == "block_ip":
            try:
                ipaddress.ip_address(target)
            except ValueError:
                return f"'{target}' is not a valid IP address"
            if self._allowlisted(target):
                return f"{target} is on the allowlist"
            if is_internal(target) and not self.cfg.allow_block_internal:
                return f"{target} is an internal address (set SIEM_ALLOW_BLOCK_INTERNAL=true to allow)"
        elif type_ == "disable_account":
            if target.lower() in {a.lower() for a in self.cfg.protected_accounts}:
                return f"account '{target}' is protected"
        elif type_ == "isolate_host":
            if target.lower() in {h.lower() for h in self.cfg.protected_hosts}:
                return f"host '{target}' is protected (critical infrastructure)"
        return None

    # ------------------------------------------------------------ recommendations
    def recommend(self, alert: Dict[str, Any], inv: Dict[str, Any]) -> List[Dict[str, str]]:
        recs: List[Dict[str, str]] = []
        rule, sev = alert["rule_id"], alert["severity"]
        ips = [ip for ip in inv["indicators"]["ips"]]
        compromised = inv.get("compromised", [])
        verdict = inv.get("verdict")

        if rule in ("brute_force", "password_spray", "port_scan", "web_attack", "compromised_account") or compromised:
            for ip in ips:
                if not is_internal(ip) or self.cfg.allow_block_internal:
                    prio = "high" if (compromised or sev in ("high", "critical")) else "medium"
                    recs.append({"type": "block_ip", "target": ip, "priority": prio,
                                 "reason": f"{alert['title']} - source {ip} is hostile."})
        for c in compromised:
            recs.append({"type": "disable_account", "target": c["user"], "priority": "high",
                         "reason": f"Account '{c['user']}' was accessed from {c['src_ip']} after repeated failures; disable and reset credentials."})
        if verdict == "likely_compromise":
            for host in {c["host"] for c in compromised}:
                recs.append({"type": "isolate_host", "target": host, "priority": "high",
                             "reason": f"{host} shows post-compromise activity; isolate for forensic review."})
        if rule == "account_persistence" and alert["user"]:
            recs.append({"type": "disable_account", "target": alert["user"], "priority": "high",
                         "reason": f"New/privileged account '{alert['user']}' on {alert['host']} may be an attacker backdoor; verify it was authorised."})
        if rule.startswith("proc_") and sev == "critical" and alert["host"]:
            recs.append({"type": "isolate_host", "target": alert["host"], "priority": "high",
                         "reason": f"{alert['title']} - isolate pending investigation."})
        if rule == "log_cleared":
            recs.append({"type": "manual_review", "target": alert["host"] or "-", "priority": "high",
                         "reason": "Preserve forensic images and forwarded copies of logs; audit logs were cleared."})
        if rule == "hunt_beaconing":
            for ip in ips:
                recs.append({"type": "manual_review", "target": ip, "priority": "medium",
                             "reason": "Inspect the process on the source host generating periodic connections; consider egress blocking."})
        if rule in ("off_hours_login", "volume_anomaly", "lateral_movement"):
            recs.append({"type": "manual_review", "target": alert["user"] or alert["host"] or "-", "priority": "low" if rule != "lateral_movement" else "medium",
                         "reason": "Confirm with the owner whether this activity was expected."})
        if compromised:
            recs.append({"type": "manual_review", "target": ", ".join(sorted({c['user'] for c in compromised})), "priority": "medium",
                         "reason": "Force password reset and MFA re-enrolment; review the account's recent activity."})
        # de-duplicate
        seen, out = set(), []
        for r in recs:
            k = (r["type"], r["target"])
            if k not in seen:
                seen.add(k)
                out.append(r)
        return out

    def propose(self, alert_id: int, inv: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Create action rows for the recommendations (idempotent). Applies policy and auto-response."""
        alert = self.store.get_alert(alert_id)
        if alert is None:
            return []
        created = []
        for rec in self.recommend(alert, inv):
            if self.store.find_action(alert_id, rec["type"], rec["target"]):
                continue
            if rec["type"] not in EXECUTABLE:
                aid = self.store.add_action(alert_id, rec["type"], rec["target"], rec["reason"], rec["priority"], "manual")
                created.append(self.store.get_action(aid))
                continue
            open_ = self.store.find_open_action(rec["type"], rec["target"])
            if open_ and open_["alert_id"] != alert_id:
                aid = self.store.add_action(alert_id, rec["type"], rec["target"], rec["reason"], rec["priority"], "covered",
                                            result=f"covered by action #{open_['id']} (alert #{open_['alert_id']}, {open_['status']})")
                created.append(self.store.get_action(aid))
                continue
            blocked = self.policy_check(rec["type"], rec["target"])
            if blocked:
                aid = self.store.add_action(alert_id, rec["type"], rec["target"], rec["reason"], rec["priority"],
                                            "blocked_by_policy", result=blocked)
                self.store.audit("policy", "action_blocked", {"action_id": aid, "reason": blocked})
                created.append(self.store.get_action(aid))
                continue
            aid = self.store.add_action(alert_id, rec["type"], rec["target"], rec["reason"], rec["priority"], "pending")
            self.store.audit("hunter", "action_proposed", {"action_id": aid, "type": rec["type"], "target": rec["target"]})
            if (self.cfg.auto_response and rec["type"] == "block_ip"
                    and inv.get("risk_score", 0) >= self.cfg.auto_response_min_risk):
                self.approve(aid, actor="autopilot")
            created.append(self.store.get_action(aid))
        return created

    # ------------------------------------------------------------ lifecycle
    def approve(self, action_id: int, actor: str = "analyst") -> Dict[str, Any]:
        act = self.store.get_action(action_id)
        if act is None:
            raise KeyError("no such action")
        if act["status"] != "pending":
            raise ValueError(f"action is '{act['status']}', only pending actions can be approved")
        blocked = self.policy_check(act["type"], act["target"])
        if blocked:  # re-check: config may have changed since proposal
            self.store.update_action(action_id, status="blocked_by_policy", result=blocked)
            self.store.audit(actor, "approve_refused", {"action_id": action_id, "reason": blocked})
            raise ValueError(f"blocked by policy: {blocked}")
        now = time.time()
        try:
            result = self.enforcer.apply(act["type"], act["target"])
            self.store.update_action(action_id, status="executed", decided_at=now, decided_by=actor, executed_at=now, result=result)
            self.store.add_enforcement(act["type"], act["target"], action_id)
            self.store.audit(actor, "action_executed", {"action_id": action_id, "type": act["type"], "target": act["target"]})
            alert = self.store.get_alert(act["alert_id"])
            if alert and alert["status"] in ("new", "investigated"):
                self.store.update_alert(act["alert_id"], status="contained")
        except Exception as exc:  # enforcer failure must be visible, not silent
            self.store.update_action(action_id, status="failed", decided_at=now, decided_by=actor, result=str(exc))
            self.store.audit(actor, "action_failed", {"action_id": action_id, "error": str(exc)})
        return self.store.get_action(action_id)

    def reject(self, action_id: int, actor: str = "analyst") -> Dict[str, Any]:
        act = self.store.get_action(action_id)
        if act is None:
            raise KeyError("no such action")
        if act["status"] != "pending":
            raise ValueError(f"action is '{act['status']}', only pending actions can be rejected")
        self.store.update_action(action_id, status="rejected", decided_at=time.time(), decided_by=actor)
        self.store.audit(actor, "action_rejected", {"action_id": action_id})
        return self.store.get_action(action_id)

    def revert(self, action_id: int, actor: str = "analyst") -> Dict[str, Any]:
        act = self.store.get_action(action_id)
        if act is None:
            raise KeyError("no such action")
        if act["status"] != "executed":
            raise ValueError(f"action is '{act['status']}', only executed actions can be reverted")
        result = self.enforcer.revert(act["type"], act["target"])
        self.store.update_action(action_id, status="reverted", reverted_at=time.time(), result=result)
        self.store.deactivate_enforcement(action_id)
        self.store.audit(actor, "action_reverted", {"action_id": action_id})
        return self.store.get_action(action_id)
