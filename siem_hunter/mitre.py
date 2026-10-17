"""A small MITRE ATT&CK lookup covering the techniques the detection rules emit."""
from __future__ import annotations

from typing import Dict, List, Tuple

TACTIC_ORDER = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# technique id -> (name, tactic)
TECHNIQUES: Dict[str, Tuple[str, str]] = {
    "T1595": ("Active Scanning", "Reconnaissance"),
    "T1595.002": ("Vulnerability Scanning", "Reconnaissance"),
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1110.001": ("Password Guessing", "Credential Access"),
    "T1110.003": ("Password Spraying", "Credential Access"),
    "T1003": ("OS Credential Dumping", "Credential Access"),
    "T1003.001": ("LSASS Memory", "Credential Access"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1059.001": ("PowerShell", "Execution"),
    "T1059.004": ("Unix Shell", "Execution"),
    "T1027": ("Obfuscated Files or Information", "Defense Evasion"),
    "T1070.001": ("Clear Windows Event Logs", "Defense Evasion"),
    "T1136": ("Create Account", "Persistence"),
    "T1098": ("Account Manipulation", "Persistence"),
    "T1548.003": ("Sudo and Sudo Caching", "Privilege Escalation"),
    "T1021": ("Remote Services", "Lateral Movement"),
    "T1021.002": ("SMB/Windows Admin Shares", "Lateral Movement"),
    "T1021.004": ("SSH", "Lateral Movement"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1490": ("Inhibit System Recovery", "Impact"),
}


def describe(technique_id: str) -> Dict[str, str]:
    name, tactic = TECHNIQUES.get(technique_id, ("Unknown technique", "Unknown"))
    return {"id": technique_id, "name": name, "tactic": tactic}


def tactic_of(technique_id: str) -> str:
    return TECHNIQUES.get(technique_id, ("", "Unknown"))[1]


def kill_chain(technique_ids: List[str]) -> List[Dict[str, object]]:
    """Group techniques by tactic, ordered along the attack lifecycle."""
    grouped: Dict[str, List[str]] = {}
    for tid in technique_ids:
        grouped.setdefault(tactic_of(tid), [])
        if tid not in grouped[tactic_of(tid)]:
            grouped[tactic_of(tid)].append(tid)

    def order(t: str) -> int:
        return TACTIC_ORDER.index(t) if t in TACTIC_ORDER else len(TACTIC_ORDER)

    return [
        {"tactic": t, "techniques": [describe(x) for x in grouped[t]]}
        for t in sorted(grouped, key=order)
    ]
