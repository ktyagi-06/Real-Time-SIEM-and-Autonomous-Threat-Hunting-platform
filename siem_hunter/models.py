"""Core data structures shared by every component."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

CATEGORIES = {
    "auth_failure",
    "auth_success",
    "process_start",
    "network_conn",
    "web_request",
    "account_change",
    "log_clear",
    "privilege",
    "generic",
}


@dataclass
class Event:
    """A normalized log event (the common schema every parser emits)."""

    ts: float
    source: str                     # auth | web | endpoint | network | system
    host: str
    category: str
    message: str = ""
    user: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    process: Optional[str] = None
    command_line: Optional[str] = None
    outcome: Optional[str] = None   # success | failure | allow | deny ...
    raw: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)
    id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d


@dataclass
class AlertDraft:
    """What a detection rule returns; the store turns it into an Alert row."""

    rule_id: str
    title: str
    severity: str
    entity: str                     # what the alert is "about" (IP, host:user ...)
    first_seen: float
    last_seen: float
    event_ids: List[int]
    description: str
    techniques: List[str] = field(default_factory=list)
    src_ip: Optional[str] = None
    user: Optional[str] = None
    host: Optional[str] = None
    merge_window: int = 3600        # extend an existing alert if it ends this recently
    extra: Dict[str, Any] = field(default_factory=dict)
