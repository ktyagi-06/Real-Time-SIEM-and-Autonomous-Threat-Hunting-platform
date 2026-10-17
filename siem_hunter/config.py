"""Runtime configuration. Every threshold can be overridden through SIEM_* env vars."""
from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from typing import List, Optional


def _split(value: str) -> List[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


@dataclass
class Config:
    # storage
    db_path: str = "data/siem.db"

    # detection thresholds
    lookback_seconds: int = 3600          # context re-read before each ingest batch
    brute_force_threshold: int = 8        # failures from one IP in one session
    brute_force_gap: int = 600            # seconds of silence that ends a session
    spray_users_threshold: int = 6        # distinct accounts from one IP => spraying
    compromise_failures: int = 5          # failures before a success => suspicious
    compromise_window: int = 900          # seconds to look back for those failures
    port_scan_threshold: int = 15         # distinct (ip, port) pairs in one session
    port_scan_gap: int = 60
    web_attack_min_hits: int = 3          # malicious-looking requests from one IP
    web_gap: int = 900
    anomaly_zscore: float = 3.0
    anomaly_min_count: int = 50
    anomaly_min_baseline_hours: int = 6
    offhours_start: int = 0               # local hour, inclusive
    offhours_end: int = 5                 # local hour, exclusive
    tz_offset_hours: float = 0.0

    # hunting
    hunt_forward_seconds: int = 7200      # how far after an alert the hunter looks

    # response policy
    allowlist_ips: List[str] = field(default_factory=lambda: ["127.0.0.0/8"])
    protected_accounts: List[str] = field(
        default_factory=lambda: ["root", "administrator", "krbtgt", "system"]
    )
    protected_hosts: List[str] = field(default_factory=lambda: ["dc01", "dc02"])
    allow_block_internal: bool = False
    auto_response: bool = False           # auto-approve block_ip for very high risk
    auto_response_min_risk: int = 85

    # platform
    api_key: Optional[str] = None
    enable_demo: bool = True              # allow /api/demo/load (disable in production)
    llm_enabled: bool = False
    llm_model: str = "claude-sonnet-5-5"

    @classmethod
    def from_env(cls) -> "Config":
        cfg = cls()
        for f in fields(cls):
            raw = os.environ.get("SIEM_" + f.name.upper())
            if raw is None:
                continue
            current = getattr(cfg, f.name)
            if isinstance(current, bool):
                value = raw.strip().lower() in ("1", "true", "yes", "on")
            elif isinstance(current, int):
                value = int(raw)
            elif isinstance(current, float):
                value = float(raw)
            elif isinstance(current, list):
                value = _split(raw)
            else:
                value = raw
            setattr(cfg, f.name, value)
        if cfg.api_key == "":
            cfg.api_key = None
        return cfg
