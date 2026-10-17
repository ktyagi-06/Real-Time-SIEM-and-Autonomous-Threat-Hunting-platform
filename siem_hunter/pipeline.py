"""The pipeline that ties everything together: ingest -> detect -> hunt -> investigate -> recommend/respond."""
from __future__ import annotations

import threading
import time
from typing import Any, Dict, Iterable, List, Optional

from .config import Config
from .detections import DetectionEngine
from .explain import Explainer
from .hunter import Hunter
from .parsers import parse_lines
from .response import Enforcer, Responder
from .store import Store


class Platform:
    def __init__(self, cfg: Optional[Config] = None, store: Optional[Store] = None, enforcer: Optional[Enforcer] = None):
        self.cfg = cfg or Config.from_env()
        self.store = store or Store(self.cfg.db_path)
        self.engine = DetectionEngine(self.cfg, self.store)
        self.hunter = Hunter(self.cfg, self.store)
        self.responder = Responder(self.cfg, self.store, enforcer)
        self.explainer = Explainer(self.cfg)
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ ingestion
    def ingest_lines(self, lines: Iterable[str], default_host: Optional[str] = None,
                     ref_time: Optional[float] = None) -> Dict[str, Any]:
        events, bad = parse_lines(lines, ref_time=ref_time, default_host=default_host)
        return self.ingest_events(events, unparsed=bad)

    def ingest_events(self, events: List, unparsed: int = 0) -> Dict[str, Any]:
        with self._lock:
            started = time.time()
            inserted = self.store.insert_events(events)
            touched: Dict[int, bool] = {}
            for aid, created, changed in self.engine.run(inserted):
                if changed:
                    touched[aid] = touched.get(aid, False) or created
            if inserted:
                lo = min(e.ts for e in inserted) - self.cfg.lookback_seconds
                hi = max(e.ts for e in inserted)
                window_events = self.store.events(since=lo, until=hi, limit=500000)
                for draft in self.hunter.proactive_hunts(window_events):
                    aid, created, changed = self.store.upsert_alert(draft)
                    if changed:
                        touched[aid] = touched.get(aid, False) or created
            for aid in touched:
                self._investigate_locked(aid)
            created_n = sum(1 for v in touched.values() if v)
            return {
                "received": len(events) + unparsed,
                "parsed": len(events),
                "unparsed": unparsed,
                "stored": len(inserted),
                "duplicates": len(events) - len(inserted),
                "alerts_created": created_n,
                "alerts_updated": len(touched) - created_n,
                "alert_ids": sorted(touched),
                "seconds": round(time.time() - started, 3),
            }

    # ------------------------------------------------------------------ investigation
    def _investigate_locked(self, alert_id: int) -> Optional[Dict[str, Any]]:
        alert = self.store.get_alert(alert_id)
        if alert is None or alert["status"] in ("resolved", "false_positive"):
            return None
        inv = self.hunter.investigate(alert_id)
        if inv is None:
            return None
        alert = self.store.get_alert(alert_id)
        inv["explanation"] = self.explainer.explain(alert, inv)
        self.store.save_investigation(alert_id, inv)
        self.responder.propose(alert_id, inv)
        return inv

    def investigate(self, alert_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._investigate_locked(alert_id)

    def alert_detail(self, alert_id: int) -> Optional[Dict[str, Any]]:
        alert = self.store.get_alert(alert_id)
        if alert is None:
            return None
        events = self.store.events_by_ids(alert["event_ids"][:300])
        return {
            "alert": alert,
            "investigation": self.store.get_investigation(alert_id),
            "actions": self.store.list_actions(alert_id=alert_id),
            "events": [e.to_dict() for e in events],
        }

    def set_alert_status(self, alert_id: int, status: str, actor: str = "analyst") -> Dict[str, Any]:
        if status not in ("new", "investigated", "contained", "resolved", "false_positive"):
            raise ValueError("invalid status")
        if self.store.get_alert(alert_id) is None:
            raise KeyError("no such alert")
        self.store.update_alert(alert_id, status=status)
        self.store.audit(actor, "alert_status", {"alert_id": alert_id, "status": status})
        return self.store.get_alert(alert_id)
