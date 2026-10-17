import pytest
from fastapi.testclient import TestClient

from conftest import T0, ssh_fail, ssh_ok
from siem_hunter.api import create_app
from siem_hunter.config import Config
from siem_hunter.pipeline import Platform
from siem_hunter.store import Store


def attack_lines(ip="8.8.4.4", user="deploy"):
    lines = [ssh_fail(T0 + i, "app01", user, ip, 4000 + i) for i in range(12)]
    lines.append(ssh_ok(T0 + 30, "app01", user, ip))
    return lines


def actions(platform, **kw):
    """Actions keyed by (type, target); 'covered' duplicates from other alerts are ignored."""
    return {(a["type"], a["target"]): a for a in platform.store.list_actions(**kw) if a["status"] != "covered"}


def test_actions_are_proposed_but_not_executed_by_default(platform):
    platform.ingest_lines(attack_lines(), ref_time=T0)
    acts = actions(platform)
    assert acts[("block_ip", "8.8.4.4")]["status"] == "pending"
    assert acts[("disable_account", "deploy")]["status"] == "pending"
    assert platform.store.list_enforcement() == []


def test_approve_execute_revert_and_audit(platform):
    platform.ingest_lines(attack_lines(), ref_time=T0)
    act = actions(platform)[("block_ip", "8.8.4.4")]
    done = platform.responder.approve(act["id"], actor="tester")
    assert done["status"] == "executed" and "8.8.4.4" in done["result"]
    assert [e["target"] for e in platform.store.list_enforcement()] == ["8.8.4.4"]
    with pytest.raises(ValueError):
        platform.responder.approve(act["id"])            # cannot execute twice
    reverted = platform.responder.revert(act["id"], actor="tester")
    assert reverted["status"] == "reverted" and platform.store.list_enforcement() == []
    events = [a["event"] for a in platform.store.list_audit()]
    assert "action_executed" in events and "action_reverted" in events and "action_proposed" in events


def test_reject(platform):
    platform.ingest_lines(attack_lines(), ref_time=T0)
    act = actions(platform)[("disable_account", "deploy")]
    assert platform.responder.reject(act["id"])["status"] == "rejected"
    with pytest.raises(ValueError):
        platform.responder.approve(act["id"])


def test_reingest_does_not_duplicate_actions(platform):
    platform.ingest_lines(attack_lines(), ref_time=T0)
    n = len(platform.store.list_actions())
    platform.ingest_lines([ssh_fail(T0 + 40 + i, "app01", "deploy", "8.8.4.4", 9000 + i) for i in range(5)], ref_time=T0)
    platform.investigate(1)
    assert len(platform.store.list_actions()) == n


def test_policy_guardrails_block_dangerous_actions(cfg):
    p = Platform(cfg, Store(":memory:"))
    # internal attacker IP, and the compromised account is a protected one
    p.ingest_lines(attack_lines(ip="10.0.5.5", user="root"), ref_time=T0)
    acts = actions(p)
    assert ("block_ip", "10.0.5.5") not in acts        # internal sources are never even proposed for blocking
    assert acts[("disable_account", "root")]["status"] == "blocked_by_policy"
    with pytest.raises(ValueError):
        p.responder.approve(acts[("disable_account", "root")]["id"])
    assert p.responder.policy_check("block_ip", "127.0.0.1")
    assert p.responder.policy_check("block_ip", "not-an-ip")
    assert p.responder.policy_check("isolate_host", "dc01")
    assert p.responder.policy_check("block_ip", "8.8.4.4") is None


def test_auto_response_only_blocks_ips_above_risk_threshold(cfg):
    cfg.auto_response = True
    cfg.auto_response_min_risk = 85
    p = Platform(cfg, Store(":memory:"))
    p.ingest_lines(attack_lines(), ref_time=T0)
    acts = actions(p)
    assert acts[("block_ip", "8.8.4.4")]["status"] == "executed" and acts[("block_ip", "8.8.4.4")]["decided_by"] == "autopilot"
    assert acts[("disable_account", "deploy")]["status"] == "pending"      # never auto-executed


def test_failing_enforcer_is_recorded(cfg):
    from siem_hunter.response import Enforcer

    class Broken(Enforcer):
        def apply(self, t, target):
            raise RuntimeError("firewall unreachable")

    p = Platform(cfg, Store(":memory:"), Broken())
    p.ingest_lines(attack_lines(), ref_time=T0)
    act = actions(p)[("block_ip", "8.8.4.4")]
    res = p.responder.approve(act["id"])
    assert res["status"] == "failed" and "unreachable" in res["result"] and p.store.list_enforcement() == []


# ------------------------------------------------------------------ API
@pytest.fixture
def client(cfg):
    return TestClient(create_app(Platform(cfg, Store(":memory:"))))


def test_api_end_to_end(client):
    r = client.post("/api/ingest", json={"lines": attack_lines()})
    assert r.status_code == 200 and r.json()["alerts_created"] >= 2
    alerts = client.get("/api/alerts").json()
    top = alerts[0]
    detail = client.get(f"/api/alerts/{top['id']}").json()
    assert detail["investigation"]["risk_score"] >= 80 and detail["events"]
    pending = [a for a in client.get("/api/actions", params={"status": "pending"}).json() if a["type"] == "block_ip"]
    assert client.post(f"/api/actions/{pending[0]['id']}/approve").json()["status"] == "executed"
    assert client.post(f"/api/actions/{pending[0]['id']}/approve").status_code == 409
    assert client.get("/api/enforcement").json()[0]["target"] == "8.8.4.4"
    assert client.post(f"/api/alerts/{top['id']}/status", json={"status": "bogus"}).status_code == 400
    assert client.post(f"/api/alerts/{top['id']}/status", json={"status": "resolved"}).json()["status"] == "resolved"
    assert client.get("/api/alerts/9999").status_code == 404
    s = client.get("/api/stats").json()
    assert s["total_events"] == 13 and s["alerts_by_severity"]
    found = client.get("/api/events/search", params={"q": "ip:8.8.4.4 user:deploy"}).json()
    assert len(found) == 13
    assert client.get("/api/audit").json()


def test_search_query_is_parameterised(client):
    client.post("/api/ingest", json={"lines": attack_lines()})
    r = client.get("/api/events/search", params={"q": "user:x' OR '1'='1"})
    assert r.status_code == 200 and r.json() == []
    assert client.get("/api/health").json()["events"] == 13        # table still intact


def test_api_key_enforced(cfg):
    cfg.api_key = "s3cret"
    c = TestClient(create_app(Platform(cfg, Store(":memory:"))))
    assert c.get("/api/health").status_code == 200
    assert c.get("/api/alerts").status_code == 401
    assert c.get("/api/alerts", headers={"X-API-Key": "wrong"}).status_code == 401
    assert c.post("/api/ingest", json={"lines": []}).status_code == 401
    assert c.get("/api/alerts", headers={"X-API-Key": "s3cret"}).status_code == 200


def test_demo_endpoint_and_disabled_mode(cfg):
    c = TestClient(create_app(Platform(cfg, Store(":memory:"))))
    r = c.post("/api/demo/load")
    assert r.status_code == 200 and r.json()["stored"] > 3000 and r.json()["alerts_created"] >= 15
    cfg.enable_demo = False
    assert c.post("/api/demo/load").status_code == 403


def test_dashboard_served_with_security_headers(client):
    r = client.get("/")
    assert r.status_code == 200 and "SIEM Hunter" in r.text
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert client.get("/static/app.js").status_code == 200


def test_xss_payload_in_logs_is_stored_verbatim_and_served_as_json(client):
    payload = '<img src=x onerror=alert(1)>'
    line = f'9.9.9.9 - - [14/Oct/2025:12:00:00 +0000] "GET /{payload} HTTP/1.1" 200 1 "-" "x"'
    client.post("/api/ingest", json={"lines": [line], "host": "web01"})
    r = client.get("/api/events/search", params={"q": "onerror"})
    assert r.headers["content-type"].startswith("application/json") and payload in r.text
    js = client.get("/static/app.js").text
    assert "esc(" in js and "innerHTML" in js           # dashboard escapes every dynamic value via esc()


def test_config_from_env(monkeypatch):
    monkeypatch.setenv("SIEM_BRUTE_FORCE_THRESHOLD", "3")
    monkeypatch.setenv("SIEM_AUTO_RESPONSE", "true")
    monkeypatch.setenv("SIEM_PROTECTED_HOSTS", "a, b")
    c = Config.from_env()
    assert c.brute_force_threshold == 3 and c.auto_response is True and c.protected_hosts == ["a", "b"]


def test_same_target_is_not_proposed_twice_across_alerts(platform):
    platform.ingest_lines(attack_lines(), ref_time=T0)
    blocks = [a for a in platform.store.list_actions() if a["type"] == "block_ip"]
    assert len(blocks) == 2                                       # one per alert (brute force + compromise) ...
    assert sorted(a["status"] for a in blocks) == ["covered", "pending"]   # ... but only one needs a decision
    assert platform.store.stats()["pending_actions"] == len([a for a in platform.store.list_actions() if a["status"] == "pending"])


def test_is_internal_excludes_documentation_ranges():
    from siem_hunter.hunter import is_internal
    assert is_internal("10.1.2.3") and is_internal("192.168.0.9") and is_internal("172.20.1.1") and is_internal("127.0.0.1")
    assert not is_internal("203.0.113.7") and not is_internal("198.51.100.9") and not is_internal("8.8.8.8") and not is_internal(None)
