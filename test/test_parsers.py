import json

from conftest import T0, iso, ssh_fail, ssh_ok
from siem_hunter.parsers import parse_line, parse_lines


def test_ssh_failure_and_success():
    f = parse_line(ssh_fail(T0, "app01", "root", "1.2.3.4", 2222), T0)
    assert (f.category, f.user, f.src_ip, f.host, f.outcome) == ("auth_failure", "root", "1.2.3.4", "app01", "failure")
    assert f.extra["port"] == 2222
    s = parse_line(ssh_ok(T0, "app01", "alice", "10.0.0.5"), T0)
    assert (s.category, s.user, s.outcome) == ("auth_success", "alice", "success")


def test_invalid_user_failure():
    line = f"{iso(T0)} app01 sshd[9]: Failed password for invalid user oracle from 9.9.9.9 port 1 ssh2"
    ev = parse_line(line, T0)
    assert ev.user == "oracle" and ev.src_ip == "9.9.9.9"


def test_bsd_syslog_timestamp_uses_reference_year():
    ev = parse_line("Oct 8 10:00:00 db01 sshd[1]: Accepted publickey for bob from 10.1.1.1 port 22 ssh2", T0)
    assert ev is not None and ev.category == "auth_success"
    assert abs(ev.ts - T0) < 3 * 86400


def test_sudo_and_useradd():
    sudo = parse_line(f"{iso(T0)} h1 sudo: bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow", T0)
    assert sudo.category == "privilege" and "/etc/shadow" in sudo.command_line and sudo.user == "bob"
    add = parse_line(f"{iso(T0)} h1 useradd[1]: new user: name=evil, UID=1001, GID=1001", T0)
    assert add.category == "account_change" and add.extra["action"] == "user_created" and add.user == "evil"
    grp = parse_line(f"{iso(T0)} h1 usermod[1]: add 'evil' to group 'sudo'", T0)
    assert grp.extra["action"] == "group_member_added" and grp.extra["group"] == "sudo"


def test_nginx_access_log():
    line = '203.0.113.5 - - [14/Oct/2025:08:00:00 +0000] "GET /a?id=1 HTTP/1.1" 200 123 "-" "curl/8.0"'
    ev = parse_line(line, T0, default_host="web01")
    assert ev.category == "web_request" and ev.host == "web01" and ev.extra["status"] == 200
    assert ev.extra["url"] == "/a?id=1" and ev.src_ip == "203.0.113.5"


def test_windows_events():
    fail = parse_line(json.dumps({"EventID": 4625, "TimeCreated": iso(T0), "Computer": "dc01", "TargetUserName": "jo", "IpAddress": "5.5.5.5"}), T0)
    assert fail.category == "auth_failure" and fail.src_ip == "5.5.5.5"
    proc = parse_line(json.dumps({"EventID": 4688, "TimeCreated": iso(T0), "Computer": "ws1", "SubjectUserName": "jo",
                                  "NewProcessName": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd /c whoami"}), T0)
    assert proc.category == "process_start" and proc.process == "cmd.exe"
    grp = parse_line(json.dumps({"EventID": 4732, "TimeCreated": iso(T0), "Computer": "ws1", "MemberName": "CN=bob,CN=Users,DC=x",
                                 "TargetUserName": "Administrators", "SubjectUserName": "jo"}), T0)
    assert grp.user == "bob" and grp.extra["group"] == "Administrators"
    assert parse_line(json.dumps({"EventID": 1102, "TimeCreated": iso(T0), "Computer": "ws1"}), T0).category == "log_clear"


def test_flow_record():
    ev = parse_line(json.dumps({"type": "flow", "timestamp": iso(T0), "host": "fw", "src_ip": "1.1.1.1", "dst_ip": "10.0.0.1", "dst_port": 22, "action": "deny"}), T0)
    assert ev.category == "network_conn" and ev.dst_port == 22 and ev.outcome == "deny"


def test_garbage_is_counted_not_fatal():
    events, bad = parse_lines(["", "   ", "not a log line", "{broken json", ssh_fail(T0, "h", "u", "1.1.1.1"), "[1,2,3]"], ref_time=T0)
    assert len(events) == 1 and bad == 3   # blank lines are skipped, not counted


def test_hostile_input_does_not_crash():
    nasty = ["A" * 100000, "\x00\x01\x02", "{" * 5000, '{"EventID": "abc"}', '{"timestamp": "nope", "dst_port": "x"}']
    events, bad = parse_lines(nasty, ref_time=T0)
    assert len(events) + bad == len(nasty)
