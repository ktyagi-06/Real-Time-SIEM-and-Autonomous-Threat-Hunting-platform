# SIEM Hunter - Real-Time SIEM & Autonomous Threat Hunting Platform

One platform that **collects** security logs, **detects** suspicious activity, **investigates** it automatically
(pivoting, correlation, kill-chain mapping, risk scoring) and **recommends - or, with approval, executes - a response**.
Everything is visible in a web dashboard and a REST API.

```
 logs (syslog, nginx, Windows JSON, firewall flows)
        |
   parsers ──► normalized Event ──► SQLite event store
                                        |
                          detection engine (11 rules + statistical baseline)
                                        |  alerts
                                        v
   autonomous hunter ── pivots on IP / user / host, finds follow-on activity, correlates alerts,
        |                maps to MITRE ATT&CK, scores risk, writes a verdict + narrative
        |  recommendations
        v
   response engine ── policy guardrails ──► pending approval ──► execute (Enforcer) ──► revert / audit log
        |
   REST API + dashboard
```

## Quick start

```bash
pip install -r requirements-dev.txt
python -m siem_hunter demo              # simulate a day of traffic + a multi-stage attack, print alerts
python -m siem_hunter serve             # dashboard + API on http://127.0.0.1:8000
pytest                                  # 40 tests
```

In the dashboard click **Load demo attack** (or run the `demo` command first, then `serve`).
Docker: `docker compose up --build` then open http://localhost:8000.

Ingest your own logs:

```bash
python -m siem_hunter ingest /var/log/auth.log
python -m siem_hunter ingest /var/log/nginx/access.log --host web01
curl -X POST localhost:8000/api/ingest -H 'content-type: application/json' \
     -d '{"lines": ["2026-10-16T10:00:00+00:00 app01 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"]}'
```

## What it detects

| Rule | Detects | ATT&CK |
|---|---|---|
| `brute_force` | many failed logins from one IP (sessionized) | T1110.001 |
| `password_spray` | one IP failing against many accounts | T1110.003 |
| `compromised_account` | success right after a burst of failures from the same IP | T1110, T1078 |
| `lateral_movement` | one account reaching several hosts quickly, *including hosts it never used before* | T1021, T1078 |
| `off_hours_login` | logins outside working hours | T1078 |
| `port_scan` | many distinct ports/hosts probed | T1046, T1595 |
| `web_attack` | SQLi, traversal, XSS, command injection, sensitive-file probes, scanner user-agents (double-URL-decoded) | T1190, T1595.002 |
| `proc_*` | encoded PowerShell, credential dumping, download cradles, `curl \| sh`, reverse shells, shadow-copy deletion, local admin creation | T1059, T1003, T1105, T1490 ... |
| `account_persistence` | new accounts and additions to privileged groups | T1136, T1098 |
| `log_cleared` | audit log wiped | T1070.001 |
| `volume_anomaly` | host-hour event volume far above that host's own baseline (z-score) | - |
| `hunt_beaconing` | *proactive hunt*: machine-regular connections to one destination (C2 check-ins) | T1071 |

Alerts for the same rule and entity are **merged** as more evidence arrives, so a long attack is one alert, not hundreds.

## What the autonomous hunter does

For every new or changed alert it (1) collects the indicators (IPs, accounts, hosts), (2) pulls related telemetry before
and *after* the alert, (3) checks whether the attacker got in (successful login after failures), (4) looks for
post-compromise behaviour - suspicious commands, new accounts, log clearing, logins to other hosts, (5) correlates other
alerts that share an indicator, (6) builds a timeline and an ATT&CK kill chain, and (7) computes a 0-100 risk score and a
verdict: `likely_compromise`, `high_risk`, `suspicious`, `low_risk` or `informational`.

In the demo, a brute-force alert on `app01` is escalated into a full account-takeover story: 70 failures -> success as
`deploy` -> `cat /etc/shadow` -> `curl ... | sh` -> backdoor account `svc_backup` added to `sudo` -> logins to three more hosts.

## Response: detect, investigate and stop are separate steps

* The hunter **recommends** `block_ip`, `disable_account`, `isolate_host` (executable) and `manual_review` (advice).
* Every executable action goes through **policy guardrails** first: allow-listed or internal IPs are never blocked,
  protected accounts (`root`, `administrator`, ...) and protected hosts (`dc01`, ...) are never touched.
  Blocked proposals are recorded as `blocked_by_policy` with the reason.
* Actions wait for **analyst approval** (dashboard, API or `python -m siem_hunter approve <id>`).
  Optional `SIEM_AUTO_RESPONSE=true` auto-approves *only* `block_ip` for alerts scoring above `SIEM_AUTO_RESPONSE_MIN_RISK`.
* Executed actions can be **reverted**, and every proposal / decision / execution is written to the **audit log**.
* The default `SimulatedEnforcer` only records state in the database - nothing on your network changes. To act for real,
  subclass `siem_hunter.response.Enforcer` (`apply` / `revert`) for your firewall, EDR or IAM and pass it to `Platform(enforcer=...)`.

## LLM explanations (optional)

By default the investigation narrative comes from a deterministic template, so the platform works offline.
With `pip install anthropic`, `SIEM_LLM_ENABLED=true` and `ANTHROPIC_API_KEY` set, Claude writes the narrative instead.
Design rules: the model only produces **text** - it cannot create or trigger actions; log-derived content is passed as data
with an instruction to ignore embedded instructions (logs are attacker-controlled); any API failure falls back to the template.

## REST API

| Method & path | Purpose |
|---|---|
| `GET /api/health` | status (no auth) |
| `POST /api/ingest` `{lines, host?}` / `POST /api/ingest/text?host=` | ingest logs |
| `GET /api/stats` | KPIs, time series, top IPs, ATT&CK techniques |
| `GET /api/alerts?severity=&status=` / `GET /api/alerts/{id}` | alerts, with investigation, actions and evidence |
| `POST /api/alerts/{id}/investigate` / `POST /api/alerts/{id}/status` | re-run hunt / set `resolved`, `false_positive`... |
| `GET /api/events/search?q=ip:1.2.3.4 user:root "shadow"` | event search (fields: ip, user, host, category, process, port, outcome, source) |
| `GET /api/actions`, `POST /api/actions/{id}/approve\|reject\|revert` | response workflow |
| `GET /api/enforcement`, `GET /api/audit` | active enforcement, audit trail |
| `POST /api/demo/load` | load simulated data (disable with `SIEM_ENABLE_DEMO=false`) |

Interactive docs at `/docs`.

## Configuration (environment variables)

All settings in `siem_hunter/config.py` can be overridden with `SIEM_<NAME>`, e.g. `SIEM_BRUTE_FORCE_THRESHOLD=5`,
`SIEM_TZ_OFFSET_HOURS=5.5`, `SIEM_PROTECTED_HOSTS=dc01,dc02,fileserver`, `SIEM_ALLOWLIST_IPS=10.0.0.0/8,203.0.113.5`,
`SIEM_DB_PATH=/data/siem.db`, `SIEM_API_KEY=...`.

## Security notes

* Set `SIEM_API_KEY` before exposing the API beyond localhost (sent as `X-API-Key`; the server warns if you bind publicly without one).
* Log content is attacker-controlled: SQL is parameterised, the dashboard escapes every dynamic value, and the server sends a
  strict `Content-Security-Policy` (`script-src 'self'`).
* Parsers tolerate malformed and hostile lines (they are counted as `unparsed`, never fatal).

## Layout

```
siem_hunter/
  parsers.py     log formats -> Event          detections.py  rules + engine      hunter.py   investigation + beaconing hunt
  store.py       SQLite storage                response.py    policy/approval     explain.py  template or LLM narrative
  mitre.py       ATT&CK lookup                 pipeline.py    ingest->detect->hunt->respond
  simulator.py   synthetic logs + attack       api.py / cli.py / dashboard/
tests/           40 tests (parsers, every rule, hunter, response workflow, API, auth, XSS)
```

## Honest limits

* Detection is rule- and statistics-based; there is no trained ML model. The z-score baseline and beaconing check are the
  "anomaly" components. Thresholds should be tuned to your environment.
* SQLite is right for a lab or small site (tens of millions of events at most). For larger volumes, put the same
  `Store` interface on Elasticsearch/OpenSearch or ClickHouse.
* Ingestion is by file/HTTP push; there is no built-in agent or syslog listener (point rsyslog/Filebeat/Fluent Bit at `/api/ingest/text`).
* Enforcement is simulated until you supply a real `Enforcer`.
