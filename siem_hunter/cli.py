"""Command line interface:  python -m siem_hunter <command>"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

from . import simulator
from .config import Config
from .pipeline import Platform


def _platform(args) -> Platform:
    cfg = Config.from_env()
    if getattr(args, "db", None):
        cfg.db_path = args.db
    return Platform(cfg)


def _print_alerts(p: Platform, limit: int = 30) -> None:
    alerts = p.store.list_alerts(limit=limit)
    if not alerts:
        print("No alerts.")
        return
    print(f"\n{'ID':>3}  {'SEV':<8} {'RISK':>4}  {'VERDICT':<18} TITLE")
    for a in alerts:
        print(f"{a['id']:>3}  {a['severity']:<8} {a['risk_score']:>4}  {a['verdict']:<18} {a['title']}")


def cmd_serve(args) -> None:
    import uvicorn

    from .api import create_app

    p = _platform(args)
    if p.cfg.api_key is None and args.host not in ("127.0.0.1", "localhost", "::1"):
        print("WARNING: serving on a non-local address without SIEM_API_KEY set - the API is unauthenticated.", file=sys.stderr)
    uvicorn.run(create_app(p), host=args.host, port=args.port, log_level="info")


def cmd_demo(args) -> None:
    p = _platform(args)
    if args.reset:
        p.store.reset()
    end = time.time()
    total = 0
    for name, lines in simulator.generate(end_ts=end, seed=args.seed).items():
        r = p.ingest_lines(lines, default_host=simulator.DEFAULT_HOSTS.get(name), ref_time=end)
        total += r["stored"]
        print(f"ingested {name:<16} {r['stored']:>5} events, {r['alerts_created']} new alerts")
    print(f"\n{total} events stored in {p.cfg.db_path}")
    _print_alerts(p)
    pend = p.store.list_actions(status="pending")
    print(f"\n{len(pend)} response action(s) awaiting approval. Start the dashboard with:  python -m siem_hunter serve --db {p.cfg.db_path}")


def cmd_ingest(args) -> None:
    p = _platform(args)
    for path in args.files:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            r = p.ingest_lines(fh, default_host=args.host)
        print(f"{path}: {json.dumps(r)}")
    _print_alerts(p)


def cmd_alerts(args) -> None:
    _print_alerts(_platform(args), args.limit)


def cmd_show(args) -> None:
    p = _platform(args)
    d = p.alert_detail(args.id)
    if not d:
        sys.exit("no such alert")
    a, inv = d["alert"], d["investigation"]
    print(f"#{a['id']} [{a['severity']}] {a['title']}\n{a['description']}\n")
    if inv:
        print(f"Risk {inv['risk_score']}/100, verdict: {inv['verdict']}")
        print("\nNarrative:\n  " + inv["explanation"]["narrative"])
        print("\nFindings:")
        for f in inv["findings"]:
            print(f"  [{f['level']:<8}] {f['text']}")
        print("\nTimeline:")
        for t in inv["timeline"]:
            print(f"  {time.strftime('%H:%M:%S', time.gmtime(t['ts']))}  {t['host']:<8} {t['text']}")
    print("\nActions:")
    for x in d["actions"]:
        print(f"  #{x['id']} {x['type']} {x['target']} -> {x['status']}")


def cmd_approve(args) -> None:
    p = _platform(args)
    print(json.dumps(p.responder.approve(args.id, actor="cli"), indent=2))


def cmd_search(args) -> None:
    p = _platform(args)
    for e in reversed(p.store.search(args.query, args.limit)):
        print(f"{time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(e.ts))} {e.host:<8} {e.category:<14} {e.user or '-':<10} {e.src_ip or '-':<16} {(e.command_line or e.message)[:90]}")


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="siem_hunter", description="SIEM + autonomous threat hunting platform")
    ap.add_argument("--db", help="SQLite path (default data/siem.db or $SIEM_DB_PATH)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the API and dashboard")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.set_defaults(fn=cmd_serve)

    s = sub.add_parser("demo", help="generate simulated logs with an attack campaign and process them")
    s.add_argument("--seed", type=int, default=7)
    s.add_argument("--no-reset", dest="reset", action="store_false")
    s.set_defaults(fn=cmd_demo)

    s = sub.add_parser("ingest", help="ingest log files")
    s.add_argument("files", nargs="+")
    s.add_argument("--host", help="host name for formats that do not carry one (e.g. web access logs)")
    s.set_defaults(fn=cmd_ingest)

    s = sub.add_parser("alerts", help="list alerts")
    s.add_argument("--limit", type=int, default=50)
    s.set_defaults(fn=cmd_alerts)

    s = sub.add_parser("show", help="show an alert with its investigation")
    s.add_argument("id", type=int)
    s.set_defaults(fn=cmd_show)

    s = sub.add_parser("approve", help="approve and execute a pending response action")
    s.add_argument("id", type=int)
    s.set_defaults(fn=cmd_approve)

    s = sub.add_parser("search", help="search events")
    s.add_argument("query")
    s.add_argument("--limit", type=int, default=50)
    s.set_defaults(fn=cmd_search)

    s = sub.add_parser("simulate", help="write simulated log files to a directory")
    s.add_argument("out_dir", nargs="?", default="sample_logs")
    s.set_defaults(fn=lambda a: print(json.dumps(simulator.write_files(a.out_dir), indent=2)))

    args = ap.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
