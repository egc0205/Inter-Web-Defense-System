"""
DDoS pipeline: Zeek http.log + conn.log -> log_parser -> DDOS-001..008 -> automated_response

    Run the ddos sample, with automated response:
        python ddos_rules/run_ddos.py

    Run any folder under sample_logs/:
        python ddos_rules/run_ddos.py --dataset portscan

    Run your own logs, detection only, printing the first 3 alerts in full:
        python ddos_rules/run_ddos.py --http X.log --conn Y.log --no-respond --show 3

Writes ddos_rules/output/ddos_alerts.jsonl, responses.jsonl and response_console.log.
"""

# argparse: reads the command-line options (--dataset, --http, --no-respond, ...)
import argparse

# asyncio: run_automated_response() is async, so we need an event loop to call it
import asyncio

# contextlib: sends the responder's print() output to response_console.log
import contextlib

# json: reads config.json and writes alerts and responses as JSON lines
import json

# os: builds file paths that work on Windows, Mac and Linux
import os

# sys: lets us import from other folders and exit with an error message
import sys

# Counter: counts alerts per rule for the summary at the end
from collections import Counter

# Don't leave __pycache__ in other team folders
sys.dont_write_bytecode = True

# Make ddos_detector.py importable no matter where this is run from
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)

# ddos_detector: the DDoS rules this script runs
from ddos_detector import detect, read_events, run_ddos_rules  # noqa: E402

SAMPLE_LOGS = os.path.join(REPO, "sample_logs")
DEFAULT_CONFIG = os.path.join(HERE, "config.json")
OUTPUT_DIR = os.path.join(HERE, "output")


def make_responder(console_log, responses):
    # automated_response: the team's responder, which takes our alerts and runs the actions.
    # Imported here so --no-respond still works if that file is broken.
    sys.path.insert(0, os.path.join(REPO, "automated_response"))
    try:
        from automated_response import run_automated_response
    except (ImportError, SyntaxError) as exc:
        sys.exit(f"Could not load automated_response.py: {type(exc).__name__}: {exc}")
    loop = asyncio.new_event_loop()

    def respond(alert):
        with contextlib.redirect_stdout(console_log):
            try:
                result = loop.run_until_complete(run_automated_response(alert))
            except Exception as exc:
                result = {"alert_id": alert["alert_id"], "rule_id": alert["rule_id"],
                          "status": "error", "error": f"{type(exc).__name__}: {exc}"}
        responses.append(result)

    return respond, loop


def write_jsonl(path, records):
    with open(path, "w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, default=str) + "\n")


def main():
    ap = argparse.ArgumentParser(
        description="DDoS pipeline: http.log + conn.log -> log_parser -> DDOS-001..008 "
                    "-> automated_response")
    ap.add_argument("--dataset", default="ddos",
                    help="folder under sample_logs/ to read zeek/http.log and zeek/conn.log "
                         "from (default: ddos)")
    ap.add_argument("--http", help="Zeek http.log (overrides --dataset)")
    ap.add_argument("--conn", help="Zeek conn.log (overrides --dataset)")
    ap.add_argument("--config", default=DEFAULT_CONFIG, help="rule config JSON")
    ap.add_argument("--no-respond", action="store_true",
                    help="detect only; skip automated_response")
    ap.add_argument("--no-parse", action="store_true",
                    help="read logs directly, skip log_parser.py")
    ap.add_argument("--out", default=os.path.join(OUTPUT_DIR, "ddos_alerts.jsonl"))
    ap.add_argument("--show", type=int, default=0, metavar="N",
                    help="print the first N alerts in full")
    args = ap.parse_args()

    zeek = os.path.join(SAMPLE_LOGS, args.dataset, "zeek")
    http_log = args.http or os.path.join(zeek, "http.log")
    conn_log = args.conn or os.path.join(zeek, "conn.log")
    logs = {"http": http_log if os.path.exists(http_log) else None,
            "conn": conn_log if os.path.exists(conn_log) else None}
    for name, path in logs.items():
        if path is None:
            print(f"Note: no {name}.log found ({http_log if name == 'http' else conn_log}); "
                  f"skipping the rules that need it")
    if not any(logs.values()):
        sys.exit("No log files found")

    config = {}
    if args.config and os.path.exists(args.config):
        with open(args.config, encoding="utf-8") as f:
            config = json.load(f)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)

    responses, responder, loop, console = [], None, None, None
    if not args.no_respond:
        console = open(os.path.join(OUTPUT_DIR, "response_console.log"), "w", encoding="utf-8")
        responder, loop = make_responder(console, responses)

    if args.no_parse:
        http_events = list(read_events(logs["http"])) if logs["http"] else None
        conn_events = list(read_events(logs["conn"])) if logs["conn"] else None
        alerts = run_ddos_rules(http_events, conn_events, config, responder)
    else:
        alerts = detect(logs["http"], logs["conn"], config, responder)
    write_jsonl(args.out, alerts)

    print(f"{len(alerts)} alert(s) written to {args.out}\n")
    for a in alerts:
        print(f"  {a['timestamp']}  {a['rule_id']}  {a['severity']:<8}  {a['key']:<15}  "
              f"{a['message']}")
    print("\nAlerts by rule:")
    for rule_id, n in sorted(Counter(a["rule_id"] for a in alerts).items()):
        print(f"  {rule_id}: {n}")

    if responder is not None:
        loop.close()
        console.close()
        resp_path = os.path.join(OUTPUT_DIR, "responses.jsonl")
        write_jsonl(resp_path, responses)
        failed = [r for r in responses if isinstance(r, dict)
                  and (r.get("status") in ("failed", "error") or r.get("success") is False)]
        print(f"\n{len(responses)} alert(s) sent to automated_response "
              f"({len(failed)} with failures)")
        print(f"Responses: {resp_path}")
        print(f"Response console output: {os.path.join(OUTPUT_DIR, 'response_console.log')}")

    for alert in alerts[:args.show]:
        shown = dict(alert, details=dict(alert["details"]))
        uids = shown["details"].get("uids", [])
        if len(uids) > 5:
            shown["details"]["uids"] = uids[:5] + [f"... {len(uids) - 5} more"]
        print("\n" + json.dumps(shown, indent=2))


if __name__ == "__main__":
    main()
