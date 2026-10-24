import argparse
import asyncio
import contextlib
import json
import os
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from detector import detect, read_events, run_injection_rules

DEFAULT_LOG = os.path.join(REPO, "sample_logs", "web_attacks", "zeek", "http.log")
OUTPUT_DIR = os.path.join(HERE, "output")


def make_responder(console_log, responses):
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
        description="Injection pipeline: http.log -> log_parser -> INJ-001..010 -> automated_response")
    ap.add_argument("log", nargs="?", default=DEFAULT_LOG)
    ap.add_argument("--config")
    ap.add_argument("--no-respond", action="store_true")
    ap.add_argument("--no-parse", action="store_true")
    ap.add_argument("--out", default=os.path.join(OUTPUT_DIR, "injection_alerts.jsonl"))
    ap.add_argument("--show", type=int, default=0, metavar="N")
    args = ap.parse_args()

    if not os.path.exists(args.log):
        sys.exit(f"Log file not found: {args.log}")
    config = {}
    if args.config:
        with open(args.config, encoding="utf-8") as f:
            config = json.load(f)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)

    responses, responder, loop, console = [], None, None, None
    if not args.no_respond:
        console = open(os.path.join(OUTPUT_DIR, "response_console.log"), "w", encoding="utf-8")
        responder, loop = make_responder(console, responses)

    if args.no_parse:
        alerts = run_injection_rules(list(read_events(args.log)), config, responder)
    else:
        alerts = detect(args.log, config, responder)
    write_jsonl(args.out, alerts)

    print(f"{len(alerts)} alert(s) written to {args.out}\n")
    print("Alerts by rule:")
    for rule_id, n in sorted(Counter(a["rule_id"] for a in alerts).items()):
        print(f"  {rule_id}: {n}")
    print("Alerts by source IP:")
    for ip, n in Counter(a["key"] for a in alerts).most_common(5):
        print(f"  {ip}: {n}")

    if responder is not None:
        loop.close()
        console.close()
        resp_path = os.path.join(OUTPUT_DIR, "responses.jsonl")
        write_jsonl(resp_path, responses)
        failed = [r for r in responses if isinstance(r, dict)
                  and (r.get("status") in ("failed", "error") or r.get("success") is False)]
        print(f"\n{len(responses)} alert(s) sent to automated_response ({len(failed)} with failures)")
        print(f"Responses: {resp_path}")
        print(f"Response console output: {os.path.join(OUTPUT_DIR, 'response_console.log')}")

    for alert in alerts[:args.show]:
        print("\n" + json.dumps(alert, indent=2))


if __name__ == "__main__":
    main()
