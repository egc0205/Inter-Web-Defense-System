import argparse
import asyncio
import contextlib
import json
import os
import sys
from collections import Counter

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from detector import PARSED_HTTP, detect, load_parsed_logs, read_events, run_injection_rules

SAMPLE_LOGS = os.path.join(REPO, "sample_logs")
DEFAULT_CONFIG = os.path.join(HERE, "config.json")
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
    ap.add_argument("log", nargs="?", help="Zeek http.log (overrides --dataset)")
    ap.add_argument("--dataset", help="folder under sample_logs/ (parsed here instead of using parsed_logs/)")
    ap.add_argument("--config", default=DEFAULT_CONFIG)
    ap.add_argument("--no-respond", action="store_true")
    ap.add_argument("--no-parse", action="store_true")
    ap.add_argument("--out", default=os.path.join(OUTPUT_DIR, "injection_alerts.jsonl"))
    ap.add_argument("--show", type=int, default=0, metavar="N")
    args = ap.parse_args()

    parsed = None
    if not (args.log or args.dataset or args.no_parse):
        parsed = load_parsed_logs()
        if parsed is None:
            print(f"No parsed log at {PARSED_HTTP} yet "
                  f"(make it with: python log_parsing/log_parser.py injection).\n"
                  f"Parsing sample_logs/web_attacks directly instead.\n")
    log = PARSED_HTTP if parsed is not None else (
        args.log or os.path.join(SAMPLE_LOGS, args.dataset or "web_attacks", "zeek", "http.log"))
    if not os.path.exists(log):
        sys.exit(f"Log file not found: {log}")
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

    if parsed is not None:
        alerts = run_injection_rules(parsed, config, responder)
    elif args.no_parse:
        alerts = run_injection_rules(list(read_events(log)), config, responder)
    else:
        alerts = detect(log, config, responder)
    write_jsonl(args.out, alerts)

    print(f"Log: {log}")
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
