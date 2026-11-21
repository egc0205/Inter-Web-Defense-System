# Program runs phishing detection and saves alerts to JSONL

import argparse
import asyncio
import contextlib
import json
import os
import sys

from phishing_detector import detect

# Set paths and directories
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)

# Default locations for email logs and created alerts
DEFAULT_LOG = os.path.join(REPO, "sample_logs", "email", "emails.jsonl")
OUTPUT_DIR = os.path.join(HERE, "output")

# Set up automated response callback and event loop
def setup_automated_response(console_log, responses):

    sys.path.insert(0, os.path.join(REPO, "automated_response"))

    try:
        from automated_response import run_automated_response
    except (ImportError, SyntaxError) as exc:
        sys.exit(f"Couldn't load automated_response.py: {type(exc).__name__}: {exc}")

    # Create event loop for async response funtion
    loop = asyncio.new_event_loop()

    def respond(alert):

        # Save automated response messages to separate log
        with contextlib.redirect_stdout(console_log):
            try:
                result = loop.run_until_complete(run_automated_response(alert))
            except Exception as exc:
                result = {
                    "alert_id": alert.get("alert_id"),
                    "rule_id": alert.get("rule_id"),
                    "status": "error",
                    "error": "f{type(exc).__name__}: {exc}",
                }

        responses.append(result)

    return respond, loop

# Write alerts to JSONL file
def write_jsonl(path, records):

    # Create output directory if it doesn't exist
    os.makedirs(os.path.dirname(path), exist_ok=True)

    # Write each alert as a new JSON line
    with open(path, "w", encoding="utf-8") as file:
        for record in records:
            file.write(json.dumps(record, ensure_ascii=False) + "\n")

# Run phishing detection using specific log and output paths
def main():

    # Set up command line arguments
    ap = argparse.ArgumentParser(description="Phishing detection pipeline")

    ap.add_argument("log", nargs="?", default=DEFAULT_LOG)
    ap.add_argument("--out", default=os.path.join(OUTPUT_DIR, "phishing_alerts.jsonl"))
    ap.add_argument("--no-respond", action="store_true", help="Generate alerts without calling automated response")

    arguments = ap.parse_args()

    if not os.path.isfile(arguments.log):
        ap.error(f"Log file not found: {arguments.log}")

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    responses = []
    responder, loop, console = None

    if not arguments.no_respond:
        console = open(os.path.join(OUTPUT_DIR, "response_console.log"), "w", encoding="utf-8")
        
        try:
            responder, loop = setup_automated_response(console, responses)
        except BaseException:
            console.close()
            raise

    try:
        # Run detection and send matched alerts to automated response
        alerts, processed = detect(arguments.log, on_alert=responder)
    finally:
        if loop is not None:
            loop.close()
        if console is not None:
            console.close()

    # Save generated alerts
    write_jsonl(arguments.out, alerts)

    # Save automated response results
    if responder is not None:
        write_jsonl(os.path.join(OUTPUT_DIR, "responses.jsonl"), responses)

    print(f"Read {processed} emails.")
    print(f"{len(alerts)} alerts written to {arguments.out}")

    if responder is not None:
        failures = sum(r.get("success") is False or r.get("status") == "error" for r in responses)
        print(f"{len(responses)} responses, {failures} failures.")


if __name__ == "__main__":
    main()