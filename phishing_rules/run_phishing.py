# Program runs phishing detection and saves alerts to JSONL

import argparse
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

    # Use default email log unless another file is specified
    ap.add_argument("log", nargs="?", default=DEFAULT_LOG)
    
    # Set output location for created alerts
    ap.add_argument("--out", default=os.path.join(OUTPUT_DIR, "phishing_alerts.jsonl"))

    arguments = ap.parse_args()

    # Check if input log file exists
    if not os.path.isfile(arguments.log):
        ap.error(f"Log file not found: {arguments.log}")

    # Run phishing detection and collect the results
    alerts, processed = detect(arguments.log)

    # Save created alerts to output JSONL file
    write_jsonl(arguments.out, alerts)

    # Display summary of detection results
    print(f"Read {processed} emails.")
    print(f"{len(alerts)} alerts written to {arguments.out}")

if __name__ == "__main__":
    main()