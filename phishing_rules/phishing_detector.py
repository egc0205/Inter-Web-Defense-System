# Program reads email logs, checks phishing rules, and creates alerts

import json
import sys
import uuid
from datetime import datetime, timezone

from phishing_rules import RULES, RESPONSE_CODES

# Read emails records from JSONL file
def read_emails(path):

    with open(path, encoding="utf-8") as file:

        for line_num, line in enumerate(file, start=1):

            if not line.strip():
                continue

            try:
                email = json.loads(line)
        
            except json.JSONDecodeError:
                print(f"Skipped: Invalid JSON on line {line_num}", file=sys.stderr)
                continue

            if not isinstance(email, dict):
                print(f"Skipped: Non-object JSON on line {line_num}", file=sys.stderr)
                continue
        
            yield email


# Create alert when phishing rule applies
def create_alert(email, rule, evidence):

    # Get email ID to identify email
    email_id = str(email.get("email_id", "unknown"))

    # Alert formatting for automated response
    return {
        "alert_id": uuid.uuid4().hex[:12],
        "rule_id": rule["id"],
        "attack_type": "phishing",
        "severity": rule["severity"],
        "timestamp": email.get("ts"),
        "key": email_id,
        "evidence_count": evidence.get("count", 1),
        "message": f"{rule['name']} detected in email {email_id}",
        "response_codes": list(RESPONSE_CODES[rule["severity"]]),
        "details": {
            "email_id": email.get("email_id"),
            "sender": email.get("from"),
            "subject": email.get("subject"),
            "matched_pattern": evidence.get("reason", ""),
        },
    }

# Check each email agianst all phishing detection rules
# Returns all created alerts and total emails processed
def run_phishing_rules(emails, on_alert=None):
    alerts = []
    processed = 0

    # Process each  email from log file
    for email in emails:
        processed += 1

        # Run each phishing rule against current email
        for rule in RULES:

            evidence = rule["check"](email)

            # Skip rule is no phishing indicator is found
            if evidence is None:
                continue

            # Create and store alert for the applied rule
            alert = create_alert(email, rule, evidence)
            alerts.append(alert)

            if on_alert is not None:
                on_alert(alert)

    return alerts, processed

# Connects log reading with detection process
def detect(log_path, on_alert=None):
    return run_phishing_rules(read_emails(log_path), on_alert)