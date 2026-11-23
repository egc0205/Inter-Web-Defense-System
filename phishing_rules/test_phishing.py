# Unit and integration checks for the phishing detector
# Run python -m unittest discover -s phishing_rules -p test_phishing_rules.py -v

import asyncio
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(REPO, "automated_response"))

from phishing_detector import create_alert, detect, read_emails, run_phishing_rules
from phishing_rules import RULES, RESPONSE_CODES
from automated_response import PLAYBOOKS, run_automated_response

def sample(**changes):

    email = {
        "email_id": "test-001", "ts": "2024-06-01T12:00:00Z",
        "from_name": "Project Team", "from": "team@example.test",
        "from_domain": "example.test", "return_path_domain": "example.test",
        "reply_to": "team@example.test", "subject": "Project update",
        "body": "The next meeting is on Monday.", "urls": [],
        "url_domains": [], "attachments": [],
        "spf": "pass", "dkim": "pass", "dmarc": "pass"
    }

    email.update(changes)
    return email


class PhishingTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.checks = {rule["id"]: rule["check"] for rule in RULES}

    def assert_rule(self, name, event, expected=True):
        actual = self.checks[name](event)
        self.assertEqual(actual is not None, expected, (name, actual))

    def test_001_credential_request(self):
        self.assert_rule("PHISH-001", sample(subject="Verify your account", urls=["https://example.test/verify"]))
        self.assert_rule("PHISH-001", sample(subject="Verify your account"), False)

    def test_002_urgent_language(self):
        self.assert_rule("PHISH-002", sample(subject="Urgent: take action"))
        self.assert_rule("PHISH-002", sample(subject="Urgent meeting"), False)

    def test_003_sender_impersonation(self):
        self.assert_rule("PHISH-003", sample(from_name="PayPal Security", from_domain="other.example.test"))
        self.assert_rule("PHISH-003", sample(from_name="PayPal Security", from_domain="paypal.com"), False)

    def test_004_url_domain(self):
        self.assert_rule("PHISH-004", sample(subject="Verify your account", url_domains=["login.example.net"]))
        self.assert_rule("PHISH-004", sample(subject="Verify your account", url_domains=["login.example.test"]), False)

    def test_005_obfuscated_urls(self):
        self.assert_rule("PHISH-005", sample(urls=["https://bit.ly/test"]))
        self.assert_rule("PHISH-005", sample(urls=["https://example.test/"]), False)

    def test_006_suspicious_login_link(self):
        self.assert_rule("PHISH-006", sample(subject="Verify your account", urls=["https://login.example.net/login"]))

    def test_007_authentication_failure(self):
        e = sample(subject="Verify your account", urls=["https://example.test/verify"], spf="fail")
        self.assert_rule("PHISH-007", e)
        self.assert_rule("PHISH-007", sample(subject="Verify your account", urls=["https://example.test/verify"], spf="none"), False)

    def test_008_mismatched_addresses(self):
        self.assert_rule("PHISH-008", sample(subject="Update your payment", reply_to="billing@example.net"))
        self.assert_rule("PHISH-008", sample(subject="Update your payment"), False)

    def test_009_suspicious_attachment(self):
        self.assert_rule("PHISH-009", sample(subject="Invoice", attachments=[{"filename": "invoice.html", "content_type": "text/html"}]))
        self.assert_rule("PHISH-009", sample(subject="Invoice", attachments=[{"filename": "photo.jpg", "content_type": "image/jpeg"}]), False)

    def test_010_payment_delivery_request(self):
        self.assert_rule("PHISH-010", sample(subject="Payment failed: click here", urls=["https://example.net/billing"]))
        self.assert_rule("PHISH-010", sample(subject="Payment failed: click here"), False)

    def test_011_deceptive_sender(self):
        self.assert_rule("PHISH-011", sample(from_name="billing@paypal.com"))
        self.assert_rule("PHISH-011", sample(from_name="Project Team"), False)

    def test_unique_rule_ids(self):
        ids = [rule["id"] for rule in RULES]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(ids), 11)

    def test_alert_schema_and_callbacks(self):
        
        email = sample(subject="Verify your account", urls=["https://example.test/verify"])
        
        received = []
        
        alerts, count = run_phishing_rules([email], on_alert=received.append)
        
        self.assertEqual(count, 1)
        self.assertEqual(alerts, received)
        self.assertTrue(alerts)
        
        for alert in alerts:
            self.assertTrue({"alert_id", "rule_id", "attack_type", "severity", "timestamp", "key", "evidence_count", "message", "response_codes", "details"} <= set(alert))
            self.assertEqual(alert["key"], "test-001")
            self.assertEqual(alert["timestamp"], email["ts"])

    def test_automatic_response_codes_supported(self):
        for codes in RESPONSE_CODES.values():
            self.assertTrue(set(codes) <= set(PLAYBOOKS))

    def test_automatic_response_integration(self):
        
        email = sample(subject="Verify your account", urls=["https://example.test/verify"])
        high_rule = next(r for r in RULES if r["id"] == "PHISH-001")
        evidence = high_rule["check"](email)
        
        alert = create_alert(email, high_rule, evidence)
        self.assertIn("PULL_EMAIL", alert["response_codes"])
        
        with contextlib.redirect_stdout(io.StringIO()):
            result = asyncio.run(run_automated_response(alert))
        
        self.assertTrue(result["success"])
        self.assertEqual([a["code"] for a in result["actions"]], alert["response_codes"])

    def test_blank_and_invalid_lines_are_skipped(self):
        with tempfile.TemporaryDirectory() as temp:
            
            path = os.path.join(temp, "email.jsonl")
            
            with open(path, "w", encoding="utf-8") as f:
                f.write("\nnot-json\n" + json.dumps(sample()) + "\n[]\n")
            with contextlib.redirect_stderr(io.StringIO()):
                events = list(read_emails(path))
            
            self.assertEqual(len(events), 1)

    def test_benign_email_no_alerts(self):
        alerts, count = run_phishing_rules([sample()])
        self.assertEqual(count, 1)
        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()