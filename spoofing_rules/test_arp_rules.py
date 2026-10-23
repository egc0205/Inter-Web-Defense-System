"""
Scores the ARP spoofing rules against the answer key. Run from anywhere:

    python spoofing_rules/test_arp_rules.py

Checks:
  1. arp_spoofing/ : every line ARP-001 flags is compared to ground_truth.csv
     (true/false positives, missed attacks, precision, recall)
  2. The attacker MAC (00:23:ae:9b:95:67) triggers ARP-001, ARP-002 and ARP-003
Exit code 1 if anything fails.
"""
import csv
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import arp_spoofing_rules as ar  # noqa: E402

FOLDER = os.path.join(ar.REPO, "sample_logs", "arp_spoofing")
ATTACKER_MAC = "00:23:ae:9b:95:67"

config = json.load(open(ar.DEFAULT_CONFIG))
events = list(ar.read_events(os.path.join(FOLDER, "arp.log")))
truth = [row["label"] != "BENIGN" for row in csv.DictReader(open(os.path.join(FOLDER, "ground_truth.csv")))]
assert len(events) == len(truth), "log and ground truth have different lengths"

alerts, flags = ar.run_arp_rules(events, config, return_flags=True)

tp = sum(f and t for f, t in zip(flags, truth))
fp = sum(f and not t for f, t in zip(flags, truth))
fn = sum(t and not f for f, t in zip(flags, truth))
tn = sum(not f and not t for f, t in zip(flags, truth))
precision = tp / (tp + fp) if tp + fp else 0
recall = tp / (tp + fn) if tp + fn else 0

print(f"Events: {len(events)}   attack lines: {sum(truth)}   benign lines: {len(truth) - sum(truth)}")
print(f"Caught (true positives):     {tp}")
print(f"False alarms (false pos.):   {fp}")
print(f"Missed (false negatives):    {fn}")
print(f"Correctly ignored (true neg.): {tn}")
print(f"Precision: {precision:.1%}   Recall: {recall:.1%}")
print(f"\nAlerts raised: {len(alerts)}")
for a in alerts:
    print(f"  {a['rule_id']}  {a['severity']:<6} x{a['evidence_count']:<4} {a['message']}")

fired = {a["rule_id"] for a in alerts if a["key"] == ATTACKER_MAC}
benign_alerts = [a for a in alerts if a["key"] != ATTACKER_MAC]
failed = False
for rule in ("ARP-001", "ARP-002", "ARP-003"):
    ok = rule in fired
    print(f"[{'PASS' if ok else 'FAIL'}] {rule} fires on the attacker")
    failed |= not ok
ok = not benign_alerts
print(f"[{'PASS' if ok else 'FAIL'}] no alerts on any benign MAC ({len(benign_alerts)} found)")
failed |= not ok
sys.exit(1 if failed else 0)
