"""
Tests for the DNS spoofing rules. Run from anywhere:

    python spoofing_rules/test_dns_rules.py

Checks:
  1. Real traffic (ddos, portscan, web_attacks dns.log) has no DNS spoofing
     -> must give 0 alerts (false-alarm check on ~29,000 real DNS events)
  2. dns_synthetic.log (+ dns_synthetic_ground_truth.csv) : hand-made attacks -> DNS-001, 002 and 003 must
     each fire, and no alert may point at a benign line
     (no real DNS spoofing capture yet; swap in real data when we have it)
Exit code 1 if anything fails.
"""
import csv
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import dns_spoofing_rules as dr  # noqa: E402

LOGS = os.path.join(dr.REPO, "sample_logs")
config = json.load(open(dr.DEFAULT_CONFIG))
failed = False


def check(ok, text):
    global failed
    print(f"[{'PASS' if ok else 'FAIL'}] {text}")
    failed |= not ok


# 1. False-alarm check on real traffic
total = 0
for folder in ("ddos", "portscan", "web_attacks"):
    events = list(dr.read_events(os.path.join(LOGS, folder, "zeek", "dns.log")))
    total += len(events)
    alerts = dr.run_dns_rules(events, config)
    for a in alerts:
        print("   unexpected:", a["rule_id"], a["message"])
    check(not alerts, f"{folder}: {len(events)} real DNS events -> {len(alerts)} alerts (expected 0)")
print(f"   ({total} real DNS events checked in total)\n")

# 2. Synthetic attacks
events = list(dr.read_events(os.path.join(HERE, "dns_synthetic.log")))
truth = {r["uid"]: r["label"] for r in csv.DictReader(open(os.path.join(HERE, "dns_synthetic_ground_truth.csv")))}
alerts = dr.run_dns_rules(events, config)
print(f"Synthetic: {len(events)} events, {sum(v != 'BENIGN' for v in truth.values())} attack connections")
for a in alerts:
    print(f"   {a['rule_id']}  {a['severity']:<6} x{a['evidence_count']}  {a['message']}")
fired = {a["rule_id"] for a in alerts}
for rule in ("DNS-001", "DNS-002", "DNS-003"):
    check(rule in fired, f"{rule} fires on the synthetic attack")
benign_hits = [a for a in alerts if truth.get(a["details"]["uid"]) == "BENIGN"]
check(not benign_hits, f"no alerts on benign synthetic lines ({len(benign_hits)} found)")
attack_uids = {u for u, l in truth.items() if l != "BENIGN"}
caught = {a["details"]["uid"] for a in alerts} & attack_uids
check(caught == attack_uids, f"every attack connection is caught ({len(caught)}/{len(attack_uids)})")
sys.exit(1 if failed else 0)
