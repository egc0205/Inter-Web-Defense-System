"""
Tests for the HTTP header spoofing rules. Run from anywhere:

    python spoofing_rules/http_spoofing/test_http_rules.py

Checks, against the answer keys in sample_logs/:
  1. header_spoofing/            Expected (10 attacks, 6 benign)
  2. header_spoofing_synthetic/  cases for HTTP-001 / 003 / 004 are still WIP (plan to swap in real data once ready)
  3. web_attacks, ddos, portscan contain no header spoofing -> must give 0 alerts
Exit code 1 if anything fails.
"""
import csv
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import http_header_rules as hr  # noqa: E402

LOGS = os.path.join(hr.REPO, "sample_logs")
CONFIG = hr.json.load(open(hr.DEFAULT_CONFIG))

# Allowlist the synthetic data was written against (three servers + one proxy).
SYN_CONFIG = {
    "by_destination": {
        "192.168.10.50": ["205.174.165.68"],
        "192.168.10.3": ["intranet.corp.local"],
        "192.168.10.51": ["shop.example.com", "*.shop.example.com"],
    },
    "global": [], "trusted_proxies": ["192.168.10.1"],
    "ua_window_seconds": 60, "ua_min_distinct": 4,
}

# In the sample the first attacker request is a plain 403 probe with nothing spoofed in it, so no header rule can flag it on its own.
KNOWN_UNDETECTABLE = {"Da1Bc2de3fGh4iJ5k6"}

failed = False


def load(folder):
    base = os.path.join(LOGS, folder)
    events = list(hr.read_events(os.path.join(base, "zeek", "http.log")))
    with open(os.path.join(base, "ground_truth.csv"), newline="") as f:
        truth = {r["uid"]: r for r in csv.DictReader(f)}
    return events, truth


def check(name, events, truth, config):
    """Compares alerts to the answer key; if the key has expected_rule, compares rule ids too."""
    global failed
    alerts = hr.run_http_header_rules(events, config)
    got = {(a["details"]["uid"], a["rule_id"]) for a in alerts}
    exact = "expected_rule" in next(iter(truth.values()))
    if exact:
        want = {(u, r) for u, row in truth.items() for r in row["expected_rule"].split(";") if r}
    else:  # label-only answer key: compares which events were flagged, not which rule
        want = {(u, None) for u, row in truth.items()
                if row["label"] != "BENIGN" and u not in KNOWN_UNDETECTABLE}
        got = {(u, None) for u, _ in got}
    missed, extra = sorted(want - got), sorted(got - want)
    ok = not missed and not extra
    failed |= not ok
    print(f"{'PASS' if ok else 'FAIL'}  {name}: {len(want)} expected, {len(got)} alerts, "
          f"{len(missed)} missed, {len(extra)} false")
    scn = {u: row.get("scenario", "") for u, row in truth.items()}
    for u, r in missed:
        print(f"      MISSED {u} {r or ''} {scn.get(u, '')}")
    for u, r in extra:
        print(f"      FALSE  {u} {r or ''} {scn.get(u, '')}")


# 1. sample through the real parser (also tests the ts fallback)
events, truth = load("header_spoofing")
check("header_spoofing sample (raw log)", events, truth, CONFIG)
parsed = {a["details"]["uid"] for a in hr.detect(os.path.join(LOGS, "header_spoofing", "zeek", "http.log"), CONFIG)}
raw = {a["details"]["uid"] for a in hr.run_http_header_rules(events, CONFIG)}
ok = parsed == raw
failed |= not ok
print(f"{'PASS' if ok else 'FAIL'}  header_spoofing sample (through log_parser.py): same alerts as raw log")

# 2. synthetic cases
if os.path.isdir(os.path.join(LOGS, "header_spoofing_synthetic")):
    events, truth = load("header_spoofing_synthetic")
    check("header_spoofing_synthetic", events, truth, SYN_CONFIG)
else:
    print("SKIP  header_spoofing_synthetic (folder not found)")

# 3. no header spoofing in these logs, so zero alerts expected
for folder in ("web_attacks", "ddos", "portscan"):
    path = os.path.join(LOGS, folder, "zeek", "http.log")
    if not os.path.exists(path):
        print(f"SKIP  {folder} (no http.log)")
        continue
    events = list(hr.read_events(path))
    n = len(hr.run_http_header_rules(events, hr.learn_allowlist(events)))
    failed |= n > 0
    print(f"{'PASS' if n == 0 else 'FAIL'}  {folder}: {len(events)} events -> {n} alerts (expected 0)")

print("\nALL PASSED" if not failed else "\nFAILURES ABOVE")
sys.exit(1 if failed else 0)
