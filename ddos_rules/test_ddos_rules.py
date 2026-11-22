"""
Tests for the DDoS rules. Run from anywhere:

    python ddos_rules/test_ddos_rules.py

What it checks:

  1. ddos/ sample: every DDoS connection in the answer key is caught, every alert is
     keyed on the attacker, and running through log_parser.py gives the same alerts.

  2. web_attacks/ and header_spoofing/ have no DDoS, so they must give 0 alerts.
     portscan/ gives only DDOS-003 (thousands of SYNs in 10s to one server meets
     the rule as written).

  3. Synthetic traffic for every rule, including the ones the samples don't exercise
     (002, 004, 005, 006, 008): each rule fires at its threshold, stays quiet below it,
     and escalates at 5x.

  4. Every response code is in automated_response.PLAYBOOKS and the responder
     accepts every alert.

Exit code 1 if anything fails.
"""

# asyncio: run_automated_response() is async, so we need an event loop to call it
import asyncio

# contextlib: lets us hide the responder's print() output while the tests run
import contextlib

# csv: reads ground_truth.csv, the answer key for the sample logs
import csv

# io: gives contextlib a place (StringIO) to send the hidden output
import io

# os: builds file paths that work on Windows, Mac and Linux
import os

# sys: lets us import from other folders and set the exit code
import sys

# tempfile: a throwaway folder for log_parser.py's output, so the test leaves no files behind
import tempfile

# Don't leave __pycache__ in other team folders
sys.dont_write_bytecode = True

# Make ddos_detector.py importable no matter where the test is run from
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# ddos_detector: the DDoS rules being tested
import ddos_detector as dd  # noqa: E402


LOGS = os.path.join(dd.REPO, "sample_logs")
ATTACKER = "172.16.0.1"
SERVER = "192.168.10.50"

# Start time for the synthetic traffic (July 2017, same period as the samples)
T0 = 1499450000.0

failed = False


# ----------------------------------------------------------------- helpers

def check(name, ok, detail=""):
    """Prints PASS or FAIL for one test and remembers if anything failed."""
    global failed
    failed |= not ok
    extra = f"  ({detail})" if detail else ""
    print(f"{'PASS' if ok else 'FAIL'}  {name}{extra}")


def load(folder):
    """Reads http.log and conn.log from a sample_logs folder."""
    zeek = os.path.join(LOGS, folder, "zeek")
    http = list(dd.read_events(os.path.join(zeek, "http.log")))
    conn = list(dd.read_events(os.path.join(zeek, "conn.log")))
    return http, conn


def summary(alerts):
    """Short, sortable version of the alerts for comparing two runs."""
    return sorted((a["rule_id"], a["severity"], a["key"]) for a in alerts)


def rules_of(alerts):
    """Alerts by rule id, so a test can look up the one rule it cares about."""
    return {a["rule_id"]: a for a in alerts}


def http_ev(i, ts, src, dst=SERVER, uri="/", status=200):
    """One fake http.log event."""
    return {
        "ts": ts,
        "uid": f"H{i}",
        "id.orig_h": src,
        "id.resp_h": dst,
        "uri": uri,
        "method": "GET",
        "status_code": status,
    }


def conn_ev(i, ts, src, dst=SERVER, proto="tcp", pkts=1, duration=0.1,
            state="SF", history="ShADadFf"):
    """One fake conn.log event."""
    return {
        "ts": ts,
        "uid": f"C{i}",
        "id.orig_h": src,
        "id.resp_h": dst,
        "proto": proto,
        "orig_pkts": pkts,
        "duration": duration,
        "conn_state": state,
        "history": history,
    }


def flood(n, seconds, sources, start=T0, **kw):
    """n HTTP requests spread evenly over `seconds`, taking turns between `sources`."""
    return [
        http_ev(i, start + seconds * i / n, sources[i % len(sources)], **kw)
        for i in range(n)
    ]


def ips(n, base="10.9"):
    """n different made-up source IPs."""
    return [f"{base}.{i // 250}.{i % 250 + 1}" for i in range(n)]


# ------------------------------------------------------- 1. ddos sample

print("== sample_logs/ddos")

http, conn = load("ddos")
alerts = dd.run_ddos_rules(http, conn)
got = rules_of(alerts)

# Every connection the answer key labels as DDoS should be in some alert
with open(os.path.join(LOGS, "ddos", "ground_truth.csv"), newline="") as f:
    attack_uids = {r["uid"] for r in csv.DictReader(f) if r["label"] != "BENIGN"}
flagged = {u for a in alerts for u in a["details"]["uids"]}
missed = attack_uids - flagged
check("every DDoS connection in ground_truth.csv is in an alert",
      not missed,
      f"{len(attack_uids) - len(missed)}/{len(attack_uids)} caught")

# Blocking must target the attacker, never our own server
check("every alert is keyed on the attacker",
      all(a["key"] == ATTACKER for a in alerts),
      ", ".join(sorted({str(a["key"]) for a in alerts})))

check("DDOS-001 fires at High (907 req/10s >= 5x100)",
      got.get("DDOS-001", {}).get("severity") == "High")

check("DDOS-003 fires (907 TCP attempts/10s >= 200)",
      "DDOS-003" in got)

check("DDOS-007 fires (traffic spike after 2 quiet minutes)",
      "DDOS-007" in got)

check("no other rules fire",
      set(got) == {"DDOS-001", "DDOS-003", "DDOS-007"},
      ", ".join(sorted(got)))

check("one alert per rule (episodes merged, not one per window)",
      len(alerts) == len(got))

# The real pipeline goes through log_parser.py first; results must not change
parsed = dd.detect(os.path.join(LOGS, "ddos", "zeek", "http.log"),
                   os.path.join(LOGS, "ddos", "zeek", "conn.log"))
check("same alerts through log_parser.py as from the raw logs",
      summary(parsed) == summary(alerts),
      str(summary(parsed)))

# Run log_parser.py the way the team does (python log_parsing/log_parser.py ddos), but into
# a temporary folder so nothing is left behind in log_parsing/parsed_logs/
sys.path.insert(0, os.path.join(dd.REPO, "log_parsing"))
import log_parser  # noqa: E402

if hasattr(log_parser, "parse_rule"):
    with tempfile.TemporaryDirectory() as tmp:
        with contextlib.redirect_stdout(io.StringIO()):
            log_parser.parse_rule("ddos", dd.REPO, tmp)
        from_files = dd.load_parsed_logs(
            os.path.join(tmp, "ddos", "http", "ddos_parsed.jsonl"),
            os.path.join(tmp, "ddos", "conn", "ddos_parsed.jsonl"))
        from_files_alerts = dd.run_ddos_rules(*from_files)
    check("same alerts from log_parser.py's parsed_logs/ddos files",
          summary(from_files_alerts) == summary(alerts),
          str(summary(from_files_alerts)))
else:
    print("SKIP  parsed_logs/ddos files (this log_parser.py has no parse_rule)")


# --------------------------------------------------- 2. other samples

print("\n== other sample_logs")

# These folders have no DDoS at all
for folder in ("web_attacks", "header_spoofing"):
    n = len(dd.run_ddos_rules(*load(folder)))
    check(f"{folder}: 0 alerts", n == 0, f"{n} alerts")

# The port scan's SYN volume meets DDOS-003 as the rules doc defines it
ps = dd.run_ddos_rules(*load("portscan"))
check("portscan: only DDOS-003 keyed on the scanner",
      summary(ps) == [("DDOS-003", "High", ATTACKER)],
      str(summary(ps)))


# --------------------------------------------------- 3. synthetic traffic

print("\n== synthetic: DDOS-001 single-source HTTP flood")

# Just under the threshold of 100 requests in 10s
r = rules_of(dd.run_ddos_rules(flood(99, 9, [ATTACKER])))
check("99 requests in 10s -> no alert", "DDOS-001" not in r)

# Exactly at the threshold
r = rules_of(dd.run_ddos_rules(flood(100, 9, [ATTACKER])))
check("100 requests in 10s -> Medium",
      r.get("DDOS-001", {}).get("severity") == "Medium")

# 5x the threshold escalates to High
a = rules_of(dd.run_ddos_rules(flood(500, 9, [ATTACKER]))).get("DDOS-001", {})
check("500 requests in 10s -> High", a.get("severity") == "High")

check("alert has the doc's fields and response code",
      a.get("response_codes") == ["ENABLE_RATE_LIMITING"]
      and a.get("key") == ATTACKER
      and a.get("evidence_count") == 500
      and a["details"].get("dst_ip") == SERVER
      and a["details"].get("uri") is None)

# A user browsing an outside site is not an attack on our servers
outside = flood(1000, 9, ["192.168.10.12"], dst="61.110.225.122")
r = rules_of(dd.run_ddos_rules(outside))
check("1000 requests to an outside server -> ignored (not a protected server)", not r)

# ...but it is watched once listed in protected_servers
r = rules_of(dd.run_ddos_rules(outside, config={"protected_servers": ["61.110.225.0/24"]}))
check("...unless that server is listed in protected_servers", "DDOS-001" in r)


print("\n== synthetic: DDOS-002 distributed HTTP flood")

# 25 IPs plus one heavier attacker, so the key should be the attacker
evs = flood(600, 8, ips(25)) + flood(40, 8, [ATTACKER], start=T0 + 0.01)
evs = [dict(e, uid=f"H{i}") for i, e in enumerate(evs)]
a = rules_of(dd.run_ddos_rules(evs)).get("DDOS-002", {})
check("640 requests from 26 IPs in 10s -> High, keyed on the top talker",
      a.get("severity") == "High"
      and a.get("key") == ATTACKER
      and a.get("response_codes") == ["ENABLE_RATE_LIMITING", "NOTIFY_ONCALL"])

# Needs at least 20 different sources
r = rules_of(dd.run_ddos_rules(flood(600, 8, ips(19))))
check("600 requests from 19 IPs -> no DDOS-002", "DDOS-002" not in r)

# 5x the threshold escalates to Critical
r = rules_of(dd.run_ddos_rules(flood(2600, 9, ips(30))))
check("2600 requests from 30 IPs -> Critical",
      r.get("DDOS-002", {}).get("severity") == "Critical")


print("\n== synthetic: DDOS-003 SYN flood")

# Half-open connections: SYN sent, no answer
syn = [conn_ev(i, T0 + i * 0.03, ATTACKER, state="S0", history="S") for i in range(250)]
a = rules_of(dd.run_ddos_rules(conn_events=syn)).get("DDOS-003", {})
check("250 SYNs in 10s -> High, ENABLE_SYN_COOKIES",
      a.get("severity") == "High"
      and a.get("response_codes") == ["ENABLE_SYN_COOKIES"])

r = rules_of(dd.run_ddos_rules(conn_events=syn[:199]))
check("199 SYNs -> no alert", "DDOS-003" not in r)

# Zeek history without "S" means the connection was already open, so no SYN to count
mid = [conn_ev(i, T0 + i * 0.03, ATTACKER, history="Dd") for i in range(250)]
check("connections with no SYN seen (picked up mid-stream) are not counted",
      not dd.run_ddos_rules(conn_events=mid))


print("\n== synthetic: DDOS-004 URI hammering")

# The query string is dropped, so every hit counts toward /login.php
login = flood(350, 25, ips(12), uri="/login.php?u=x")
a = rules_of(dd.run_ddos_rules(login)).get("DDOS-004", {})
check("350 hits on /login.php from 12 IPs in 30s -> Medium, CHALLENGE_ENDPOINT",
      a.get("severity") == "Medium"
      and a.get("response_codes") == ["CHALLENGE_ENDPOINT"]
      and a["details"].get("uri") == "/login.php")

# Needs at least 10 different sources
r = rules_of(dd.run_ddos_rules(flood(350, 25, ips(9), uri="/login.php")))
check("from 9 IPs -> no DDOS-004", "DDOS-004" not in r)

# 5x the threshold escalates to High
r = rules_of(dd.run_ddos_rules(flood(1600, 25, ips(40), uri="/search")))
check("1600 hits -> High", r.get("DDOS-004", {}).get("severity") == "High")


print("\n== synthetic: DDOS-005 UDP / ICMP flood")

dns = "192.168.10.3"

# 2 minutes of light DNS traffic (about 20 packets per 10s), then a big burst
quiet = [conn_ev(i, T0 + i, "192.168.10.9", dns, "udp", pkts=2) for i in range(120)]
burst = [
    conn_ev(200 + i, T0 + 120 + i * 0.05, ATTACKER, dns, "udp", pkts=10)
    for i in range(150)
]
a = rules_of(dd.run_ddos_rules(conn_events=quiet + burst)).get("DDOS-005", {})
check("1500 UDP packets in 10s vs ~20 normal -> High, BLOCK_PROTOCOL_RATE",
      a.get("severity") == "High"
      and a.get("response_codes") == ["BLOCK_PROTOCOL_RATE"]
      and a.get("key") == ATTACKER
      and a["details"].get("proto") == "udp")

# A server that is always this busy is not being flooded
busy = [conn_ev(i, T0 + i * 0.1, "192.168.10.9", dns, "udp", pkts=30) for i in range(1200)]
burst2 = [
    conn_ev(2000 + i, T0 + 120 + i * 0.05, ATTACKER, dns, "udp", pkts=20)
    for i in range(150)
]
r = rules_of(dd.run_ddos_rules(conn_events=busy + burst2))
check("3000 packets/10s on a target that normally gets 3000/10s -> no alert (< 10x)",
      "DDOS-005" not in r)

icmp = [
    conn_ev(i, T0 + 120 + i * 0.05, ATTACKER, proto="icmp", pkts=10)
    for i in range(150)
]
check("ICMP counts too",
      "DDOS-005" in rules_of(dd.run_ddos_rules(conn_events=quiet + icmp)))

# With no history yet there is nothing to compare against, so stay quiet
check("busy UDP server at the very start of the log -> no alert (no history yet)",
      not dd.run_ddos_rules(conn_events=busy[:300]))


print("\n== synthetic: DDOS-006 error-rate spike")

# 2 out of every 3 requests get a 503
evs = [
    http_ev(i, T0 + i, f"10.0.0.{i}", status=503 if i % 3 else 200)
    for i in range(30)
]
a = rules_of(dd.run_ddos_rules(evs)).get("DDOS-006", {})
check("20 of 30 requests are 5xx -> Medium, ALERT_ONLY",
      a.get("severity") == "Medium"
      and a.get("response_codes") == ["ALERT_ONLY"])

# Only 1 out of every 3 is an error
evs = [
    http_ev(i, T0 + i, f"10.0.0.{i}", status=500 if i % 3 == 0 else 200)
    for i in range(30)
]
check("10 of 30 are 5xx -> no alert",
      "DDOS-006" not in rules_of(dd.run_ddos_rules(evs)))

# All errors, but too few requests to judge
evs = [http_ev(i, T0 + i, f"10.0.0.{i}", status=500) for i in range(19)]
check("19 requests all 5xx (< 20 requests) -> no alert",
      "DDOS-006" not in rules_of(dd.run_ddos_rules(evs)))


print("\n== synthetic: DDOS-007 traffic spike vs baseline")

# Start exactly on a minute boundary
base_t = 1499450040.0

# 100 requests/min for 3 minutes, then 800 in the 4th minute
normal = [http_ev(i, base_t + i * 0.6, ips(50)[i % 50]) for i in range(300)]
spike = [
    http_ev(1000 + i, base_t + 180 + i * 0.07, ips(80)[i % 80])
    for i in range(800)
]
a = rules_of(dd.run_ddos_rules(normal + spike)).get("DDOS-007", {})
check("800 req/min after 3 min of ~100/min -> Medium, ALERT_ONLY",
      a.get("severity") == "Medium"
      and a.get("response_codes") == ["ALERT_ONLY"]
      and a.get("evidence_count") == 800)

# Shift everything 2 minutes earlier so only 1 minute of history comes before the spike
short = [dict(e, ts=e["ts"] - 120) for e in normal[200:] + spike]
check("same spike with only 1 minute of history -> no alert",
      "DDOS-007" not in rules_of(dd.run_ddos_rules(short)))

# Below the 600 requests/min floor
small = normal + spike[:500]
check("500 req/min (< 600) -> no alert",
      "DDOS-007" not in rules_of(dd.run_ddos_rules(small)))


print("\n== synthetic: DDOS-008 slow attack")

# 60 two-minute connections from 2 IPs, one every 3 seconds
slow = [
    conn_ev(i, T0 + i * 3, ["10.1.1.1", "10.1.1.2"][i % 2], duration=120.0)
    for i in range(60)
]
a = rules_of(dd.run_ddos_rules(conn_events=slow)).get("DDOS-008", {})
check("60 two-minute connections from 2 IPs in 300s -> Medium, DROP_CONNECTIONS",
      a.get("severity") == "Medium"
      and a.get("response_codes") == ["DROP_CONNECTIONS"])

# S1 = opened and never closed
opened = [
    conn_ev(i, T0 + i * 3, "10.1.1.1", duration=None, state="S1")
    for i in range(55)
]
check("never-closed (S1) connections count too",
      "DDOS-008" in rules_of(dd.run_ddos_rules(conn_events=opened)))

# Rule allows at most 3 sources
spread = [dict(e, **{"id.orig_h": f"10.1.1.{i % 5}"}) for i, e in enumerate(slow)]
check("same from 5 IPs -> no alert",
      not dd.run_ddos_rules(conn_events=spread))

check("40 connections -> no alert",
      not dd.run_ddos_rules(conn_events=slow[:40]))


print("\n== episodes")

# Two separate attacks should give two alerts, not one
two = flood(200, 9, [ATTACKER]) + flood(200, 9, [ATTACKER], start=T0 + 120)
two = [dict(e, uid=f"H{i}") for i, e in enumerate(two)]
check("two floods 2 minutes apart -> two DDOS-001 alerts",
      sum(a["rule_id"] == "DDOS-001" for a in dd.run_ddos_rules(two)) == 2)

check("enabled_rules turns rules off",
      not dd.run_ddos_rules(flood(500, 9, [ATTACKER]),
                            config={"enabled_rules": ["DDOS-003"]}))


# ---------------------------------------------- 4. automated_response

print("\n== automated_response compatibility")

# automated_response: the team's responder, which takes our alerts and runs the actions
sys.path.insert(0, os.path.join(dd.REPO, "automated_response"))
from automated_response import PLAYBOOKS, run_automated_response  # noqa: E402

# Codes must match exactly, or the responder reports them as failed
codes = {c for r in dd.RULES.values() for c in r["response_codes"]}
unknown = codes - set(PLAYBOOKS)
check("every response code exists in PLAYBOOKS",
      not unknown,
      ", ".join(sorted(unknown)))

needed = {"rule_id", "attack_type", "severity", "timestamp", "key",
          "evidence_count", "message", "response_codes", "details"}
check("alerts have every field from the alert format",
      all(needed <= set(a) for a in alerts))


async def respond_all(batch):
    """Sends each alert to the responder, one after another."""
    return [await run_automated_response(a) for a in batch]


# Hide the responder's print() output so the test results stay readable
with contextlib.redirect_stdout(io.StringIO()):
    results = asyncio.run(respond_all(alerts))

check("run_automated_response succeeds for every ddos-sample alert",
      all(r["success"] for r in results),
      f"{sum(r['success'] for r in results)}/{len(results)}")


print("\nALL PASSED" if not failed else "\nFAILURES ABOVE")
sys.exit(1 if failed else 0)
