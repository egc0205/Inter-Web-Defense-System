"""
ARP spoofing rules for the Inter-Web-Defense-System pipeline.

Input : parsed arp.log events (one dict per ARP message).
Output: alert dicts in the Detection Rules -> Automated Response format
        (same shape as http_header_rules.py).

  ARP-001  IP-to-MAC binding changed (a new MAC claims an IP that already had an owner)
  ARP-002  One MAC claims several IPs (one network card pretending to be many hosts)
  ARP-003  Unsolicited ARP reply flood (replies nobody asked for, sent over and over)

Run it:     python spoofing_rules/arp_spoofing_rules.py
From code:  run_arp_rules(events, config) -> list of alerts

Required event fields: sender_ip, sender_mac, operation, target_ip,
                       ts (or the parser's "date and time (utc)")
"""
import argparse
import json
import os
import sys
from collections import defaultdict, deque
from datetime import datetime, timezone

ATTACK_TYPE = "arp_spoofing"

# Every code must exist in PLAYBOOKS (automated_response.py).
RESPONSE_CODES = {
    "High": ["ISOLATE_HOST", "NOTIFY_ONCALL", "OPEN_TICKET"],
    "Medium": ["NOTIFY_ONCALL", "OPEN_TICKET"],
    "Low": [],
}

PARSER_TS_FORMAT = "%Y-%m-%d %I:%M:%S %p"


# ----------------------------------------------------------------- helpers
def get_ts(event):
    """Epoch seconds. Uses numeric 'ts' if present; otherwise falls back to
    the log parser's 'date and time (utc)' string."""
    try:
        return float(event["ts"])
    except (KeyError, TypeError, ValueError):
        pass
    try:
        dt = datetime.strptime(event["date and time (utc)"], PARSER_TS_FORMAT)
        return dt.replace(tzinfo=timezone.utc).timestamp()
    except (KeyError, TypeError, ValueError):
        return None


def make_alert(rule_id, severity, event, message, key, extra):
    ts = get_ts(event)
    iso = (datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
           if ts is not None else None)
    return {
        "rule_id": rule_id,
        "attack_type": ATTACK_TYPE,
        "severity": severity,
        "timestamp": iso,
        "key": key,                       # the attacker's MAC
        "evidence_count": 1,              # bumped each time the same thing repeats
        "message": message,
        "response_codes": list(RESPONSE_CODES[severity]),
        "details": extra,
    }


# ------------------------------------------------------------- ARP-001
class BindingChangeRule:
    """Remembers the first MAC seen for each IP. If a different MAC later
    claims that IP, someone is lying about who owns it.
    Spoofing the gateway is High (all outside traffic flows through it);
    spoofing any other host is Medium."""
    RULE_ID = "ARP-001"

    def __init__(self, gateways, known_bindings):
        self.gateways = set(gateways)
        self.table = {ip: mac.lower() for ip, mac in known_bindings.items()}
        self.open_alerts = {}             # (ip, new_mac) -> alert, so we don't make 900 alerts

    def process(self, event):
        ip, mac = event["sender_ip"], event["sender_mac"].lower()
        if ip == "0.0.0.0":               # ARP probe: the sender has no IP yet
            return [], False
        owner = self.table.get(ip)
        if owner is None:                 # first time we see this IP: learn it
            self.table[ip] = mac
            return [], False
        if owner == mac:                  # same owner as before: normal
            return [], False

        # A different MAC is claiming this IP.
        k = (ip, mac)
        if k in self.open_alerts:         # already alerted: just count it
            self.open_alerts[k]["evidence_count"] += 1
            return [], True
        severity = "High" if ip in self.gateways else "Medium"
        who = "the GATEWAY " + ip if ip in self.gateways else ip
        alert = make_alert(self.RULE_ID, severity, event,
                           f"MAC {mac} is claiming to be {who} (real owner is {owner})",
                           key=mac,
                           extra={"claimed_ip": ip, "real_mac": owner,
                                  "spoofed_mac": mac, "told_to": event.get("target_ip")})
        self.open_alerts[k] = alert
        return [alert], True


# ------------------------------------------------------------- ARP-002
class MultiIpClaimRule:
    """A normal network card has one IP. If one MAC claims `max_ips` or more
    different IPs, it is probably impersonating other machines."""
    RULE_ID = "ARP-002"

    def __init__(self, max_ips):
        self.max_ips = max_ips
        self.claims = defaultdict(set)    # mac -> set of IPs it has claimed
        self.alerted = {}                 # mac -> alert

    def process(self, event):
        ip, mac = event["sender_ip"], event["sender_mac"].lower()
        if ip == "0.0.0.0":
            return []
        self.claims[mac].add(ip)
        ips = self.claims[mac]
        if len(ips) < self.max_ips:
            return []
        if mac in self.alerted:           # already alerted: update the IP list
            a = self.alerted[mac]
            a["evidence_count"] += 1
            a["details"]["claimed_ips"] = sorted(ips)
            a["message"] = f"MAC {mac} is claiming {len(ips)} different IPs: {', '.join(sorted(ips))}"
            return []
        alert = make_alert(self.RULE_ID, "High", event,
                           f"MAC {mac} is claiming {len(ips)} different IPs: {', '.join(sorted(ips))}",
                           key=mac, extra={"claimed_ips": sorted(ips)})
        self.alerted[mac] = alert
        return [alert]


# ------------------------------------------------------------- ARP-003
class UnsolicitedReplyFloodRule:
    """In normal ARP, a reply answers a request. Spoofing tools send replies
    nobody asked for, every couple of seconds, to keep victims' caches poisoned.
    Alert when one MAC sends `min_replies` unsolicited replies within `window` seconds."""
    RULE_ID = "ARP-003"

    def __init__(self, window, min_replies, request_timeout=5):
        self.window = window
        self.min_replies = min_replies
        self.request_timeout = request_timeout
        self.pending = {}                 # (asker_ip, asked_about_ip) -> time of request
        self.recent = defaultdict(deque)  # mac -> times of its unsolicited replies
        self.alerted = {}

    def process(self, event):
        ts = get_ts(event) or 0
        op = event.get("operation")
        if op == "request":               # remember who asked about what
            self.pending[(event["sender_ip"], event["target_ip"])] = ts
            return []
        if op != "reply":
            return []

        # Was this reply asked for? (target asked about sender_ip recently)
        asked = self.pending.get((event["target_ip"], event["sender_ip"]))
        if asked is not None and ts - asked <= self.request_timeout:
            return []                     # solicited reply: normal

        mac = event["sender_mac"].lower()
        q = self.recent[mac]
        q.append(ts)
        while q and ts - q[0] > self.window:
            q.popleft()                   # forget replies older than the window
        if len(q) < self.min_replies:
            return []
        if mac in self.alerted:
            self.alerted[mac]["evidence_count"] += 1
            return []
        alert = make_alert(self.RULE_ID, "Medium", event,
                           f"MAC {mac} sent {len(q)} unsolicited ARP replies in {self.window}s",
                           key=mac, extra={"window_seconds": self.window,
                                           "unsolicited_replies": len(q)})
        self.alerted[mac] = alert
        return [alert]


# ------------------------------------------------------- main entry point
def run_arp_rules(events, config=None, return_flags=False):
    """Runs all ARP rules over parsed events (in time order); returns a list of alerts.
    With return_flags=True, also returns a list saying, for each event, whether
    ARP-001 flagged it (used to score against ground_truth.csv)."""
    cfg = config or {}
    r1 = BindingChangeRule(cfg.get("gateways", []), cfg.get("known_bindings", {}))
    r2 = MultiIpClaimRule(cfg.get("max_ips_per_mac", 2))
    r3 = UnsolicitedReplyFloodRule(cfg.get("reply_window_seconds", 30),
                                   cfg.get("min_unsolicited_replies", 10))
    alerts, flags = [], []
    for e in events:                      # assumes events are already sorted by time
        new, flagged = r1.process(e)
        alerts += new
        alerts += r2.process(e)
        alerts += r3.process(e)
        flags.append(flagged)
    return (alerts, flags) if return_flags else alerts


# ---------------------------------------------------------- pipeline / CLI
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
DEFAULT_LOG = os.path.join(REPO, "sample_logs", "arp_spoofing", "arp.log")
DEFAULT_CONFIG = os.path.join(HERE, "arp_config.json")
REQUIRED_FIELDS = ["sender_ip", "sender_mac", "operation", "target_ip"]


def read_events(path):
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue


def detect(log_path, config):
    """Parses arp.log with log_parsing/log_parser.py, then runs the rules."""
    import tempfile
    sys.path.insert(0, os.path.join(REPO, "log_parsing"))
    from log_parser import parseLog
    with tempfile.TemporaryDirectory() as tmp:
        parsed = os.path.join(tmp, "parsed.jsonl")
        parseLog(log_path, parsed, REQUIRED_FIELDS)
        return run_arp_rules(list(read_events(parsed)), config)


def main():
    ap = argparse.ArgumentParser(
        description="ARP spoofing pipeline: arp.log -> log_parser -> ARP-001/002/003 -> automated_response")
    ap.add_argument("log", nargs="?", default=DEFAULT_LOG, help="ARP log (default: the arp_spoofing sample)")
    ap.add_argument("--config", default=DEFAULT_CONFIG, help="rule config JSON")
    ap.add_argument("--no-respond", action="store_true", help="detect only; skip automated_response")
    ap.add_argument("--out", help="also write alerts to this JSONL file")
    args = ap.parse_args()

    with open(args.config, encoding="utf-8") as f:
        config = json.load(f)
    alerts = detect(args.log, config)
    print(f"\n{len(alerts)} alert(s)")
    for a in alerts:
        print(f"  {a['timestamp']}  {a['rule_id']}  {a['severity']:<6}  x{a['evidence_count']:<4} {a['message']}")
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.writelines(json.dumps(a) + "\n" for a in alerts)
        print(f"alerts written to {args.out}")
    if args.no_respond or not alerts:
        return

    import asyncio
    sys.path.insert(0, os.path.join(REPO, "automated_response"))
    from automated_response import run_automated_response

    async def respond():
        return [await run_automated_response(a) for a in alerts]

    print("\n--- automated response ---")
    results = asyncio.run(respond())
    print(f"\n{sum(r['success'] for r in results)}/{len(results)} responses succeeded")


if __name__ == "__main__":
    main()
