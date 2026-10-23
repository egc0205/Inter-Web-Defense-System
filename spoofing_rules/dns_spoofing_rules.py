"""
DNS spoofing rules for the Inter-Web-Defense-System pipeline.

Input : parsed Zeek dns.log events (one dict per event; Zeek JSON field names).
Output: alert dicts in the Detection Rules -> Automated Response format
        (same shape as http_header_rules.py and arp_spoofing_rules.py).

  DNS-001  Conflicting answers to the same query (classic spoofing race)
  DNS-002  DNS answer from a server that is not one of our trusted resolvers
  DNS-003  Public domain resolves to a private/internal IP (traffic redirected inside the network)

Run it:     python spoofing_rules/dns_spoofing_rules.py [path/to/dns.log]
From code:  run_dns_rules(events, config) -> list of alerts

Required event fields: id.orig_h, id.resp_h, id.resp_p, trans_id, query, answers,
                       ts (or the parser's "date and time (utc)")
"""
import argparse
import ipaddress
import json
import os
import sys
from datetime import datetime, timezone

ATTACK_TYPE = "dns_spoofing"

# Every code must exist in PLAYBOOKS (automated_response.py).
RESPONSE_CODES = {
    "High": ["BLOCK_IP", "NOTIFY_ONCALL", "OPEN_TICKET"],
    "Medium": ["NOTIFY_ONCALL", "OPEN_TICKET"],
    "Low": [],
}

PARSER_TS_FORMAT = "%Y-%m-%d %I:%M:%S %p"
DNS_PORT = 53                             # 137 (NetBIOS) and 5353 (mDNS) are not regular DNS


# ----------------------------------------------------------------- helpers
def get_ts(event):
    try:
        return float(event["ts"])
    except (KeyError, TypeError, ValueError):
        pass
    try:
        dt = datetime.strptime(event["date and time (utc)"], PARSER_TS_FORMAT)
        return dt.replace(tzinfo=timezone.utc).timestamp()
    except (KeyError, TypeError, ValueError):
        return None


def ip_answers(event):
    """Only the answers that are IP addresses (drops CNAME names etc.)."""
    out = []
    for a in event.get("answers") or []:
        try:
            out.append(str(ipaddress.ip_address(a)))
        except ValueError:
            pass
    return out


# Real internal ranges only. (Python's is_private also includes documentation
# ranges like 203.0.113.0/24, which are not inside anyone's network.)
INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",   # private (RFC 1918)
    "127.0.0.0/8", "169.254.0.0/16",                    # loopback, link-local
    "::1/128", "fc00::/7", "fe80::/10")]


def is_internal_ip(ip):
    a = ipaddress.ip_address(ip)
    return any(a in n for n in INTERNAL_NETS if n.version == a.version)


def make_alert(rule_id, severity, event, message, key, extra, codes=None):
    ts = get_ts(event)
    iso = (datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
           if ts is not None else None)
    return {
        "rule_id": rule_id,
        "attack_type": ATTACK_TYPE,
        "severity": severity,
        "timestamp": iso,
        "key": key,
        "evidence_count": 1,
        "message": message,
        "response_codes": list(codes if codes is not None else RESPONSE_CODES[severity]),
        "details": {"uid": event.get("uid"), "client": event.get("id.orig_h"),
                    "dns_server": event.get("id.resp_h"), "query": event.get("query"), **extra},
    }


class Deduper:
    """One alert per (rule, key, query); repeats just bump evidence_count."""
    def __init__(self):
        self.seen = {}

    def emit(self, k, build):
        if k in self.seen:
            self.seen[k]["evidence_count"] += 1
            return []
        self.seen[k] = build()
        return [self.seen[k]]


# ------------------------------------------------------------- DNS-001
class ConflictingAnswerRule:
    """A client asks one question (one transaction ID). It should get one answer.
    In a spoofing race the attacker sends a fake answer with the same ID, so the
    client sees two DIFFERENT answers for the same question within seconds.
    (Zeek sometimes logs the same answer twice; identical answers are ignored.)
    The key is the VICTIM (we can't tell which answer was fake), so this rule
    notifies and opens a ticket instead of blocking anyone."""
    RULE_ID = "DNS-001"

    def __init__(self, window):
        self.window = window
        self.first = {}                   # (client, trans_id, query) -> (ts, answers, server)
        self.dedup = Deduper()

    def process(self, event):
        answers = ip_answers(event)
        if not answers:
            return []
        ts = get_ts(event) or 0
        k = (event["id.orig_h"], event["trans_id"], event["query"])
        prev = self.first.get(k)
        if prev is None or ts - prev[0] > self.window:
            self.first[k] = (ts, set(answers), event["id.resp_h"])
            return []
        if set(answers) == prev[1]:
            return []                     # duplicate log line, same answer: normal
        return self.dedup.emit(k, lambda: make_alert(
            self.RULE_ID, "High", event,
            f"Two different answers for {event['query']} (txid {event['trans_id']}) "
            f"to {event['id.orig_h']}: {sorted(prev[1])} vs {sorted(answers)}",
            key=event["id.orig_h"],
            codes=["NOTIFY_ONCALL", "OPEN_TICKET"],
            extra={"first_answers": sorted(prev[1]), "second_answers": sorted(answers),
                   "first_server": prev[2]}))


# ------------------------------------------------------------- DNS-002
class RogueResolverRule:
    """Clients should only get DNS answers from our own DNS servers. An answer
    from any other machine on port 53 means a rogue DNS server."""
    RULE_ID = "DNS-002"

    def __init__(self, trusted):
        self.trusted = set(trusted)
        self.dedup = Deduper()

    def process(self, event):
        server = event["id.resp_h"]
        if event.get("id.resp_p") != DNS_PORT or not ip_answers(event):
            return []
        if not self.trusted or server in self.trusted:
            return []
        return self.dedup.emit((server, event["query"]), lambda: make_alert(
            self.RULE_ID, "High", event,
            f"Untrusted DNS server {server} answered {event['query']} for {event['id.orig_h']}",
            key=server, extra={"answers": ip_answers(event),
                               "trusted_resolvers": sorted(self.trusted)}))


# ------------------------------------------------------------- DNS-003
class PrivateAnswerRule:
    """A public website (google.com, a bank, ...) should never resolve to an
    address inside our network. If it does, someone is redirecting victims to a
    machine they control. The company's own domains are allowed."""
    RULE_ID = "DNS-003"

    def __init__(self, internal_domains):
        self.internal = [d.lower().lstrip(".") for d in internal_domains]
        self.dedup = Deduper()

    def _is_internal_name(self, name):
        name = (name or "").lower().rstrip(".")
        return (name.endswith((".local", ".lan", ".arpa"))
                or any(name == d or name.endswith("." + d) for d in self.internal))

    def process(self, event):
        q = event.get("query")
        if event.get("id.resp_p") != DNS_PORT or self._is_internal_name(q):
            return []
        bad = [a for a in ip_answers(event) if is_internal_ip(a)]
        if not bad:
            return []
        return self.dedup.emit((event["id.resp_h"], q), lambda: make_alert(
            self.RULE_ID, "Medium", event,
            f"Public domain {q} resolved to internal IP {', '.join(bad)} (server {event['id.resp_h']})",
            key=event["id.resp_h"], extra={"internal_answers": bad}))


# ------------------------------------------------------- main entry point
def run_dns_rules(events, config=None):
    cfg = config or {}
    rules = [
        ConflictingAnswerRule(cfg.get("conflict_window_seconds", 5)),
        RogueResolverRule(cfg.get("trusted_resolvers", [])),
        PrivateAnswerRule(cfg.get("internal_domains", [])),
    ]
    ordered = sorted(events, key=lambda e: get_ts(e) or 0)   # Zeek dns.log is not always in time order
    return [a for e in ordered for r in rules for a in r.process(e)]


# ---------------------------------------------------------- pipeline / CLI
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
DEFAULT_LOG = os.path.join(REPO, "sample_logs", "dns_spoofing_synthetic", "dns.log")
DEFAULT_CONFIG = os.path.join(HERE, "dns_config.json")
REQUIRED_FIELDS = ["id.orig_h", "id.resp_h", "id.resp_p", "trans_id", "query"]


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
    """Parses dns.log with log_parsing/log_parser.py, then runs the rules."""
    import tempfile
    sys.path.insert(0, os.path.join(REPO, "log_parsing"))
    from log_parser import parseLog
    with tempfile.TemporaryDirectory() as tmp:
        parsed = os.path.join(tmp, "parsed.jsonl")
        parseLog(log_path, parsed, REQUIRED_FIELDS)
        return run_dns_rules(list(read_events(parsed)), config)


def main():
    ap = argparse.ArgumentParser(
        description="DNS spoofing pipeline: dns.log -> log_parser -> DNS-001/002/003 -> automated_response")
    ap.add_argument("log", nargs="?", default=DEFAULT_LOG, help="Zeek dns.log (default: synthetic DNS spoofing sample)")
    ap.add_argument("--config", default=DEFAULT_CONFIG, help="rule config JSON")
    ap.add_argument("--no-respond", action="store_true", help="detect only; skip automated_response")
    ap.add_argument("--out", help="also write alerts to this JSONL file")
    args = ap.parse_args()

    with open(args.config, encoding="utf-8") as f:
        config = json.load(f)
    alerts = detect(args.log, config)
    print(f"\n{len(alerts)} alert(s)")
    for a in alerts:
        print(f"  {a['timestamp']}  {a['rule_id']}  {a['severity']:<6}  x{a['evidence_count']:<3} {a['message']}")
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
