"""
HTTP header spoofing rules for the Inter-Web-Defense-System pipeline.

Input : parsed http.log events (one dict per event; Zeek JSON field names).
Output: alert dicts in the Detection Rules -> Automated Response format.

  HTTP-001  Host header anomaly (Host not valid for the destination server)
  HTTP-003  Rapid User-Agent switching from one source (low severity)
  HTTP-004  Forged client-IP headers (X-Forwarded-For, X-Real-IP, Forwarded)

Run it:     python spoofing_rules/http_spoofing/http_header_rules.py   (see README.md)
From code:  run_http_header_rules(events, config) -> list of alerts

Required event fields (needs to function) : ts (or the parser's "date and time (utc)"), uid, id.orig_h, id.resp_h
Optional event fields (has backup implemented to still function) : host (001, 003), user_agent (003),
                        x_forwarded_for, x_real_ip, forwarded, x_client_ip,
                        true_client_ip, x_originating_ip (004)
"""
import argparse
import ipaddress
import json
import os
import re
import sys
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from fnmatch import fnmatch

ATTACK_TYPE = "http_header_spoofing"

# Every code here must exist in PLAYBOOKS (automated_response.py);
# an unknown code is reported as a failed action. Low is still in progress, thus []:
# send_alert() logs every alert.
RESPONSE_CODES = {
    "High": ["BLOCK_IP", "NOTIFY_ONCALL"],
    "Medium": ["NOTIFY_ONCALL"],
    "Low": [],
}

INTERNAL_HOSTNAMES = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "[::1]"}
CLIENT_IP_HEADERS = ["x_forwarded_for", "x_real_ip", "forwarded",
                     "x_client_ip", "true_client_ip", "x_originating_ip"]
PARSER_TS_FORMAT = "%Y-%m-%d %I:%M:%S %p"   

# ----------------------------------------------------------------- helpers
def get_ip(event, which):
    flat = event.get(f"id.{which}")
    if flat is not None:
        return flat
    nested = event.get("id")
    return nested.get(which) if isinstance(nested, dict) else None


def get_ts(event):
    """Epoch seconds. Will use numeric 'ts'(WIP); falls back to the parser's
    'date and time (utc)' string (loses sub-second precision)."""
    try:
        return float(event["ts"])
    except (KeyError, TypeError, ValueError):
        pass
    try:
        dt = datetime.strptime(event["date and time (utc)"], PARSER_TS_FORMAT)
        return dt.replace(tzinfo=timezone.utc).timestamp()
    except (KeyError, TypeError, ValueError):
        return None


def normalize_host(host):
    if not host or not isinstance(host, str):
        return None
    host = host.strip().lower()
    if host.startswith("["):
        host = host.split("]")[0] + "]"
    elif host.count(":") == 1:
        host = host.split(":")[0]
    return host.rstrip(".") or None


def make_alert(rule_id, severity, event, message, extra, evidence_count=1):
    ts = get_ts(event)
    iso = (datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
           if ts is not None else None)
    src = get_ip(event, "orig_h")
    return {
        "rule_id": rule_id,
        "attack_type": ATTACK_TYPE,
        "severity": severity,
        "timestamp": iso,
        "key": src,
        "evidence_count": evidence_count,
        "message": f"{message} from {src}",
        "response_codes": list(RESPONSE_CODES[severity]),
        "details": {"uid": event.get("uid"), "dst_ip": get_ip(event, "resp_h"), **extra},
    }


# ------------------------------------------------------------- HTTP-001
class HostHeaderRule:
    """Host header must be valid for the destination server. Destinations with
    no allowlist entry are skipped."""
    RULE_ID = "HTTP-001"

    def __init__(self, by_destination=None, global_allowed=None):
        self.by_destination = {ip: [h.lower() for h in hosts]
                               for ip, hosts in (by_destination or {}).items()}
        self.global_allowed = [h.lower() for h in (global_allowed or [])]

    def _allowed(self, host, dst):
        return any(fnmatch(host, p)
                   for p in self.by_destination.get(dst, []) + self.global_allowed)

    def process(self, event):
        host, dst = normalize_host(event.get("host")), get_ip(event, "resp_h")
        if host is None or dst is None:
            return []
        if host in INTERNAL_HOSTNAMES and dst not in ("127.0.0.1", "::1"):
            return [make_alert(self.RULE_ID, "Medium", event,
                               "Host header claims a loopback/internal name",
                               {"host": host})]
        if dst in self.by_destination and not self._allowed(host, dst):
            return [make_alert(self.RULE_ID, "Medium", event,
                               "Host header not allowed for this destination",
                               {"host": host,
                                "allowed_hosts": self.by_destination[dst]})]
        return []


def _is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def learn_allowlist(events, min_count=5, protected_servers=None):
    """
    Draft allowlist from BASELINE (ideally attack-free) traffic.

    Only PROTECTED servers get an allowlist: the IPs in `protected_servers`, or
    by default every private (internal) destination. Public internet
    destinations are skipped on purpose.

    Review the output before use; attacks in the baseline get learned as valid.
    """
    protected = set(protected_servers) if protected_servers else None
    counts = defaultdict(Counter)
    for e in events:
        host, dst = normalize_host(e.get("host")), get_ip(e, "resp_h")
        if not host or not dst:
            continue
        if (dst in protected) if protected is not None else _is_private(dst):
            counts[dst][host] += 1
    return {"by_destination": {d: sorted(h for h, n in c.items() if n >= min_count)
                               for d, c in counts.items()},
            "global": [], "trusted_proxies": []}


# ------------------------------------------------------------- HTTP-003
class UserAgentSwitchRule:
    """>= min_distinct User-Agents from one source to one host inside a sliding
    window. Weak evidence: Low severity. Feeds events in timestamp order."""
    RULE_ID = "HTTP-003"

    def __init__(self, window_seconds=60, min_distinct=4, cooldown_seconds=300):
        self.window, self.min_distinct, self.cooldown = (
            window_seconds, min_distinct, cooldown_seconds)
        self._seen = defaultdict(deque)
        self._last_alert = {}

    def process(self, event):
        ua, src, ts = event.get("user_agent"), get_ip(event, "orig_h"), get_ts(event)
        host = normalize_host(event.get("host")) or get_ip(event, "resp_h")
        if not ua or not src or ts is None:
            return []
        key = (src, host)
        win = self._seen[key]
        win.append((ts, ua))
        while win and ts - win[0][0] > self.window:
            win.popleft()
        distinct = {u for _, u in win}
        if len(distinct) < self.min_distinct:
            return []
        if ts - self._last_alert.get(key, float("-inf")) < self.cooldown:
            return []
        self._last_alert[key] = ts
        return [make_alert(
            self.RULE_ID, "Low", event,
            f"{len(distinct)} distinct User-Agents to one host within {self.window}s",
            {"host": host, "window_seconds": self.window,
             "user_agents": sorted(distinct)},
            evidence_count=len(win))]


# ------------------------------------------------------------- HTTP-004
def _clean_token(tok):
    tok = tok.strip().strip('"').strip()
    if tok.startswith("["):
        return tok[1:].split("]")[0]
    if tok.count(":") == 1:                     # ipv4:port
        tok = tok.split(":")[0]
    return tok


def claimed_tokens(event):
    """{header_name: [claimed client tokens]} for every client-IP header present."""
    out = {}
    for h in CLIENT_IP_HEADERS:
        val = event.get(h)
        if not val or not isinstance(val, str):
            continue
        if h == "forwarded":
            raw = re.findall(r'for=("[^"]*"|[^;,\s]+)', val, flags=re.I)
        else:
            raw = val.split(",")
        toks = [_clean_token(t) for t in raw if t.strip()]
        if toks:
            out[h] = toks
    return out


def _as_ip(tok):
    try:
        return ipaddress.ip_address(tok)
    except ValueError:
        return None


class ForwardedIpSpoofRule:
    """
    Flags:
      High   claimed IP is loopback/localhost/unspecified, or is the server itself
      Medium claimed client IP differs from the observed source IP
      Medium different headers claim different client IPs
      Medium claimed value is not an IP at all (malformed / injected)
    A header that simply repeats the observed source IP is treated as benign.
    """
    RULE_ID = "HTTP-004"

    def __init__(self, trusted_proxies=None):
        self.trusted = set(trusted_proxies or [])

    def process(self, event):
        src, dst = get_ip(event, "orig_h"), get_ip(event, "resp_h")
        if src in self.trusted:
            return []
        claims = claimed_tokens(event)
        if not claims:
            return []

        high, medium = [], []
        leftmost = {}
        for header, toks in claims.items():
            for i, tok in enumerate(toks):
                ip = _as_ip(tok)
                if tok.lower() == "localhost" or (ip and (ip.is_loopback or ip.is_unspecified)):
                    high.append(f"{header} claims loopback ({tok})")
                elif ip and str(ip) == dst:
                    high.append(f"{header} claims the server itself ({tok})")
                elif ip is None and tok.lower() not in ("unknown",) and not tok.startswith("_"):
                    medium.append(f"{header} has non-IP value ({tok})")
                if i == 0 and ip:
                    leftmost[header] = str(ip)
        for header, ip in leftmost.items():
            if ip != src and not any(header in r for r in high):
                medium.append(f"{header} claims {ip}, observed source is {src}")
        if len(set(leftmost.values())) > 1:
            medium.append("headers disagree on client IP: " + ", ".join(
                f"{h}={v}" for h, v in leftmost.items()))

        reasons = high + medium
        if not reasons:
            return []
        severity = "High" if high else "Medium"
        return [make_alert(self.RULE_ID, severity, event,
                           "Forged client-IP header",
                           {"headers": claims, "reasons": reasons})]


# ------------------------------------------------------- main entry point
def run_http_header_rules(events, config=None):
    """Runs all HTTP header rules over parsed events; returns a list of alerts.
    config keys (all optional): by_destination, global, trusted_proxies,
    ua_window_seconds, ua_min_distinct."""
    cfg = config or {}
    rules = [
        HostHeaderRule(cfg.get("by_destination"), cfg.get("global")),
        UserAgentSwitchRule(cfg.get("ua_window_seconds", 60),
                            cfg.get("ua_min_distinct", 4)),
        ForwardedIpSpoofRule(cfg.get("trusted_proxies")),
    ]
    ordered = sorted(events, key=lambda e: get_ts(e) or 0)
    return [a for e in ordered for r in rules for a in r.process(e)]


# ---------------------------------------------------------- pipeline / CLI
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))      # repo root
DEFAULT_LOG = os.path.join(REPO, "sample_logs", "header_spoofing", "zeek", "http.log")
DEFAULT_CONFIG = os.path.join(HERE, "config.json")
# Only fields every rule truly needs.
REQUIRED_FIELDS = ["uid", "id.orig_h", "id.resp_h"]


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
    """Parses a Zeek http.log with log_parsing/log_parser.py, then runs the rules."""
    import tempfile
    sys.path.insert(0, os.path.join(REPO, "log_parsing"))
    from log_parser import parseLog
    with tempfile.TemporaryDirectory() as tmp:
        parsed = os.path.join(tmp, "parsed.jsonl")
        parseLog(log_path, parsed, REQUIRED_FIELDS)
        return run_http_header_rules(list(read_events(parsed)), config)


def main():
    ap = argparse.ArgumentParser(
        description="HTTP header spoofing pipeline: http.log -> log_parser -> "
                    "HTTP-001/003/004 -> automated_response")
    ap.add_argument("log", nargs="?", default=DEFAULT_LOG, help="Zeek http.log (default: the header_spoofing sample)")
    ap.add_argument("--config", default=DEFAULT_CONFIG, help="rule config JSON")
    ap.add_argument("--no-respond", action="store_true", help="detect only; skip automated_response")
    ap.add_argument("--out", help="also write alerts to this JSONL file")
    ap.add_argument("--learn", metavar="FILE", help="write a draft allowlist learned from LOG and exit")
    args = ap.parse_args()

    if args.learn:
        with open(args.learn, "w", encoding="utf-8") as f:
            json.dump(learn_allowlist(read_events(args.log)), f, indent=2)
        print(f"Wrote draft allowlist to {args.learn} (review it before use)")
        return

    with open(args.config, encoding="utf-8") as f:
        config = json.load(f)
    alerts = detect(args.log, config)
    print(f"\n{len(alerts)} alert(s)")
    for a in alerts:
        print(f"  {a['timestamp']}  {a['rule_id']}  {a['severity']:<6}  {a['key']}  {a['message']}")
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
    for r in results:
        if not r["success"]:
            print("FAILED:", r)


if __name__ == "__main__":
    main()
