"""
DDoS detection rules (DDOS-001 .. DDOS-008) for the Inter-Web-Defense-System pipeline.
Implements "DDoS Detection Rules.pdf" in this folder.

Input : parsed Zeek http.log and/or conn.log events (one dict per event, Zeek JSON
        field names). Works on raw logs and on log_parser.py output (which swaps
        "ts" for a "date and time (utc)" string).
Output: alert dicts in the Detection Rules -> Automated Response format
        (rule_id, attack_type, severity, timestamp, key, evidence_count, message,
        response_codes, details), ready for automated_response.run_automated_response().

  DDOS-001  Single-source HTTP flood        http.log  Medium -> High
  DDOS-002  Distributed HTTP flood          http.log  High   -> Critical
  DDOS-003  SYN flood                       conn.log  High
  DDOS-004  URI hammering                   http.log  Medium -> High
  DDOS-005  UDP / ICMP flood                conn.log  High
  DDOS-006  Error-rate spike                http.log  Medium (alert only)
  DDOS-007  Traffic spike vs baseline       http.log  Medium (alert only)
  DDOS-008  Slow attack (Slowloris-style)   conn.log  Medium

One alert per attack episode: an episode opens when a rule's condition first holds,
keeps collecting evidence while it holds, and ends once the condition has not held
for a full window. The alert's timestamp is when the episode started, the message
reports the peak window, and evidence_count / details.uids cover the whole episode.

From code:  run_ddos_rules(http_events, conn_events, config) -> list of alerts
            detect(http_log_path, conn_log_path, config)    -> same, via log_parser.py
Run it:     python ddos_rules/run_ddos.py --help
"""

# contextlib: hides log_parser.py's print() output while it parses for us
import contextlib

# copy: deep-copies DEFAULT_CONFIG so one run's settings never change another's
import copy

# io: gives contextlib a place (StringIO) to send the hidden output
import io

# ipaddress: checks whether an IP is one of our protected servers (IPs, CIDR ranges,
# private addresses)
import ipaddress

# json: every Zeek log line is a JSON object
import json

# math: square root for the standard deviation in DDOS-007
import math

# os: builds file paths that work on Windows, Mac and Linux
import os

# sys: lets us import log_parser.py from the log_parsing folder
import sys

# uuid: gives every alert a unique alert_id, like the injection rules do
import uuid

# Counter: counts requests per source IP
# defaultdict: per-target state without checking if the key exists first
# deque: the sliding window; old events drop off the front quickly
from collections import Counter, defaultdict, deque

# datetime / timezone: converts Unix timestamps to the alert's UTC time format
# and reads log_parser.py's "date and time (utc)" field
from datetime import datetime, timezone

# Don't leave __pycache__ in other team folders
sys.dont_write_bytecode = True

# Folder paths, so the code works no matter where it is run from
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

ATTACK_TYPE = "ddos"
PARSER_TIME_FIELD = "date and time (utc)"
PARSER_TIME_FORMAT = "%Y-%m-%d %I:%M:%S %p"

# Response codes must match PLAYBOOKS in automated_response.py exactly.
# ALERT_ONLY is not a playbook action: those rules send [] (send_alert() still logs
# the alert) and record "ALERT_ONLY" in details["response"].
RULES = {
    "DDOS-001": {"name": "Single-source HTTP flood", "log": "http",
                 "severity": ("Medium", "High"), "response_codes": ["ENABLE_RATE_LIMITING"]},
    "DDOS-002": {"name": "Distributed HTTP flood", "log": "http",
                 "severity": ("High", "Critical"),
                 "response_codes": ["ENABLE_RATE_LIMITING", "NOTIFY_ONCALL"]},
    "DDOS-003": {"name": "SYN flood", "log": "conn",
                 "severity": ("High", "High"), "response_codes": ["ENABLE_SYN_COOKIES"]},
    "DDOS-004": {"name": "URI hammering", "log": "http",
                 "severity": ("Medium", "High"), "response_codes": ["CHALLENGE_ENDPOINT"]},
    "DDOS-005": {"name": "UDP / ICMP flood", "log": "conn",
                 "severity": ("High", "High"), "response_codes": ["BLOCK_PROTOCOL_RATE"]},
    "DDOS-006": {"name": "Error-rate spike", "log": "http",
                 "severity": ("Medium", "Medium"), "response_codes": ["ALERT_ONLY"]},
    "DDOS-007": {"name": "Traffic spike vs baseline", "log": "http",
                 "severity": ("Medium", "Medium"), "response_codes": ["ALERT_ONLY"]},
    "DDOS-008": {"name": "Slow attack (Slowloris-style)", "log": "conn",
                 "severity": ("Medium", "Medium"), "response_codes": ["DROP_CONNECTIONS"]},
}
ALERT_ONLY = "ALERT_ONLY"

# Default thresholds from section 2 of the rules doc. config.json overrides any of these.
DEFAULT_CONFIG = {
    # Servers we defend. IPs or CIDRs. Empty = every private (internal) address.
    # Traffic to other destinations (e.g. users browsing the internet) is ignored.
    "protected_servers": [],
    "enabled_rules": list(RULES),
    # Higher severity once the count reaches 5x the threshold
    "escalation_factor": 5,
    # Cap on details.uids per alert; null = keep all
    "max_uids": None,
    "DDOS-001": {"window_seconds": 10, "threshold": 100},
    "DDOS-002": {"window_seconds": 10, "threshold": 500, "min_sources": 20},
    "DDOS-003": {"window_seconds": 10, "threshold": 200},
    "DDOS-004": {"window_seconds": 30, "threshold": 300, "min_sources": 10},
    "DDOS-005": {"window_seconds": 10, "threshold": 1000, "baseline_multiplier": 10,
                 "min_history_seconds": 60},
    "DDOS-006": {"window_seconds": 60, "min_requests": 20, "error_ratio": 0.5},
    "DDOS-007": {"window_seconds": 60, "history_minutes": 10, "min_history_minutes": 2,
                 "std_devs": 3, "min_requests": 600},
    "DDOS-008": {"window_seconds": 300, "threshold": 50, "max_sources": 3,
                 "min_duration": 60, "open_states": ["S1"]},
}

HTTP_REQUIRED_FIELDS = ["ts", "uid", "id.orig_h", "id.resp_h"]
CONN_REQUIRED_FIELDS = ["ts", "uid", "id.orig_h", "id.resp_h", "proto"]


# ----------------------------------------------------------------- helpers
def event_time(event):
    """Epoch seconds from 'ts', or from log_parser's 'date and time (utc)' string."""
    try:
        return float(event["ts"])
    except (KeyError, TypeError, ValueError):
        pass
    try:
        dt = datetime.strptime(event[PARSER_TIME_FIELD], PARSER_TIME_FORMAT)
        return dt.replace(tzinfo=timezone.utc).timestamp()
    except (KeyError, TypeError, ValueError):
        return None


def get_ip(event, which):
    flat = event.get(f"id.{which}")
    if flat is not None:
        return flat
    nested = event.get("id")
    return nested.get(which) if isinstance(nested, dict) else None


def iso_utc(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_config(config=None):
    """Defaults from the rules doc, with any keys in `config` laid on top."""
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    for k, v in (config or {}).items():
        if isinstance(v, dict) and isinstance(cfg.get(k), dict):
            cfg[k].update(v)
        else:
            cfg[k] = v
    return cfg


class ProtectedServers:
    def __init__(self, entries):
        self.nets = [ipaddress.ip_network(e, strict=False) for e in (entries or [])]
        self._cache = {}

    def __contains__(self, ip):
        if ip not in self._cache:
            try:
                addr = ipaddress.ip_address(ip)
            except (ValueError, TypeError):
                self._cache[ip] = False
            else:
                if self.nets:
                    self._cache[ip] = any(addr in n for n in self.nets)
                else:
                    self._cache[ip] = addr.is_private and not (
                        addr.is_loopback or addr.is_multicast or addr.is_unspecified
                        or addr.is_link_local)
        return self._cache[ip]


def make_alert(rule_id, severity, ts, key, uids, message, details, max_uids=None):
    rule = RULES[rule_id]
    codes = [c for c in rule["response_codes"] if c != ALERT_ONLY]
    shown = uids if max_uids is None else uids[:max_uids]
    out_details = {"uid": uids[0] if uids else None, "uids": shown}
    if ALERT_ONLY in rule["response_codes"]:
        out_details["response"] = ALERT_ONLY
    out_details.update(details)
    return {
        "alert_id": uuid.uuid4().hex[:12],
        "rule_id": rule_id,
        "attack_type": ATTACK_TYPE,
        "severity": severity,
        "timestamp": iso_utc(ts),
        "key": key,
        "evidence_count": len(uids),
        "message": message,
        "response_codes": codes,
        "details": out_details,
    }


class Episode:
    """One attack episode for one group key: start, peak and all evidence."""

    def __init__(self, start):
        self.start = start
        self.last_hit = start
        self.end = start
        self.uids = []
        self._seen = set()
        self.sources = Counter()
        self.peak = 0
        self.peak_ts = start
        self.peak_info = {}

    def add(self, ts, src, uid, weight=1):
        if uid and uid not in self._seen:
            self._seen.add(uid)
            self.uids.append(uid)
        if src:
            self.sources[src] += weight
        self.end = max(self.end, ts)

    def top_source(self):
        return self.sources.most_common(1)[0][0] if self.sources else None

    def top_sources(self, n=5):
        return [{"ip": ip, "count": c} for ip, c in self.sources.most_common(n)]


# ------------------------------------------------- sliding-window rule base
class SlidingWindowRule:
    """Counts events per group key over the last `window_seconds` and tracks episodes.
    Subclasses define group(), qualifies(), and alert()."""
    RULE_ID = None

    def __init__(self, cfg, protected, global_cfg):
        self.cfg = cfg
        self.window = cfg["window_seconds"]
        self.protected = protected
        self.factor = global_cfg["escalation_factor"]
        self.max_uids = global_cfg["max_uids"]
        # Events in the current window per key, as (ts, src, uid, weight, tag)
        self.items = defaultdict(deque)
        # Total weight in the current window per key
        self.total = defaultdict(float)
        # Weight from each source in the current window per key
        self.srcs = defaultdict(Counter)
        # Episode in progress per key
        self.active = {}
        self.alerts = []

    # -- subclass hooks
    def group(self, event):
        raise NotImplementedError

    def weight(self, event):
        return 1

    def tag(self, event):
        return None

    def on_add(self, key, item):
        pass

    def on_remove(self, key, item):
        pass

    def qualifies(self, key, ts):
        """-> (bool, peak measure, info dict for the message)"""
        raise NotImplementedError

    def alert(self, key, ep):
        raise NotImplementedError

    # -- engine
    def severity(self, peak, threshold):
        low, high = RULES[self.RULE_ID]["severity"]
        return high if peak >= self.factor * threshold else low

    def process(self, event, ts):
        key = self.group(event)
        if key is None:
            return
        self._close_stale(ts)
        src, uid = get_ip(event, "orig_h"), event.get("uid")
        item = (ts, src, uid, self.weight(event), self.tag(event))
        dq = self.items[key]
        dq.append(item)
        self.total[key] += item[3]
        self.srcs[key][src] += item[3]
        self.on_add(key, item)
        while dq and ts - dq[0][0] >= self.window:
            old = dq.popleft()
            self.total[key] -= old[3]
            self.srcs[key][old[1]] -= old[3]
            if self.srcs[key][old[1]] <= 0:
                del self.srcs[key][old[1]]
            self.on_remove(key, old)

        ok, measure, info = self.qualifies(key, ts)
        ep = self.active.get(key)
        if ok:
            if ep is None:
                ep = self.active[key] = Episode(dq[0][0])
                for t, s, u, w, _ in dq:
                    ep.add(t, s, u, w)
            else:
                ep.add(ts, src, uid, item[3])
            ep.last_hit = ts
            if measure > ep.peak:
                ep.peak, ep.peak_ts = measure, ts
                ep.peak_info = {**info, "distinct_sources": len(self.srcs[key])}
        elif ep is not None:
            # Tail of an ongoing episode
            ep.add(ts, src, uid, item[3])

    def _close_stale(self, ts):
        for key in [k for k, ep in self.active.items() if ts - ep.last_hit >= self.window]:
            self.alerts.append(self.alert(key, self.active.pop(key)))

    def flush(self):
        for key in list(self.active):
            self.alerts.append(self.alert(key, self.active.pop(key)))

    def base_details(self, dst, ep, pattern):
        return {
            "dst_ip": dst,
            "matched_pattern": pattern,
            "window_seconds": self.window,
            "peak_count": ep.peak,
            "peak_time": iso_utc(ep.peak_ts),
            "episode_start": iso_utc(ep.start),
            "episode_end": iso_utc(ep.end),
            "distinct_sources": len(ep.sources),
            "top_sources": ep.top_sources(),
        }

    def _alert(self, ep, severity, key_ip, message, details):
        return make_alert(self.RULE_ID, severity, ep.start, key_ip, ep.uids,
                          message, details, self.max_uids)


def _num(n):
    return int(n) if float(n).is_integer() else round(n, 1)


# ------------------------------------------------------------- DDOS-001
class SingleSourceFlood(SlidingWindowRule):
    """One source sends >= threshold HTTP requests to one protected server in the window."""
    RULE_ID = "DDOS-001"

    def group(self, e):
        src, dst = get_ip(e, "orig_h"), get_ip(e, "resp_h")
        return (src, dst) if src and dst in self.protected else None

    def qualifies(self, key, ts):
        n = self.total[key]
        return n >= self.cfg["threshold"], n, {}

    def alert(self, key, ep):
        src, dst = key
        thr = self.cfg["threshold"]
        return self._alert(
            ep, self.severity(ep.peak, thr), src,
            f"{RULES[self.RULE_ID]['name']}: {_num(ep.peak)} requests from {src} "
            f"to {dst} in {self.window}s",
            self.base_details(dst, ep, f">= {thr} requests from one IP in {self.window}s"))


# ------------------------------------------------------------- DDOS-002
class DistributedFlood(SlidingWindowRule):
    """A protected server receives >= threshold requests from >= min_sources IPs."""
    RULE_ID = "DDOS-002"

    def group(self, e):
        dst = get_ip(e, "resp_h")
        return dst if get_ip(e, "orig_h") and dst in self.protected else None

    def qualifies(self, key, ts):
        n = self.total[key]
        return (n >= self.cfg["threshold"] and len(self.srcs[key]) >= self.cfg["min_sources"],
                n, {})

    def alert(self, dst, ep):
        thr, ms = self.cfg["threshold"], self.cfg["min_sources"]
        n_src = ep.peak_info.get("distinct_sources", len(ep.sources))
        return self._alert(
            ep, self.severity(ep.peak, thr), ep.top_source(),
            f"{RULES[self.RULE_ID]['name']}: {_num(ep.peak)} requests from {n_src} sources "
            f"to {dst} in {self.window}s",
            self.base_details(dst, ep, f">= {thr} requests from >= {ms} IPs in {self.window}s"))


# ------------------------------------------------------------- DDOS-003
class SynFlood(SlidingWindowRule):
    """>= threshold TCP connection attempts (each counts as one SYN) to one protected server."""
    RULE_ID = "DDOS-003"

    def group(self, e):
        if str(e.get("proto", "")).lower() != "tcp":
            return None
        history = e.get("history")
        # Skip connections picked up mid-stream (no SYN seen)
        if history is not None and "S" not in history:
            return None
        dst = get_ip(e, "resp_h")
        return dst if dst in self.protected else None

    def qualifies(self, key, ts):
        n = self.total[key]
        return n >= self.cfg["threshold"], n, {}

    def alert(self, dst, ep):
        thr = self.cfg["threshold"]
        return self._alert(
            ep, self.severity(ep.peak, thr), ep.top_source(),
            f"{RULES[self.RULE_ID]['name']}: {_num(ep.peak)} TCP connection attempts "
            f"to {dst} in {self.window}s",
            self.base_details(dst, ep, f">= {thr} SYNs to one target in {self.window}s"))


# ------------------------------------------------------------- DDOS-004
class UriHammering(SlidingWindowRule):
    """>= threshold requests to one URI on a protected server from >= min_sources IPs."""
    RULE_ID = "DDOS-004"

    def group(self, e):
        dst, uri = get_ip(e, "resp_h"), e.get("uri")
        if not uri or not get_ip(e, "orig_h") or dst not in self.protected:
            return None
        return (dst, uri.split("?", 1)[0])

    def qualifies(self, key, ts):
        n = self.total[key]
        return (n >= self.cfg["threshold"] and len(self.srcs[key]) >= self.cfg["min_sources"],
                n, {})

    def alert(self, key, ep):
        dst, uri = key
        thr, ms = self.cfg["threshold"], self.cfg["min_sources"]
        n_src = ep.peak_info.get("distinct_sources", len(ep.sources))
        details = self.base_details(
            dst, ep, f">= {thr} requests to one URI from >= {ms} IPs in {self.window}s")
        details["uri"] = uri[:300]
        return self._alert(
            ep, self.severity(ep.peak, thr), ep.top_source(),
            f"{RULES[self.RULE_ID]['name']}: {_num(ep.peak)} requests to {uri[:100]} on {dst} "
            f"from {n_src} sources in {self.window}s",
            details)


# ------------------------------------------------------------- DDOS-005
class UdpIcmpFlood(SlidingWindowRule):
    """>= threshold UDP or ICMP packets to one protected server in the window, and
    >= baseline_multiplier x that target's normal rate. Normal rate = the target's
    packets before this window, averaged over the time since the log started
    (0 for a target never seen before). Needs min_history_seconds of log before the
    window, otherwise every busy UDP server would look like a flood at startup."""
    RULE_ID = "DDOS-005"

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.cumulative = defaultdict(float)
        self.stream_start = None

    def group(self, e):
        proto = str(e.get("proto", "")).lower()
        if proto not in ("udp", "icmp"):
            return None
        dst = get_ip(e, "resp_h")
        return (dst, proto) if dst in self.protected else None

    def weight(self, e):
        try:
            return max(float(e.get("orig_pkts") or 0), 1.0)
        except (TypeError, ValueError):
            return 1.0

    def process(self, event, ts):
        if self.stream_start is None:
            self.stream_start = ts
        super().process(event, ts)

    def on_add(self, key, item):
        self.cumulative[key] += item[3]

    def qualifies(self, key, ts):
        n = self.total[key]
        before = self.cumulative[key] - n
        elapsed = (ts - self.window) - self.stream_start
        if elapsed < self.cfg["min_history_seconds"]:
            return False, n, {}
        normal = before / elapsed * self.window
        ok = n >= self.cfg["threshold"] and n >= self.cfg["baseline_multiplier"] * normal
        return ok, n, {"normal_per_window": round(normal, 1)}

    def alert(self, key, ep):
        dst, proto = key
        thr, mult = self.cfg["threshold"], self.cfg["baseline_multiplier"]
        normal = ep.peak_info.get("normal_per_window", 0)
        ratio = f"{ep.peak / normal:.0f}x" if normal else "no prior traffic to compare"
        details = self.base_details(
            dst, ep, f">= {thr} {proto.upper()} packets in {self.window}s and >= {mult}x normal")
        details.update({"proto": proto, "normal_packets_per_window": normal})
        return self._alert(
            ep, self.severity(ep.peak, thr), ep.top_source(),
            f"{proto.upper()} flood: {_num(ep.peak)} packets to {dst} in {self.window}s ({ratio})",
            details)


# ------------------------------------------------------------- DDOS-006
class ErrorRateSpike(SlidingWindowRule):
    """>= error_ratio of requests to a protected server are 5xx, with >= min_requests."""
    RULE_ID = "DDOS-006"

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.errors = defaultdict(int)

    def group(self, e):
        dst = get_ip(e, "resp_h")
        return dst if dst in self.protected else None

    def tag(self, e):
        try:
            return 500 <= int(e.get("status_code")) <= 599
        except (TypeError, ValueError):
            return False

    def on_add(self, key, item):
        self.errors[key] += item[4]

    def on_remove(self, key, item):
        self.errors[key] -= item[4]

    def qualifies(self, key, ts):
        n, err = self.total[key], self.errors[key]
        ok = n >= self.cfg["min_requests"] and err / n >= self.cfg["error_ratio"]
        return ok, err, {"requests": int(n), "ratio": err / n if n else 0}

    def alert(self, dst, ep):
        pct = round(100 * ep.peak_info.get("ratio", 0))
        n = ep.peak_info.get("requests", 0)
        details = self.base_details(
            dst, ep, f">= {round(100 * self.cfg['error_ratio'])}% 5xx with "
                     f">= {self.cfg['min_requests']} requests in {self.window}s")
        details["peak_requests"] = n
        return self._alert(
            ep, RULES[self.RULE_ID]["severity"][0], ep.top_source(),
            f"{RULES[self.RULE_ID]['name']}: {pct}% of {n} requests to {dst} returned 5xx "
            f"in {self.window}s",
            details)


# ------------------------------------------------------------- DDOS-008
class SlowAttack(SlidingWindowRule):
    """>= threshold long-lived (>= min_duration s) or never-closed connections to one
    protected server in the window, from <= max_sources IPs."""
    RULE_ID = "DDOS-008"

    def group(self, e):
        dst = get_ip(e, "resp_h")
        if dst not in self.protected:
            return None
        try:
            long_lived = float(e.get("duration") or 0) >= self.cfg["min_duration"]
        except (TypeError, ValueError):
            long_lived = False
        if long_lived or e.get("conn_state") in self.cfg["open_states"]:
            return dst
        return None

    def qualifies(self, key, ts):
        n = self.total[key]
        return (n >= self.cfg["threshold"] and len(self.srcs[key]) <= self.cfg["max_sources"],
                n, {})

    def alert(self, dst, ep):
        thr, ms = self.cfg["threshold"], self.cfg["max_sources"]
        n_src = ep.peak_info.get("distinct_sources", len(ep.sources))
        return self._alert(
            ep, RULES[self.RULE_ID]["severity"][0], ep.top_source(),
            f"{RULES[self.RULE_ID]['name']}: {_num(ep.peak)} long-lived/unclosed connections "
            f"to {dst} from {n_src} source(s) in {self.window}s",
            self.base_details(
                dst, ep, f">= {thr} connections lasting >= {self.cfg['min_duration']}s or "
                         f"never closed, from <= {ms} IPs in {self.window}s"))


# ------------------------------------------------------------- DDOS-007
class TrafficSpike:
    """Requests per minute to a protected server exceed the previous history_minutes'
    average + std_devs standard deviations, are >= min_requests, and at least
    min_history_minutes of history exist (minutes with no traffic count as 0)."""
    RULE_ID = "DDOS-007"

    def __init__(self, cfg, protected, global_cfg):
        self.cfg = cfg
        self.bucket = cfg["window_seconds"]
        self.protected = protected
        self.max_uids = global_cfg["max_uids"]
        self.first_bucket = None
        # Minute being counted per destination, as [bucket, count, sources, uids, first ts]
        self.current = {}
        # Finished minutes per destination, as {bucket: count}
        self.history = defaultdict(dict)
        # Episode in progress per destination
        self.active = {}
        self.alerts = []

    def process(self, e, ts):
        b = int(ts // self.bucket)
        if self.first_bucket is None:
            self.first_bucket = b
        dst = get_ip(e, "resp_h")
        if dst not in self.protected:
            return
        cur = self.current.get(dst)
        if cur is not None and cur[0] != b:
            self._finish(dst, cur)
            cur = None
        if cur is None:
            cur = self.current[dst] = [b, 0, Counter(), [], ts]
        cur[1] += 1
        cur[2][get_ip(e, "orig_h")] += 1
        if e.get("uid"):
            cur[3].append(e["uid"])

    def _finish(self, dst, cur):
        b, count, srcs, uids, first_ts = cur
        hist_range = range(max(self.first_bucket, b - self.cfg["history_minutes"]), b)
        fire, mean, std = False, 0.0, 0.0
        if len(hist_range) >= self.cfg["min_history_minutes"]:
            vals = [self.history[dst].get(i, 0) for i in hist_range]
            mean = sum(vals) / len(vals)
            std = math.sqrt(sum((v - mean) ** 2 for v in vals) / len(vals))
            fire = count >= self.cfg["min_requests"] and count > mean + self.cfg["std_devs"] * std
        hist = self.history[dst]
        hist[b] = count
        for old in [k for k in hist if k < b - self.cfg["history_minutes"]]:
            del hist[old]

        ep = self.active.get(dst)
        if ep is not None and not (fire and b == ep.last_bucket + 1):
            self.alerts.append(self._alert(dst, self.active.pop(dst)))
            ep = None
        if not fire:
            return
        start = b * self.bucket
        if ep is None:
            ep = self.active[dst] = Episode(first_ts)
        ep.last_bucket = b
        for u in uids:
            ep.add(first_ts, None, u)
        ep.end = start + self.bucket
        ep.sources.update(srcs)
        if count > ep.peak:
            ep.peak, ep.peak_ts = count, start
            ep.peak_info = {"mean": mean, "std": std}

    def flush(self):
        for dst, cur in list(self.current.items()):
            self._finish(dst, cur)
        self.current.clear()
        for dst in list(self.active):
            self.alerts.append(self._alert(dst, self.active.pop(dst)))

    def _alert(self, dst, ep):
        mean, std = ep.peak_info["mean"], ep.peak_info["std"]
        k = self.cfg["std_devs"]
        details = {
            "dst_ip": dst,
            "matched_pattern": f"requests/min > previous {self.cfg['history_minutes']} min "
                               f"average + {k} std devs and >= {self.cfg['min_requests']}",
            "window_seconds": self.bucket,
            "peak_count": ep.peak,
            "peak_time": iso_utc(ep.peak_ts),
            "baseline_mean": round(mean, 1),
            "baseline_std": round(std, 1),
            "episode_start": iso_utc(ep.start),
            "episode_end": iso_utc(ep.end),
            "distinct_sources": len(ep.sources),
            "top_sources": ep.top_sources(),
        }
        return make_alert(
            self.RULE_ID, RULES[self.RULE_ID]["severity"][0], ep.start, ep.top_source(),
            ep.uids,
            f"{RULES[self.RULE_ID]['name']}: {ep.peak} requests/min to {dst} "
            f"(baseline {mean:.0f} +/- {std:.0f})",
            details, self.max_uids)


RULE_CLASSES = {
    "DDOS-001": SingleSourceFlood,
    "DDOS-002": DistributedFlood,
    "DDOS-003": SynFlood,
    "DDOS-004": UriHammering,
    "DDOS-005": UdpIcmpFlood,
    "DDOS-006": ErrorRateSpike,
    "DDOS-007": TrafficSpike,
    "DDOS-008": SlowAttack,
}


# ------------------------------------------------------- main entry point
def run_ddos_rules(http_events=None, conn_events=None, config=None, on_alert=None):
    """Runs every enabled DDoS rule. http_events feed DDOS-001/002/004/006/007,
    conn_events feed DDOS-003/005/008; either may be None. Returns alerts sorted by
    timestamp; on_alert(alert) is called for each one in that order."""
    cfg = load_config(config)
    protected = ProtectedServers(cfg["protected_servers"])
    streams = {"http": http_events or [], "conn": conn_events or []}
    alerts = []
    for log in ("http", "conn"):
        rules = [RULE_CLASSES[r](cfg[r], protected, cfg) for r in cfg["enabled_rules"]
                 if r in RULE_CLASSES and RULES[r]["log"] == log]
        if not rules:
            continue
        timed = [(t, e) for e in streams[log] if (t := event_time(e)) is not None]
        timed.sort(key=lambda p: p[0])
        for ts, e in timed:
            for rule in rules:
                rule.process(e, ts)
        for rule in rules:
            rule.flush()
            alerts.extend(rule.alerts)
    alerts.sort(key=lambda a: (a["timestamp"], a["rule_id"]))
    if on_alert is not None:
        for a in alerts:
            on_alert(a)
    return alerts


def read_events(path):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def parse_with_log_parser(path, required_fields):
    """Runs log_parsing/log_parser.py on `path` and returns the parsed events."""
    # tempfile: log_parser.py writes to a file, so give it a temporary folder
    # that is deleted afterwards. Only needed here, so it is imported here.
    import tempfile

    # log_parser: the team's parser; the real pipeline runs every log through it first
    sys.path.insert(0, os.path.join(REPO, "log_parsing"))
    from log_parser import parseLog

    with tempfile.TemporaryDirectory() as tmp:
        parsed = os.path.join(tmp, "parsed.jsonl")
        with contextlib.redirect_stdout(io.StringIO()):
            parseLog(path, parsed, required_fields)
        return list(read_events(parsed))


def detect(http_log=None, conn_log=None, config=None, on_alert=None):
    """Parses Zeek http.log / conn.log with log_parser.py, then runs the DDoS rules."""
    http_events = parse_with_log_parser(http_log, HTTP_REQUIRED_FIELDS) if http_log else None
    conn_events = parse_with_log_parser(conn_log, CONN_REQUIRED_FIELDS) if conn_log else None
    return run_ddos_rules(http_events, conn_events, config, on_alert)
