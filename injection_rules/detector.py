import contextlib
import io
import json
import os
import sys
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone

from normalize import normalize
from rules import (RULES, CAMPAIGN_RULE, CAMPAIGN_WINDOW_SECONDS, CAMPAIGN_MIN_HITS,
                   CAMPAIGN_MIN_DISTINCT_RULES, REQUIRED_FIELDS)

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
PARSER_TIME_FIELD = "date and time (utc)"
PARSER_TIME_FORMAT = "%Y-%m-%d %I:%M:%S %p"


def event_time(event):
    try:
        return float(event["ts"])
    except (KeyError, TypeError, ValueError):
        pass
    try:
        dt = datetime.strptime(event[PARSER_TIME_FIELD], PARSER_TIME_FORMAT)
        return dt.replace(tzinfo=timezone.utc).timestamp()
    except (KeyError, TypeError, ValueError):
        return None


def iso_utc(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def missing_fields(event):
    missing = [f for f in REQUIRED_FIELDS if f != "ts" and not event.get(f)]
    if event_time(event) is None:
        missing.append("ts")
    return missing


def match_rules(uri):
    clean = normalize(uri)
    hits = []
    for rule in RULES:
        for pattern in rule["compiled"]:
            if pattern.search(clean):
                hits.append((rule, pattern.pattern))
                break
    return hits


def make_alert(rule, src_ip, ts, evidence_count, details):
    return {
        "alert_id": uuid.uuid4().hex[:12],
        "rule_id": rule["id"],
        "attack_type": rule["attack_type"],
        "severity": rule["severity"],
        "timestamp": iso_utc(ts),
        "key": src_ip,
        "evidence_count": evidence_count,
        "message": f"{rule['name']} from {src_ip}",
        "response_codes": list(rule["response_codes"]),
        "details": details,
    }


class InjectionDetector:
    def __init__(self, window=CAMPAIGN_WINDOW_SECONDS, min_hits=CAMPAIGN_MIN_HITS,
                 min_distinct=CAMPAIGN_MIN_DISTINCT_RULES):
        self.window = window
        self.min_hits = min_hits
        self.min_distinct = min_distinct
        self.recent = defaultdict(deque)
        self.last_campaign = {}
        self.stats = {"events": 0, "skipped": 0, "matched_events": 0, "alerts": 0}

    def process(self, event):
        self.stats["events"] += 1
        if missing_fields(event):
            self.stats["skipped"] += 1
            return []
        uri = event["uri"]
        hits = match_rules(uri)
        if not hits:
            return []
        self.stats["matched_events"] += 1
        src = event["id.orig_h"]
        ts = event_time(event)
        details = {
            "uid": event["uid"],
            "dst_ip": event.get("id.resp_h"),
            "uri": uri[:300],
            "method": event.get("method"),
            "status_code": event.get("status_code"),
            "host": event.get("host"),
            "user_agent": event.get("user_agent"),
        }
        alerts = [make_alert(rule, src, ts, 1, {**details, "matched_pattern": pattern})
                  for rule, pattern in hits]
        alerts.extend(self._correlate(src, ts, [r["id"] for r, _ in hits], details))
        self.stats["alerts"] += len(alerts)
        return alerts

    def _correlate(self, src, ts, rule_ids, details):
        queue = self.recent[src]
        for rule_id in rule_ids:
            queue.append((ts, rule_id))
        while queue and ts - queue[0][0] > self.window:
            queue.popleft()
        distinct = {rule_id for _, rule_id in queue}
        if len(queue) < self.min_hits and len(distinct) < self.min_distinct:
            return []
        if ts - self.last_campaign.get(src, float("-inf")) < self.window:
            return []
        self.last_campaign[src] = ts
        campaign_details = {**details, "matched_pattern": "campaign",
                            "rules_seen": sorted(distinct), "window_seconds": self.window}
        return [make_alert(CAMPAIGN_RULE, src, ts, len(queue), campaign_details)]


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


def run_injection_rules(events, config=None, on_alert=None):
    cfg = config or {}
    detector = InjectionDetector(
        cfg.get("campaign_window_seconds", CAMPAIGN_WINDOW_SECONDS),
        cfg.get("campaign_min_hits", CAMPAIGN_MIN_HITS),
        cfg.get("campaign_min_distinct_rules", CAMPAIGN_MIN_DISTINCT_RULES),
    )
    ordered = sorted(events, key=lambda e: event_time(e) or 0)
    alerts = []
    for event in ordered:
        for alert in detector.process(event):
            alerts.append(alert)
            if on_alert is not None:
                on_alert(alert)
    return alerts


def detect(log_path, config=None, on_alert=None):
    import tempfile
    sys.path.insert(0, os.path.join(REPO, "log_parsing"))
    from log_parser import parseLog
    with tempfile.TemporaryDirectory() as tmp:
        parsed = os.path.join(tmp, "parsed.jsonl")
        with contextlib.redirect_stdout(io.StringIO()):
            parseLog(log_path, parsed, REQUIRED_FIELDS)
        return run_injection_rules(list(read_events(parsed)), config, on_alert)
