"""
Evaluation of the DDoS rules: reproduces the DDoS numbers in Section 6 of the report.

    python ddos_rules/evaluate_ddos.py

What it measures:

  1. Accuracy on the ddos sample, checked against ground_truth.csv
     (alerts, attack connections caught, benign connections flagged, time to detection)

  2. Comparison with Suricata on the same traffic, using sample_logs/ddos/suricata_alerts.json
     (alert count, DDoS signatures, and how many attack connections its alerts touch)

  3. Alerts on the other samples, which have no DDoS traffic

  4. The protected-server filter: false alerts with and without it

  5. Processing speed (median of several runs)

Results are printed and saved to ddos_rules/output/evaluation.json.
"""

# argparse: reads the command-line options (--runs)
import argparse

# csv: reads ground_truth.csv, the answer key for the sample logs
import csv

# json: reads the Suricata alerts and writes evaluation.json
import json

# os: builds file paths that work on Windows, Mac and Linux
import os

# statistics: median run time for the speed test
import statistics

# sys: lets us import ddos_detector.py from this folder
import sys

# time: measures how long the rules take to run
import time

# Counter: counts Suricata alerts per signature
from collections import Counter

# Don't leave __pycache__ in other team folders
sys.dont_write_bytecode = True

# Make ddos_detector.py importable no matter where this is run from
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# ddos_detector: the DDoS rules being evaluated
import ddos_detector as dd  # noqa: E402


LOGS = os.path.join(dd.REPO, "sample_logs")
OUTPUT_DIR = os.path.join(HERE, "output")
ATTACKER = "172.16.0.1"

# Words that would mark a Suricata signature as a DDoS / flood detection
DDOS_TERMS = ("ddos", "dos ", "flood", "loic", "hoic", "slowloris", "syn flood")


# ----------------------------------------------------------------- helpers

def load(folder):
    """Reads http.log and conn.log from a sample_logs folder."""
    zeek = os.path.join(LOGS, folder, "zeek")
    http = list(dd.read_events(os.path.join(zeek, "http.log")))
    conn = list(dd.read_events(os.path.join(zeek, "conn.log")))
    return http, conn


def load_truth(folder):
    """uid -> label from a sample's ground_truth.csv."""
    with open(os.path.join(LOGS, folder, "ground_truth.csv"), newline="",
              encoding="utf-8") as f:
        return {r["uid"].strip(): r["label"].strip() for r in csv.DictReader(f)}


def pct(n, d):
    return round(100 * n / d, 2) if d else 0.0


# ----------------------------------------------------------- 1. accuracy

def accuracy_section(http, conn, truth):
    alerts = dd.run_ddos_rules(http, conn)
    attack = {u for u, label in truth.items() if label == "DDoS"}
    benign = {u for u, label in truth.items() if label == "BENIGN"}

    # Every connection listed as evidence in any alert counts as flagged
    flagged = {u for a in alerts for u in a["details"]["uids"]} & set(truth)
    tp, fp = len(flagged & attack), len(flagged & benign)
    fn = len(attack - flagged)

    # Time from the first attack request to the moment each rule's condition first held
    start = min(float(e["ts"]) for e in http if e.get("id.orig_h") == ATTACKER)
    cfg = dd.load_config()
    servers = dd.ProtectedServers(cfg["protected_servers"])
    first = {}
    for cls, events in ((dd.SingleSourceFlood, http), (dd.SynFlood, conn)):
        rule = cls(cfg[cls.RULE_ID], servers, cfg)
        for e in sorted(events, key=lambda x: float(x["ts"])):
            rule.process(e, float(e["ts"]))
            if rule.active:
                first[cls.RULE_ID] = round(float(e["ts"]) - start, 1)
                break

    return {
        "alerts": [{"rule_id": a["rule_id"], "severity": a["severity"], "key": a["key"],
                    "evidence_count": a["evidence_count"], "message": a["message"]}
                   for a in alerts],
        "attack_connections": len(attack),
        "benign_connections": len(benign),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision_pct": pct(tp, tp + fp),
        "recall_pct": pct(tp, tp + fn),
        "false_positive_rate_pct": pct(fp, len(benign)),
        "seconds_to_first_detection": first,
    }


# ------------------------------------------------- 2. Suricata comparison

def suricata_section(conn, truth):
    path = os.path.join(LOGS, "ddos", "suricata_alerts.json")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        records = [json.loads(line) for line in f if line.strip()]
    alerts = [r for r in records if r.get("event_type") == "alert"]
    signatures = Counter(a["alert"]["signature"] for a in alerts)
    ddos_sigs = {s: n for s, n in signatures.items()
                 if any(t in s.lower() for t in DDOS_TERMS)}

    # Suricata alerts have no Zeek uid, so match them to Zeek connections by
    # source IP/port and destination IP/port, in either direction
    by_tuple = {(e["id.orig_h"], e["id.orig_p"], e["id.resp_h"], e["id.resp_p"]): e["uid"]
                for e in conn}
    touched = set()
    for a in alerts:
        fwd = (a.get("src_ip"), a.get("src_port"), a.get("dest_ip"), a.get("dest_port"))
        rev = (a.get("dest_ip"), a.get("dest_port"), a.get("src_ip"), a.get("src_port"))
        for key in (fwd, rev):
            if key in by_tuple:
                touched.add(by_tuple[key])

    attack = {u for u, label in truth.items() if label == "DDoS"}
    benign = {u for u, label in truth.items() if label == "BENIGN"}
    return {
        "suricata_alerts": len(alerts),
        "ddos_signature_alerts": sum(ddos_sigs.values()),
        "ddos_signatures": ddos_sigs,
        "top_signatures": dict(signatures.most_common(10)),
        "attack_connections_touched": len(touched & attack),
        "benign_connections_touched": len(touched & benign),
    }


# ---------------------------------------------------- 3. other samples

def other_samples_section():
    out = {}
    for folder in ("web_attacks", "portscan", "header_spoofing"):
        http, conn = load(folder)
        alerts = dd.run_ddos_rules(http, conn)
        out[folder] = {"events": len(http) + len(conn),
                       "alerts": len(alerts),
                       "rules": sorted({a["rule_id"] for a in alerts})}
    return out


# ------------------------------------------ 4. protected-server filter

def filter_section():
    """False alerts (alerts not keyed on the attacker) with and without the filter."""
    everything = {"protected_servers": ["0.0.0.0/0"]}
    out = {}
    for folder in ("ddos", "portscan", "web_attacks"):
        http, conn = load(folder)
        with_filter = dd.run_ddos_rules(http, conn)
        without = dd.run_ddos_rules(http, conn, everything)
        out[folder] = {
            "false_alerts_with_filter": sum(a["key"] != ATTACKER for a in with_filter),
            "false_alerts_without_filter": sum(a["key"] != ATTACKER for a in without),
        }
    return out


# ---------------------------------------------------------- 5. speed

def speed_section(http, conn, runs):
    # One warm-up run, then time the rest
    dd.run_ddos_rules(http, conn)
    times = []
    for _ in range(runs):
        t = time.perf_counter()
        dd.run_ddos_rules(http, conn)
        times.append(time.perf_counter() - t)
    events = len(http) + len(conn)
    median = statistics.median(times)
    return {"events": events, "runs": runs, "median_seconds": round(median, 3),
            "events_per_second": round(events / median)}


# ------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description="Accuracy, Suricata comparison and speed "
                                             "of the DDoS rules")
    ap.add_argument("--runs", type=int, default=9, help="timed runs for the speed test")
    args = ap.parse_args()

    http, conn = load("ddos")
    truth = load_truth("ddos")

    results = {
        "accuracy": accuracy_section(http, conn, truth),
        "suricata": suricata_section(conn, truth),
        "other_samples": other_samples_section(),
        "protected_server_filter": filter_section(),
        "speed": speed_section(http, conn, args.runs),
    }

    acc, suri = results["accuracy"], results["suricata"]
    print("== Accuracy on the ddos sample")
    for a in acc["alerts"]:
        print(f"   {a['rule_id']}  {a['severity']:<6}  {a['key']}  {a['message']}")
    print(f"   Attack connections caught: {acc['true_positives']:,} of "
          f"{acc['attack_connections']:,} (recall {acc['recall_pct']}%, "
          f"precision {acc['precision_pct']}%)")
    print(f"   Benign connections flagged: {acc['false_positives']} of "
          f"{acc['benign_connections']:,} ({acc['false_positive_rate_pct']}%)")
    print(f"   Seconds from first attack request to detection: "
          f"{acc['seconds_to_first_detection']}")

    if suri:
        print("\n== Suricata (ET Open rules) on the same traffic")
        print(f"   Alerts: {suri['suricata_alerts']}, DDoS/flood signatures: "
              f"{suri['ddos_signature_alerts']}")
        print(f"   Attack connections its alerts touch: "
              f"{suri['attack_connections_touched']:,} of {acc['attack_connections']:,} "
              f"(benign touched: {suri['benign_connections_touched']})")
        print("   Most common signatures:")
        for sig, n in suri["top_signatures"].items():
            print(f"     {n:5}  {sig}")
    else:
        print("\n== Suricata: sample_logs/ddos/suricata_alerts.json not found, skipped")

    print("\n== Samples without DDoS")
    for folder, r in results["other_samples"].items():
        rules = ", ".join(r["rules"]) or "-"
        print(f"   {folder:<16} {r['events']:>6,} events -> {r['alerts']} alerts ({rules})")

    print("\n== Protected-server filter (alerts not on the attacker)")
    for folder, r in results["protected_server_filter"].items():
        print(f"   {folder:<12} with filter: {r['false_alerts_with_filter']}   "
              f"without: {r['false_alerts_without_filter']}")

    sp = results["speed"]
    print(f"\n== Speed: {sp['events']:,} events in {sp['median_seconds']} s "
          f"(median of {sp['runs']}) -> {sp['events_per_second']:,} events/s")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out = os.path.join(OUTPUT_DIR, "evaluation.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved {out}")


if __name__ == "__main__":
    main()
