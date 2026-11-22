import argparse
import csv
import json
import os
import sys
import time
from collections import Counter

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from detector import InjectionDetector, read_events, run_injection_rules
from rules import RULES
from cases import EVASION_CASES, BENIGN_URIS
from urllib.parse import urlsplit, parse_qsl

SAMPLE_LOGS = os.path.join(REPO, "sample_logs")
OUTPUT_DIR = os.path.join(HERE, "output")
CLASSES = {"sql_injection": "Web Attack Sql Injection", "xss": "Web Attack XSS"}
SURICATA_TERMS = ("sql", "xss", "cross site", "cross-site", "<script", "injection", "union select")


def load_truth(path):
    with open(path, newline="", encoding="utf-8") as f:
        return {r["uid"].strip(): r["label"].strip() for r in csv.DictReader(f)}


def flagged_by_type(alerts):
    flagged = {t: set() for t in CLASSES}
    for a in alerts:
        flagged.setdefault(a["attack_type"], set()).add(a["details"]["uid"])
    return flagged


def score(pred, actual):
    tp, fp, fn = len(pred & actual), len(pred - actual), len(actual - pred)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": prec, "recall": rec, "f1": f1}


def raw_match(uri):
    text = (uri or "").lower()
    return [r for r in RULES if any(p.search(text) for p in r["compiled"])]


def suricata_injection_alerts(path):
    if not os.path.exists(path):
        return None, 0
    total, hits = 0, 0
    with open(path, encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            total += 1
            sig = json.loads(line).get("alert", {}).get("signature", "").lower()
            if any(t in sig for t in SURICATA_TERMS):
                hits += 1
    return total, hits


def accuracy_section(events, truth, alerts):
    http = {}
    for e in events:
        http.setdefault(e.get("uid"), []).append(e.get("uri", ""))
    benign = {u for u in http if truth.get(u) == "BENIGN"}
    flagged = flagged_by_type(alerts)
    rows = {}
    print(f"Connections with HTTP records: {len(http)} (benign: {len(benign)})\n")
    print(f"{'Class':<15}{'TP':>5}{'FP':>5}{'FN':>5}{'Precision':>11}{'Recall':>9}{'F1':>7}")
    for atype, label in CLASSES.items():
        actual = {u for u in http if truth.get(u) == label}
        s = score(flagged[atype], actual)
        rows[atype] = s
        print(f"{atype:<15}{s['tp']:>5}{s['fp']:>5}{s['fn']:>5}"
              f"{s['precision']:>11.2%}{s['recall']:>9.2%}{s['f1']:>7.2f}")
        for u in sorted(flagged[atype] - actual):
            print(f"   FP {u} labeled '{truth.get(u)}': {http[u][0][:90]}")
        missed = actual - flagged[atype]
        no_query = [u for u in missed if not any("?" in x for x in http[u])]
        if missed:
            print(f"   {len(no_query)} of {len(missed)} missed connection(s) have no query string")
    all_flagged = set().union(*flagged.values())
    benign_fp = len(all_flagged & benign)
    print(f"\nBenign connections falsely flagged: {benign_fp} of {len(benign)}")
    return rows, benign_fp, len(benign)


def has_payload(uri):
    query = urlsplit(uri or "").query
    return any(v.strip() for _, v in parse_qsl(query, keep_blank_values=True))


def ablation_section(events, truth):
    print("\nNormalization ablation:")
    print(f"{'Input set':<32}{'Total':>7}{'Normalized':>12}{'Raw URI':>9}")
    rows = {}
    for atype, label in CLASSES.items():
        reqs = [e["uri"] for e in events if truth.get(e.get("uid")) == label and has_payload(e.get("uri"))]
        norm = sum(1 for u in reqs if InjectionDetector().process(
            {"uri": u, "uid": "x", "id.orig_h": "x", "ts": 0}))
        raw = sum(1 for u in reqs if raw_match(u))
        rows[f"dataset_{atype}"] = {"total": len(reqs), "normalized": norm, "raw": raw}
        print(f"{'dataset ' + atype + ' requests':<32}{len(reqs):>7}{norm:>12}{raw:>9}")
    uris = [u for u, _ in EVASION_CASES]
    norm = sum(1 for u in uris if InjectionDetector().process({"uri": u, "uid": "x", "id.orig_h": "x", "ts": 0}))
    raw = sum(1 for u in uris if raw_match(u))
    rows["evasion_corpus"] = {"total": len(uris), "normalized": norm, "raw": raw}
    print(f"{'evasion corpus (encoded)':<32}{len(uris):>7}{norm:>12}{raw:>9}")
    norm_fp = sum(1 for u in BENIGN_URIS if InjectionDetector().process({"uri": u, "uid": "x", "id.orig_h": "x", "ts": 0}))
    raw_fp = sum(1 for u in BENIGN_URIS if raw_match(u))
    rows["benign_corpus"] = {"total": len(BENIGN_URIS), "normalized": norm_fp, "raw": raw_fp}
    print(f"{'benign corpus (should be 0)':<32}{len(BENIGN_URIS):>7}{norm_fp:>12}{raw_fp:>9}")
    return rows


def cross_dataset_section(config):
    print("\nFalse-positive check on datasets with no injection attacks:")
    rows = {}
    for name in sorted(os.listdir(SAMPLE_LOGS)):
        path = os.path.join(SAMPLE_LOGS, name, "zeek", "http.log")
        if name == "web_attacks" or not os.path.exists(path):
            continue
        events = list(read_events(path))
        alerts = run_injection_rules(events, config)
        rows[name] = {"events": len(events), "alerts": len(alerts)}
        print(f"  {name:<16}{len(events):>7} events  {len(alerts):>4} alerts")
    return rows


def throughput_section(events, config, runs):
    best = None
    for _ in range(runs):
        start = time.perf_counter()
        run_injection_rules(events, config)
        elapsed = time.perf_counter() - start
        best = elapsed if best is None else min(best, elapsed)
    rate = len(events) / best if best else 0.0
    print(f"\nThroughput: {len(events)} events in {best:.3f} s ({rate:,.0f} events/s, best of {runs})")
    return {"events": len(events), "seconds": best, "events_per_second": rate}


def main():
    ap = argparse.ArgumentParser(description="Accuracy, comparison and performance of the injection rules")
    ap.add_argument("--dataset", default="web_attacks")
    ap.add_argument("--config", default=os.path.join(HERE, "config.json"))
    ap.add_argument("--runs", type=int, default=3)
    args = ap.parse_args()

    base = os.path.join(SAMPLE_LOGS, args.dataset)
    log = os.path.join(base, "zeek", "http.log")
    truth_path = os.path.join(base, "ground_truth.csv")
    for p in (log, truth_path):
        if not os.path.exists(p):
            sys.exit(f"Missing file: {p}")
    config = {}
    if os.path.exists(args.config):
        with open(args.config, encoding="utf-8") as f:
            config = json.load(f)

    truth = load_truth(truth_path)
    events = list(read_events(log))
    alerts = run_injection_rules(events, config)

    print(f"Dataset: {args.dataset} ({len(events)} HTTP events, {len(alerts)} alerts)")
    print("Alerts by rule: " + ", ".join(f"{k}={v}" for k, v in
                                          sorted(Counter(a['rule_id'] for a in alerts).items())))
    print("Alerts by source: " + ", ".join(f"{k}={v}" for k, v in
                                            Counter(a['key'] for a in alerts).most_common()) + "\n")

    accuracy, benign_fp, benign_total = accuracy_section(events, truth, alerts)
    ablation = ablation_section(events, truth)

    total, sur_hits = suricata_injection_alerts(os.path.join(base, "suricata_alerts.json"))
    ours = sum(1 for a in alerts if a["attack_type"] in CLASSES)
    if total is not None:
        print(f"\nBaseline comparison: Suricata raised {total} alerts, {sur_hits} for SQLi/XSS; "
              f"injection rules raised {ours} SQLi/XSS alerts")

    cross = cross_dataset_section(config)
    perf = throughput_section(events, config, args.runs)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    out = os.path.join(OUTPUT_DIR, "evaluation.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump({
            "dataset": args.dataset,
            "events": len(events),
            "alerts": len(alerts),
            "alerts_by_rule": dict(Counter(a["rule_id"] for a in alerts)),
            "accuracy": accuracy,
            "benign_false_positives": benign_fp,
            "benign_connections": benign_total,
            "normalization_ablation": ablation,
            "suricata": {"total_alerts": total, "injection_alerts": sur_hits},
            "injection_rule_alerts": ours,
            "cross_dataset": cross,
            "throughput": perf,
        }, f, indent=2)
    print(f"\nResults written to {out}")


if __name__ == "__main__":
    main()
