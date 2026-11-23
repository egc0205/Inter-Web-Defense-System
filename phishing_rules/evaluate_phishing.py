# Evaluate phishing detections against the email answer key.
# Run python phishing_rules/evaluate_phishing.py from root

import argparse
import csv
import json
import os
import time
from collections import Counter
from pathlib import Path

from phishing_detector import detect

HERE = Path(__file__).resolve().parent
REPO = HERE.parent

DEFAULT_LOG = REPO / "sample_logs" / "email" / "emails.jsonl"
DEFAULT_TRUTH = REPO / "sample_logs" / "email" / "ground_truth.csv"
DEFAULT_OUT = HERE / "output" / "evaluation"

def load_ground_truth(path):

    labels = {}

    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):

            email_id = str(row["email_id"]).strip()
            label = row["label"].strip().lower()
            
            if email_id in labels:
                raise ValueError(f"Duplicate ground-truth email_id: {email_id}")
            if label not in ("phishing", "benign"):
                raise ValueError(f"Unexpected ground-truth label for {email_id}: {label}")
            
            labels[email_id] = label
    
    return labels


def safe_ratio(top, bottom):
    return top / bottom if bottom else 0.0


def evaluate(log_path, truth_path):

    # Run detection before reading labels: ground truth never influences alerts.
    start = time.perf_counter()
    alerts, processed = detect(log_path)
    elapsed = time.perf_counter() - start
    truth = load_ground_truth(truth_path)

    all_ids = set(truth)
    flagged_ids = {str(alert["key"]) for alert in alerts}
    unlabeled = flagged_ids - all_ids
    
    if unlabeled:
        raise ValueError(f"Alerts refer to {len(unlabeled)} unknown email_id(s): {sorted(unlabeled)[:5]}")
    if processed != len(truth):
        raise ValueError(f"Processed {processed} events but found {len(truth)} ground-truth labels")

    positives = {email_id for email_id, label in truth.items() if label == "phishing"}
    negatives = all_ids - positives
    
    tp = len(flagged_ids & positives)
    fp = len(flagged_ids & negatives)
    fn = len(positives - flagged_ids)
    tn = len(negatives - flagged_ids)
    
    precision = safe_ratio(tp, tp + fp)
    recall = safe_ratio(tp, tp + fn)
    
    metrics = {
        "total_emails": processed,
        "actual_phishing": len(positives),
        "actual_benign": len(negatives),
        "alerts": len(alerts),
        "unique_flagged_emails": len(flagged_ids),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision,
        "recall": recall,
        "accuracy": safe_ratio(tp + tn, len(truth)),
        "f1": safe_ratio(2 * precision * recall, precision + recall),
        "elapsed_seconds": elapsed,
        "emails_per_second": safe_ratio(processed, elapsed),
    }

    by_rule = Counter(alert["rule_id"] for alert in alerts)
    by_rule_ids = {}
    
    for alert in alerts:
        by_rule_ids.setdefault(alert["rule_id"], set()).add(str(alert["key"]))
    
    per_rule = []
    
    for rule_id in sorted(by_rule):
        ids = by_rule_ids[rule_id]
        per_rule.append({"rule_id": rule_id, "alerts": by_rule[rule_id],
                         "unique_emails": len(ids),
                         "phishing_emails": len(ids & positives),
                         "benign_emails": len(ids & negatives)})
    
    return metrics, per_rule, alerts, flagged_ids, truth


def save_results(path, metrics, per_rule, alerts, flagged_ids, truth):
    
    path.mkdir(parents=True, exist_ok=True)
    
    with (path / "phishing_metrics.json").open("w", encoding="utf-8") as f:
        json.dump({"summary": metrics, "by_rule": per_rule}, f, indent=2)

    with (path / "phishing_alerts_test.jsonl").open("w", encoding="utf-8") as f:
        for alert in alerts:
            f.write(json.dumps(alert, ensure_ascii=False) + "\n")

    with (path / "phishing_rule_counts.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["rule_id", "alerts", "unique_emails",
                                                    "phishing_emails", "benign_emails"])
        writer.writeheader()
        writer.writerows(per_rule)

    # One row per email: useful for checking individual false positives and misses.
    with (path / "phishing_classifications.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["email_id", "ground_truth", "predicted", "outcome"])
        for email_id, label in sorted(truth.items(), key=lambda item: int(item[0])):
            flagged = email_id in flagged_ids
            outcome = ("TP" if label == "phishing" else "FP") if flagged else ("FN" if label == "phishing" else "TN")
            writer.writerow([email_id, label, "phishing" if flagged else "benign", outcome])

def main():

    ap = argparse.ArgumentParser(description="Evaluate phishing rule accuracy using ground truth")
    
    ap.add_argument("--log", type=Path, default=DEFAULT_LOG)
    ap.add_argument("--truth", type=Path, default=DEFAULT_TRUTH)
    ap.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    
    args = ap.parse_args()

    metrics, by_rule, alerts, flagged_ids, truth = evaluate(args.log, args.truth)
    save_results(args.out_dir, metrics, by_rule, alerts, flagged_ids, truth)

    print(f"Emails: {metrics['total_emails']} ({metrics['actual_phishing']} phishing, {metrics['actual_benign']} benign)")
    print(f"Rule alerts: {metrics['alerts']} | Unique emails flagged: {metrics['unique_flagged_emails']}")
    print(f"TP: {metrics['tp']} | FP: {metrics['fp']} | FN: {metrics['fn']} | TN: {metrics['tn']}")
    print(f"Precision: {metrics['precision']:.1%} | Recall: {metrics['recall']:.1%} | Accuracy: {metrics['accuracy']:.1%} | F1: {metrics['f1']:.1%}")
    print(f"Elapsed: {metrics['elapsed_seconds']:.2f}s | Rate: {metrics['emails_per_second']:.0f} emails/s")
    print("Rule breakdown:")
    
    for row in by_rule:
        print(f"  {row['rule_id']}: {row['alerts']:3} alerts, {row['phishing_emails']:3} phishing emails, {row['benign_emails']:3} benign emails")
    
    print(f"Saved results to {args.out_dir}")

if __name__ == "__main__":
    main()