import asyncio
import contextlib
import csv
import io
import os
import sys

sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from cases import BENIGN_URIS, DATASET_PAYLOADS, EVASION_CASES
from detector import InjectionDetector, detect, match_rules, read_events, run_injection_rules
from normalize import normalize
from rules import CAMPAIGN_RULE, REQUIRED_FIELDS, RULES

SAMPLE_LOGS = os.path.join(REPO, "sample_logs")
WEB_LOG = os.path.join(SAMPLE_LOGS, "web_attacks", "zeek", "http.log")
WEB_TRUTH = os.path.join(SAMPLE_LOGS, "web_attacks", "ground_truth.csv")
ALERT_FIELDS = ["alert_id", "rule_id", "attack_type", "severity", "timestamp", "key",
                "evidence_count", "message", "response_codes", "details"]
SEVERITIES = {"Low", "Medium", "High", "Critical"}

results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""))


def fired(uri):
    return {rule["id"] for rule, _ in match_rules(uri)}


def event(uri, ts=1000.0, src="10.0.0.9", uid="C1"):
    return {"ts": ts, "uid": uid, "id.orig_h": src, "id.resp_h": "10.0.0.1", "uri": uri}


def test_normalize():
    check("normalize decodes + and %XX", normalize("/a?id=1%27+OR+1%3D1") == "/a?id=1' or 1=1")
    check("normalize undoes double encoding", normalize("%253Cscript%253E") == "<script>")
    check("normalize removes SQL inline comments", "union select" in normalize("UNION/**/SELECT"))
    check("normalize handles empty input", normalize("") == "" and normalize(None) == "")


def test_rule_catalog():
    ids = [r["id"] for r in RULES] + [CAMPAIGN_RULE["id"]]
    check("rule ids are unique", len(ids) == len(set(ids)), f"{len(ids)} rules")
    check("every severity is a known level",
          all(r["severity"] in SEVERITIES for r in RULES + [CAMPAIGN_RULE]))


def test_payloads():
    bad = [(u, sorted(exp - fired(u))) for u, exp in DATASET_PAYLOADS if not exp <= fired(u)]
    check("dataset payloads fire the expected rules", not bad,
          f"{len(DATASET_PAYLOADS) - len(bad)}/{len(DATASET_PAYLOADS)}")
    bad = [(u, r) for u, r in EVASION_CASES if r not in fired(u)]
    check("encoded / obfuscated variants are caught", not bad,
          f"{len(EVASION_CASES) - len(bad)}/{len(EVASION_CASES)}" + (f", missed {bad}" if bad else ""))
    bad = [u for u in BENIGN_URIS if fired(u)]
    check("benign URIs raise no alerts", not bad,
          f"{len(BENIGN_URIS) - len(bad)}/{len(BENIGN_URIS)}" + (f", flagged {bad}" if bad else ""))


def test_input_contract():
    missing_ok = True
    for field in ["uri", "id.orig_h", "uid", "ts"]:
        e = event("/x?id=1'+union+select+1")
        del e[field]
        missing_ok &= InjectionDetector().process(e) == []
    check("events missing a required field are skipped", missing_ok)
    e = {"date and time (utc)": "2017-07-06 01:40:07 PM", "uid": "C1",
         "id.orig_h": "1.2.3.4", "uri": "/x?q=<script>"}
    a = InjectionDetector().process(e)
    check("log_parser time string is used when ts is absent",
          bool(a) and a[0]["timestamp"] == "2017-07-06T13:40:07Z")


def test_alert_format():
    a = InjectionDetector().process(event("/x?id=1'+union+select+1", ts=1499348407.4, src="172.16.0.1"))[0]
    check("alert has every agreed field", all(f in a for f in ALERT_FIELDS))
    check("alert timestamp is ISO-8601 UTC", a["timestamp"] == "2017-07-06T13:40:07Z")
    check("alert key is the source IP", a["key"] == "172.16.0.1")
    check("alert details carry evidence",
          {"uid", "dst_ip", "uri", "matched_pattern"} <= set(a["details"]))
    ids = {x["alert_id"] for x in run_injection_rules([event("/x?q=<script>", ts=i, uid=f"C{i}")
                                                       for i in range(20)])}
    check("alert_id is unique per alert", len(ids) >= 20)


def test_campaign():
    det = InjectionDetector(window=60, min_hits=5, min_distinct=3)
    alerts = []
    for i in range(10):
        alerts += det.process(event("/x?id=1'+or+1=1--+", ts=1000 + i, uid=f"C{i}"))
    check("INJ-009 fires once per source per window",
          sum(a["rule_id"] == "INJ-009" for a in alerts) == 1)
    det = InjectionDetector(window=60, min_hits=5, min_distinct=3)
    quiet = []
    for i in range(4):
        quiet += det.process(event("/x?q=<b>x</b>", ts=1000 + i * 100, uid=f"Q{i}"))
        quiet += det.process(event("/x?id=1'", ts=1000 + i * 100, uid=f"R{i}"))
    check("INJ-009 stays quiet when hits are spread out",
          not any(a["rule_id"] == "INJ-009" for a in quiet))


def test_entry_point():
    sent = []
    events = [event("/x?q=<script>", ts=2), event("/ok", ts=1), event("/x?id=1'+union+select+1", ts=3)]
    alerts = run_injection_rules(events, on_alert=sent.append)
    check("on_alert receives every alert as it is created", sent == alerts and len(alerts) > 0)
    check("alerts are emitted in time order",
          [a["timestamp"] for a in alerts] == sorted(a["timestamp"] for a in alerts))


def test_sample_logs():
    with open(WEB_TRUTH, newline="", encoding="utf-8") as f:
        truth = {r["uid"].strip(): r["label"].strip() for r in csv.DictReader(f)}
    events = list(read_events(WEB_LOG))
    alerts = run_injection_rules(events)
    sqli = {u for u, l in truth.items() if l == "Web Attack Sql Injection"}
    caught = {a["details"]["uid"] for a in alerts if a["attack_type"] == "sql_injection"}
    check("web_attacks: every SQL injection connection detected",
          sqli <= caught, f"{len(sqli & caught)}/{len(sqli)}")
    benign = {e["uid"] for e in events if truth.get(e["uid"]) == "BENIGN"}
    flagged = {a["details"]["uid"] for a in alerts}
    check("web_attacks: no benign connection flagged", not (benign & flagged),
          f"0/{len(benign)}" if not (benign & flagged) else f"{len(benign & flagged)} flagged")
    check("web_attacks: every alert is keyed on the attacker",
          {a["key"] for a in alerts} == {"172.16.0.1"})
    with contextlib.redirect_stdout(io.StringIO()):
        parsed = detect(WEB_LOG)
    check("web_attacks: log_parser path gives the same alerts",
          len(parsed) == len(alerts), f"{len(parsed)} vs {len(alerts)}")
    sys.path.insert(0, os.path.join(REPO, "log_parsing"))
    import tempfile
    from log_parser import RULES as PARSER_RULES, parse_log
    fields = PARSER_RULES["injection"][0][2]
    check("log_parser's injection field list covers every required field",
          set(REQUIRED_FIELDS) <= set(fields), ", ".join(sorted(set(REQUIRED_FIELDS) - set(fields))))
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "web_attacks_parsed.jsonl")
        with contextlib.redirect_stdout(io.StringIO()):
            parse_log(WEB_LOG, out, fields, True)
        from_folder = run_injection_rules(read_events(out))
    check("web_attacks: parsed_logs output gives the same alerts",
          len(from_folder) == len(alerts), f"{len(from_folder)} vs {len(alerts)}")
    for name in sorted(os.listdir(SAMPLE_LOGS)):
        path = os.path.join(SAMPLE_LOGS, name, "zeek", "http.log")
        if name == "web_attacks" or not os.path.exists(path):
            continue
        n = len(run_injection_rules(read_events(path)))
        check(f"{name}: no injection alerts on attack-free HTTP traffic", n == 0, f"{n} alerts")
    return alerts


def test_automated_response(alerts):
    sys.path.insert(0, os.path.join(REPO, "automated_response"))
    try:
        from automated_response import PLAYBOOKS, run_automated_response
    except (ImportError, SyntaxError) as exc:
        check("automated_response.py loads", False, f"{type(exc).__name__}: {exc}")
        return
    codes = {c for r in RULES + [CAMPAIGN_RULE] for c in r["response_codes"]}
    missing = sorted(codes - set(PLAYBOOKS))
    check("every response code exists in PLAYBOOKS", not missing, ", ".join(missing))
    sample = {}
    for a in alerts:
        sample.setdefault(a["rule_id"], a)
    loop = asyncio.new_event_loop()
    ok = 0
    with contextlib.redirect_stdout(io.StringIO()):
        for a in sample.values():
            result = loop.run_until_complete(run_automated_response(a))
            ok += bool(result.get("success"))
    loop.close()
    check("run_automated_response succeeds for one alert of every rule",
          ok == len(sample), f"{ok}/{len(sample)}")


def main():
    test_normalize()
    test_rule_catalog()
    test_payloads()
    test_input_contract()
    test_alert_format()
    test_campaign()
    test_entry_point()
    alerts = test_sample_logs()
    test_automated_response(alerts)
    passed = sum(results)
    print(f"\n{passed}/{len(results)} checks passed")
    print("ALL PASSED" if passed == len(results) else "SOME CHECKS FAILED")
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
