# Injection Detection Rules

Detects **SQL injection**, **cross-site scripting (XSS)** and **command injection / path traversal** in Zeek `http.log` events, escalates repeated attacks from one source, and hands every alert to `automated_response` the moment it is created.

Owner: Onkar Bajwa

## Requirements

| Item | Value |
|---|---|
| OS | Windows, macOS or Linux |
| Language | Python 3.10 or newer |
| Dependencies | None. Python standard library only |
| Input data | `sample_logs/<dataset>/zeek/http.log` (JSON lines) |

## Commands

Run from the repository root.

```bash
python log_parsing/log_parser.py injection                      # writes log_parsing/parsed_logs/injection/http/
python injection_rules/run_injection.py                         # reads that parsed log, with automated response
python injection_rules/run_injection.py --dataset ddos          # parse and scan any folder under sample_logs/
python injection_rules/run_injection.py path/to/http.log        # your own Zeek http.log
python injection_rules/run_injection.py --no-respond --show 1   # detection only, print the first alert
python injection_rules/test_injection_rules.py                  # 31 checks, exit code 1 on failure
python injection_rules/evaluate.py                              # accuracy, comparison and throughput
```

| Option | Meaning |
|---|---|
| `log` | Zeek `http.log` to scan (overrides `--dataset`) |
| `--dataset NAME` | Folder under `sample_logs/` to parse and scan |
| `--config FILE` | Threshold file (default `injection_rules/config.json`) |
| `--no-respond` | Detect only; do not call `automated_response` |
| `--no-parse` | Skip `log_parsing/log_parser.py` and read the log directly |
| `--out FILE` | Where to write alerts (default `injection_rules/output/injection_alerts.jsonl`) |
| `--show N` | Print the first N alerts in full |

Generated files go to `injection_rules/output/` (ignored by git):

| File | Contents |
|---|---|
| `injection_alerts.jsonl` | One alert per line |
| `responses.jsonl` | One `run_automated_response` result per alert |
| `response_console.log` | Messages printed by `automated_response` |
| `evaluation.json` | Results from `evaluate.py` |

## Pipeline

```
http.log -> log_parser.parse_log -> parsed_logs/injection/http/ -> run_injection_rules -> alert -> run_automated_response
```

With no log or `--dataset` given, `run_injection.py` reads `log_parsing/parsed_logs/injection/http/web_attacks_parsed.jsonl`. If that file does not exist yet it parses `sample_logs/web_attacks` itself. The Shuffle `iwds` app calls `detect()` for `--type injection`.

1. **Parse.** `log_parser.py injection` (or `detect()`) runs `parse_log` with the injection field list and sorts events by `ts`.
2. **Order.** Events are sorted by time so the campaign window sees them in sequence.
3. **Validate.** Events without `uri`, `id.orig_h`, `uid` or a timestamp are skipped.
4. **Normalize.** The URI is URL-decoded up to three times, lowercased, SQL `/**/` comments become spaces and whitespace is collapsed. `id=1%27+UnIoN/**/SeLeCt` becomes `id=1' union select`.
5. **Match.** Each rule's regular expressions are tested against the normalized URI. A rule fires at most once per request.
6. **Alert.** One alert is created per rule that fires.
7. **Correlate.** Each hit joins a per-source 60-second window. At 5 or more hits, or 3 or more distinct rules, a Critical `INJ-009` alert is raised, at most once per source per window.
8. **Respond.** Each alert is passed to `run_automated_response(alert)` as soon as it exists. A response that raises an exception is recorded with `"status": "error"` and the run continues.

Other modules call the same entry point:

```python
from detector import run_injection_rules
alerts = run_injection_rules(events, config, on_alert)
```

## Input (from the log parser)

| Field | Required | Used for |
|---|---|---|
| `uri` | Yes | Contains the payload; kept undecoded until `normalize.py` |
| `id.orig_h` | Yes | Source IP; becomes the alert `key` |
| `uid` | Yes | Links the event to `conn.log` and `ground_truth.csv` |
| `ts` | Yes | Event order and the campaign window. The parser's `date and time (utc)` string is used if `ts` was removed |
| `id.resp_h`, `method`, `status_code`, `host`, `user_agent` | No | Copied into `details` as evidence |

## Output (to automated response)

```json
{
  "alert_id": "51c52ebce187",
  "rule_id": "INJ-006",
  "attack_type": "xss",
  "severity": "High",
  "timestamp": "2017-07-06T13:16:18Z",
  "key": "172.16.0.1",
  "evidence_count": 1,
  "message": "XSS script tag from 172.16.0.1",
  "response_codes": ["BLOCK_IP"],
  "details": {"uid": "CdhVKYTq5V5S9pZ21", "dst_ip": "192.168.10.50", "uri": "...",
              "method": "GET", "status_code": 200, "host": "205.174.165.68",
              "user_agent": "...", "matched_pattern": "<\\s*/?\\s*script"}
}
```

Every `severity` is one of `Low`, `Medium`, `High`, `Critical`, and every response code exists in `PLAYBOOKS` in `automated_response.py`.

## Rules

| ID | Detects | Example | Severity | Response codes |
|---|---|---|---|---|
| INJ-001 | SQLi tautology / quote break | `' or 1=1`, `id=1'` | Medium | OPEN_TICKET |
| INJ-002 | SQLi UNION query | `union select` | High | BLOCK_IP |
| INJ-003 | SQLi schema / data enumeration | `information_schema`, `database()`, `from users` | High | BLOCK_IP, NOTIFY_ONCALL |
| INJ-004 | SQLi comment truncation | `' and 1=1#` | Medium | OPEN_TICKET |
| INJ-005 | SQLi time-based blind | `sleep(5)`, `waitfor delay` | High | BLOCK_IP |
| INJ-006 | XSS script tag | `<script>` | High | BLOCK_IP |
| INJ-007 | XSS event handler / `javascript:` URI | `onerror=`, `<svg onload=` | High | BLOCK_IP |
| INJ-008 | XSS cookie / session theft | `document.cookie` | Critical | BLOCK_IP, REVOKE_SESSION |
| INJ-009 | Injection campaign from one source | 5 hits or 3 rules in 60 s | Critical | BLOCK_IP, NOTIFY_ONCALL |
| INJ-010 | Command injection / path traversal | `;cat /etc/passwd`, `../../` | High | BLOCK_IP |

Campaign thresholds are set in `config.json`.

## Files

| File | Purpose |
|---|---|
| `normalize.py` | URI decoding and cleanup |
| `rules.py` | Rule catalog, default thresholds, required fields |
| `detector.py` | `InjectionDetector`, `run_injection_rules()`, `detect()`, `load_parsed_logs()`, `read_events()` |
| `run_injection.py` | Command-line pipeline |
| `config.json` | INJ-009 thresholds |
| `cases.py` | Known attack, evasion and benign URIs shared by the tests and evaluation |
| `test_injection_rules.py` | 31 automated checks |
| `evaluate.py` | Accuracy, normalization ablation, Suricata comparison, false-positive check on other datasets, throughput |

## Results on `sample_logs`

| Measure | Result |
|---|---|
| web_attacks HTTP events scanned | 11,946 |
| Alerts raised | 1,844, all keyed on the attacker 172.16.0.1 |
| SQL injection connections | 12 of 12 detected (precision 92.3%, recall 100%) |
| XSS connections with a payload | 18 of 18 detected (precision 100%) |
| Benign web_attacks connections flagged | 0 of 1,315 |
| Alerts on ddos, portscan, header_spoofing HTTP (17,577 events) | 0 |
| Encoded / obfuscated variants detected | 18 of 18 with normalization, 6 of 18 without |
| Suricata SQLi/XSS alerts on the same traffic | 0 |
| Alerts accepted by `automated_response` | 1,844 of 1,844 |
| Test checks | 31 of 31 pass |

The one SQL injection false positive is a genuine `id=1'` request inside a connection the dataset labels XSS (labels are per connection). Of the 11 XSS connections not flagged, 10 contain no query string (page and asset loads) and the 11th is that same SQL injection connection.

## Limitations

- Only the request URI is inspected. Zeek does not log POST bodies, cookies or most headers, so payloads sent there are not seen.
- Signature rules detect known patterns. A new encoding or syntax not covered by `normalize.py` or `rules.py` can evade them.
- 608 of the 637 XSS-labelled connections in `web_attacks` have no HTTP record, so they cannot be evaluated.
- INJ-005, INJ-007 and INJ-010 have no matching attacks in the sample data; they are verified with the synthetic cases in `cases.py`.
- Every alert is sent to `automated_response`; repeated alerts from one attack are not merged before response.
- The source IP is taken from the log and can be spoofed or shared behind NAT.
