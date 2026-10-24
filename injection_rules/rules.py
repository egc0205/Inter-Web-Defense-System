import re

RULES = [
    {
        "id": "INJ-001",
        "name": "SQLi tautology / quote break",
        "attack_type": "sql_injection",
        "severity": "Medium",
        "response_codes": ["OPEN_TICKET"],
        "patterns": [
            r"'\s*(or|and)\s+('?\w+'?\s*=\s*'?\w+|true|false|\d)",
            r"=\s*[\w-]*'\s*(&|$|#|--)",
        ],
    },
    {
        "id": "INJ-002",
        "name": "SQLi UNION-based",
        "attack_type": "sql_injection",
        "severity": "High",
        "response_codes": ["BLOCK_IP"],
        "patterns": [r"\bunion\s+(all\s+)?select\b"],
    },
    {
        "id": "INJ-003",
        "name": "SQLi schema / data enumeration",
        "attack_type": "sql_injection",
        "severity": "High",
        "response_codes": ["BLOCK_IP", "NOTIFY_ONCALL"],
        "patterns": [
            r"\binformation_schema\b",
            r"\b(database|user|version|schema|current_user)\s*\(\s*\)",
            r"\bselect\b.+\bfrom\s+(users|mysql\.user|pg_shadow|sysobjects)\b",
        ],
    },
    {
        "id": "INJ-004",
        "name": "SQLi comment truncation",
        "attack_type": "sql_injection",
        "severity": "Medium",
        "response_codes": ["OPEN_TICKET"],
        "patterns": [r"'[^&]*?(#|--\s|--$)"],
    },
    {
        "id": "INJ-005",
        "name": "SQLi time-based blind",
        "attack_type": "sql_injection",
        "severity": "High",
        "response_codes": ["BLOCK_IP"],
        "patterns": [r"\b(sleep|benchmark|pg_sleep)\s*\(", r"\bwaitfor\s+delay\b"],
    },
    {
        "id": "INJ-006",
        "name": "XSS script tag",
        "attack_type": "xss",
        "severity": "High",
        "response_codes": ["BLOCK_IP"],
        "patterns": [r"<\s*/?\s*script", r"\bscript\s*>"],
    },
    {
        "id": "INJ-007",
        "name": "XSS event handler / javascript: URI",
        "attack_type": "xss",
        "severity": "High",
        "response_codes": ["BLOCK_IP"],
        "patterns": [
            r"\bon(error|load|mouseover|focus|click|submit|mouseenter)\s*=",
            r"javascript\s*:",
            r"<\s*(img|svg|iframe|body|object|embed)\b[^>]*>",
        ],
    },
    {
        "id": "INJ-008",
        "name": "XSS cookie / session theft",
        "attack_type": "xss",
        "severity": "Critical",
        "response_codes": ["BLOCK_IP", "REVOKE_SESSION"],
        "patterns": [r"document\s*\.\s*(cookie|location|domain)", r"\bwindow\s*\.\s*location\b"],
    },
    {
        "id": "INJ-010",
        "name": "Command injection / path traversal",
        "attack_type": "command_injection",
        "severity": "High",
        "response_codes": ["BLOCK_IP"],
        "patterns": [
            r"(;|\||&&|`|\$\()\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh|ping)(\s|$|`|\))",
            r"(\.\./){2,}",
            r"/etc/(passwd|shadow)\b",
        ],
    },
]

CAMPAIGN_RULE = {
    "id": "INJ-009",
    "name": "Injection campaign",
    "attack_type": "injection_campaign",
    "severity": "Critical",
    "response_codes": ["BLOCK_IP", "NOTIFY_ONCALL"],
}

CAMPAIGN_WINDOW_SECONDS = 60
CAMPAIGN_MIN_HITS = 5
CAMPAIGN_MIN_DISTINCT_RULES = 3

REQUIRED_FIELDS = ["uri", "id.orig_h", "uid", "ts"]
EVIDENCE_FIELDS = ["id.resp_h", "method", "status_code", "host", "user_agent"]

for _rule in RULES:
    _rule["compiled"] = [re.compile(p) for p in _rule["patterns"]]
