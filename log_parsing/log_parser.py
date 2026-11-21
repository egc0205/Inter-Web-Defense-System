import json
import os
import sys

# This parsing function goes through logs and takes the fields that are needed for our rules to work. I added sort_ts as a parameter 
# since our email logs didn't need to be sorted by the ts. Our rules need the missing fields to not be dropped, so the parser replaces
# them with none if they are missing. 
def parse_log(in_path, out_path, req_fields, sort_ts):
    parsed = []

    with open(in_path, "r", encoding = "utf-8") as in_file:
        for line_num, line in enumerate(in_file, start = 1):
            line = line.strip()

            if not line:
                continue
  
            try: 
                event = json.loads(line)
            except json.JSONDecodeError:
                print(f"Invalid JSON on line {line_num}")
                continue

            if not isinstance(event, dict):
                print(f"{line_num} is not a JSON object")
                continue

            missing = [field for field in req_fields if field not in event]
            
            if missing:
                for field in missing:
                    event[field] = None

            parsed.append(event)

    if sort_ts:
            parsed.sort(key = lambda x: x["ts"])

    with open(out_path, "w", encoding = "utf-8") as out_file:
        for event in parsed:
            out_file.write(json.dumps(event) + "\n")

FOLDERS = {
    "web_attacks": "sample_logs/web_attacks/zeek",
    "header_spoofing": "sample_logs/header_spoofing/zeek",
    "header_spoofing_synthetic": "sample_logs/header_spoofing/header_spoofing_synthetic/zeek",
    "arp_spoofing": "sample_logs/arp_spoofing",
    "ddos": "sample_logs/ddos/zeek",
    "phishing": "sample_logs/email"
}

# Required fields for each rule
HTTP_INJECTION = ["ts", "uid", "id.orig_h", "uri", "id.resp_h", "host", "method", "user_agent", "status_code"]
HTTP_SPOOFING = ["ts", "uid", "id.orig_h", "uri", "id.resp_h", "host", "method", "user_agent", "origin", "status_code", "x_forwarded_for", "x_real_ip", "forwarded"]
CONN_SPOOFING = ["ts", "uid", "id.orig_h", "id.resp_h", "proto", "conn_state", "history", "orig_pkts", "resp_pkts", "id.orig_p", "id.resp_p"]
DNS_SPOOFING = ["ts", "uid", "id.orig_h", "id.resp_h", "query", "answers", "qtype_name", "rcode_name", "TTLs"]
ARP_SPOOFING = ["ts", "src_mac", "dst_mac","operation", "sender_mac", "sender_ip", "target_mac", "target_ip"]
PHISHING = ["email_id", "subject", "body", "from", "from_domain", "urls", "url_domains", "ts", "from_name", "spf", "dkim", "dmarc", "reply_to", "return_path_domain", "attachments", "message_id"]
HTTP_DDOS = ["ts", "uid", "id.orig_h", "id.resp_h"]
CONN_DDOS = ["ts", "uid", "id.orig_h", "id.resp_h", "proto"]

# Dictionary for the rules, each has a log folder, log type, required fields, and sort by ts or not
RULES = {
    "injection": [("web_attacks", "http.log", HTTP_INJECTION, True)],
    "spoofing": [("header_spoofing", "http.log", HTTP_SPOOFING, True),
                 ("header_spoofing", "conn.log", CONN_SPOOFING, True),
                 ("header_spoofing_synthetic", "http.log", HTTP_SPOOFING, True),
                 ("arp_spoofing", "arp.log", ARP_SPOOFING, False)],
    "phishing": [("phishing", "emails.jsonl", PHISHING, False)],
    "ddos": [("ddos", "http.log", HTTP_DDOS, True),
             ("ddos", "conn.log", CONN_DDOS, True)]
}


# This function is in charge of parsing the right logs for each detection rule. It looks this up in the RULES dictionary, and then it finds each log's
# folder in the FOLDERS dictionary. It then sends that information to parse_log. The parsed logs are placed in a parsed_logs folder under the corresponding
# rule type, that way our rules can easily access the logs they need.
def parse_rule(rule_name, repo_dir, out_root):
    out_dir = os.path.join(out_root, rule_name)
    os.makedirs(out_dir, exist_ok=True)

    for key, file_name, fields, sort_ts in RULES[rule_name]:
        in_path = os.path.join(repo_dir, *FOLDERS[key].split("/"), file_name)

        if not os.path.exists(in_path):
            print(f"Input file {in_path} not found, skipping")
            continue

        log_type = os.path.splitext(file_name)[0]
        out_dir = os.path.join(out_root, rule_name, log_type)
        os.makedirs(out_dir, exist_ok=True)
        out_name = key + "_parsed.jsonl"
        print(f"{rule_name}, parsing {in_path} to {out_dir}")
        
        parse_log(in_path, os.path.join(out_dir, out_name), fields, sort_ts)
        
if __name__ == "__main__":
    parser_dir = os.path.dirname(os.path.abspath(__file__))
    repo_dir = os.path.dirname(parser_dir)
    out_root = os.path.join(parser_dir, "parsed_logs")

    selected_rules = sys.argv[1:] or list(RULES)
    unknown_rules = [rule for rule in selected_rules if rule not in RULES]
    
    if unknown_rules:
        print(f"Unknown rule/rules: {', '.join(unknown_rules)}. Current rules are: {', '.join(RULES)}")
        sys.exit(1)

    for rule in selected_rules:
        parse_rule(rule, repo_dir, out_root)
    