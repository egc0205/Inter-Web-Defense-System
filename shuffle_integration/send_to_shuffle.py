# Sends a log file to the Shuffle workflow's webhook.
#Refer to read me for instructions
import argparse
import json
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument("--url", required=True, help="Shuffle webhook URI")
parser.add_argument("--type", required=True, choices=["arp", "dns", "http", "ddos", "injection", "phishing"])
parser.add_argument("--log", required=True, help="main log (ddos: the http.log, phishing: the emails.jsonl)")
parser.add_argument("--conn-log", help="ddos only: the Zeek conn.log")
parser.add_argument("--max-events", type=int, default=0, help="only send the first N events of each log (0 = all)")
args = parser.parse_args()


# Read the log file, skipping lines that aren't valid json
def load(path):
    events = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
            if args.max_events and len(events) >= args.max_events:
                break
    return events


events = load(args.log)
#always send conn_events, which is usually empty of ddos, so $exec.conn_events in the workflow can be found
body = {"log_type": args.type, "events": events, "conn_events": []}
if args.conn_log:
    body["conn_events"] = load(args.conn_log)

request = urllib.request.Request(args.url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}, method="POST")
with urllib.request.urlopen(request, timeout=30) as response:
    print(response.status, response.read().decode())

if args.conn_log:
    print(f"sent {len(events)} events + {len(body['conn_events'])} conn events")
else:
    print(f"sent {len(events)} events")
