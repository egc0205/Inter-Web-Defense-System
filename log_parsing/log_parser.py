import json
from datetime import datetime, timezone

def parseLog(inFile, outFile, reqFields):
    parsed = []

    with open(inFile, "r", encoding="utf-8") as in_file:
        for lineNum, line in enumerate(in_file, start=1):
            line = line.strip()

            if not line:
                continue
 
            try: 
                event = json.loads(line)
            except json.JSONDecodeError:
                print(f"Invalid JSON on line {lineNum}")
                continue

            if not all(field in event for field in reqFields):
                print(f"Missing fields on line {lineNum}")
                continue

            if "ts" in event:
                try: 
                    timestamp = float(event.pop("ts"))
                    event["date and time (utc)"] = datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d %I:%M:%S %p")
                except (ValueError, TypeError, OverflowError, OSError):
                    print(f"Invalid timestamp on line {lineNum}")
                    continue

            parsed.append(event)

    with open(outFile, "w", encoding="utf-8") as out_file:
        for event in parsed:
            out_file.write(json.dumps(event) + "\n")
            
    print(f"Successfully processed {len(parsed)} events to {outFile}")