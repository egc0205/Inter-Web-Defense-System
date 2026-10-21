import json
from datetime import datetime, timezone

def parseLog(inFile, outFile, reqFields):
    parsed = []

    # Read from JSON to parse
    with open(inFile, "r", encoding="utf-8") as in_file:
        for lineNum, line in enumerate(in_file, start=1):
            line = line.strip()

            # Skipping empty lines
            if not line:
                continue

            # Check for valid JSON before loading  
            try: 
                event = json.loads(line)
            except json.JSONDecodeError:
                print(f"Invalid JSON on line {lineNum}")
                continue

            # Check for missing fields
            if not all(field in event for field in reqFields):
                print(f"Missing fields on line {lineNum}")
                continue

            # Convert the ts to a date and time
            if "ts" in event:
                try: 
                    timestamp = float(event.pop("ts"))
                    event["date and time (utc)"] = datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d %I:%M:%S %p")
                except (ValueError, TypeError, OverflowError, OSError):
                    print(f"Invalid timestamp on line {lineNum}")
                    continue

            parsed.append(event)

    # Write to new JSON
    with open(outFile, "w", encoding="utf-8") as out_file:
        for event in parsed:
            out_file.write(json.dumps(event) + "\n")
            
    print(f"Successfully processed {len(parsed)} events to {outFile}")
