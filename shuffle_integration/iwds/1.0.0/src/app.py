#shuffle app for the Inter-Web-Defense-System (IWDS)
import asyncio
import concurrent.futures
import contextlib
import importlib
import io
import json
import os
import sys
import tempfile

from shuffle_sdk import AppBase

#where shuffle mounts our repo inside the container
REPO = "/iwds_repo"

sys.dont_write_bytecode = True

# which folder/module/config to use for each log type
SPECS = {
    "arp": {"dir": "spoofing_rules", "module": "arp_spoofing_rules","config": "spoofing_rules/arp_config.json"},
    "dns": {"dir": "spoofing_rules", "module": "dns_spoofing_rules", "config": "spoofing_rules/dns_config.json"},
    "http": {"dir": "spoofing_rules", "module": "http_header_rules","config": "spoofing_rules/config.json"},
    "ddos": {"dir": "ddos_rules", "module": "ddos_detector","config": "ddos_rules/config.json"},
    "injection": {"dir": "injection_rules", "module": "detector", "config": None},
    "phishing": {"dir": "phishing_rules", "module": "phishing_detector", "config": None},
}

# Shuffle changes dots in json keys to underscores (for examplem, id.orig_h would be id_orig_h)
# So we change the zeek ones back before the log parser grabs them
ZEEK_FIELDS = {
    "id_orig_h": "id.orig_h",
    "id_orig_p": "id.orig_p",
    "id_resp_h": "id.resp_h",
    "id_resp_p": "id.resp_p",
}


def load_module(folder, module_name):
    if not os.path.isdir(os.path.join(REPO, "automated_response")):
        raise ImportError(f"repo not found at {REPO}. (see shuffle_integration/README.md, this one comes up a lot at the start) and restart it")
    #the detectors import the log parser so these folders need to be on the path
    for d in ("log_parsing", "automated_response", folder):
        sys.path.insert(0, os.path.join(REPO, d))
    return importlib.import_module(module_name)


def load_config(log_type):
    rel = SPECS[log_type]["config"]
    if not rel:
        return {}
    path = os.path.join(REPO, *rel.split("/"))
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# Turns alerts back into the dict (shuffle passes them as strings)
def to_dict(value):
    if isinstance(value, dict):
        return value
    loaded = json.loads(value.strip())
    #  Looped values sometimes come in as a list with one item
    if isinstance(loaded, list) and len(loaded) == 1:
        loaded = loaded[0]
    return loaded

#RThe events come in as a list (or a json array string).
# Our detectors read files with one json event per line, so turn it into that.
def to_log_text(value):
    if not value:
        return None
    if isinstance(value, str):
        value = json.loads(value)
    lines = []
    for event in value:
        event = {ZEEK_FIELDS.get(k, k): v for k, v in event.items()}
        lines.append(json.dumps(event))
    return "\n".join(lines)

#The response functions are async, so run them in their own thread
#mainly for future planning
#Also note, this function did use claude to help make it, mainly just to find functions we needed and to research the right way to handle the async
def run_async(coro):
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()

def capture(fn, *args):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        result = fn(*args)
    lines = [line for line in buf.getvalue().splitlines() if line.strip()]
    return result, lines

#Got help with claude for structure purposes and actually understanding
#How to make this app actually work with Shuffle (hardest part, required like 5 hours with claude to actually understand how it works)
#Essentially had claude generate a template, used it to help define my own template that acutally implements our repo's functions

class IWDS(AppBase):
    __version__ = "1.0.0"
    app_name = "iwds"

    def __init__(self, redis, logger, console_logger=None):
        super().__init__(redis, logger, console_logger)

    def detect(self, log_type, log_data, log_data_2=""):
        log_type = (log_type or "").strip().lower()
        if log_type not in SPECS:
            return {"success": False, "error": f"unknown log_type '{log_type}'", "supported": sorted(SPECS)}
        try:
            module = load_module(SPECS[log_type]["dir"], SPECS[log_type]["module"])
            config = load_config(log_type)
        except Exception as e:
            return {"success": False, "error": f"{type(e).__name__}: {e}"}

        main_text = to_log_text(log_data)
        second_text = None
        if log_type == "ddos":
            second_text = to_log_text(log_data_2)
        if not main_text:
            return {"success": False, "error": "log_data is empty"}

        try:
            #The detectors take file paths, so write the events to temp files
            with tempfile.TemporaryDirectory() as tmp:
                main_path = os.path.join(tmp, "main.log")
                with open(main_path, "w", encoding="utf-8") as f:
                    f.write(main_text)
                second_path = None
                if second_text:
                    second_path = os.path.join(tmp, "second.log")
                    with open(second_path, "w", encoding="utf-8") as f:
                        f.write(second_text)

                # Makes sure that each detector actually receives the correct arguments. 
                if log_type == "ddos":
                    result, parser_output = capture(module.detect, main_path, second_path, config, None)
                elif log_type == "injection":
                    result, parser_output = capture(module.detect, main_path, config, None)
                elif log_type == "phishing":
                    result, parser_output = capture(module.detect, main_path, None)
                else:
                    result, parser_output = capture(module.detect, main_path, config)
        except Exception as e:
            return {"success": False, "log_type": log_type, "error": f"{type(e).__name__}: {e}"}

        if log_type == "phishing":
            alerts = result[0]
        else:
            alerts = result
        return {"success": True, "log_type": log_type, "count": len(alerts), "alerts": alerts, "parser_output": parser_output}

    def respond(self, alert):
        alert = to_dict(alert)
        ar = load_module("automated_response", "automated_response")
        #all the response logic is in automated_response.py, we just run it and show what it printed
        result, output = capture(run_async, ar.run_automated_response(alert))
        result["output"] = output
        return result


if __name__ == "__main__":
    IWDS.run()
