import asyncio


# ---- Pipeline ---------------------------------------------------------------
async def run_actions(response_codes, severity):
        #Run each response code's action in order.
        #Returns the list of codes that failed (empty if everything succeeded)
    failed = []
    for code in response_codes:
        action = PLAYBOOKS.get(code)
        if action is None:
            print(f"run_actions: unknown response code {code}, skipping")
            failed.append(code)
            continue
        try:
            await action(severity)
        except Exception as exc:
            print(f"run_actions: {code} failed: {exc}")
            failed.append(code)
    return failed

async def run_automated_response(alert):
       #Entry point: run the full automated response and wait for it to finish.
        #Returns (True, []) if every action succeeded, or (False, [failed codes]).
    await send_alert(alert["rule_id"], alert["severity"], alert["message"])
    failed = await run_actions(alert["response_codes"], alert["severity"])
    return {
        "rule_id": alert["rule_id"],
        "severity": alert["severity"],
        "success": len(failed) == 0,
        "failed_actions": failed,
    }


# ---- Alerting ---------------------------------------------------------------

async def send_alert(rule_id, severity, message):
    print(f"send_alert: [{severity}] {rule_id}: {message}")



# ---- Severity tuning --------------------------------------------------------
# Basically a place to determine how we should respond to something based on severity

RATE_LIMITS = {"Low": 500, "Medium": 200, "High": 100, "Critical": 25}

# ---- Response actions (print only for now) ----------------------------------

async def rate_limit(severity):
    #Severity defaults to medium if theres an error.
    limit = RATE_LIMITS.get(severity, RATE_LIMITS["Medium"])
    print(f"rate_limit: capping each source at {limit} req/s (severity={severity})")

async def open_ticket(severity):
    print("Opening incident ticket")

async def notify_oncall(severity):
    print("Notifying On Call SOC")

async def drop_connections(severity):
    print("Dropping current connections")

async def block_ip(severity):
    print("Blocking offending source IPs")

async def challenge_endpoint(severity):
    print("Enabling captchas to challenge endpoints")

async def enable_syn_cookies(severity):
    print("Enabling SYN cookies to absorb the SYN flood")

async def block_protocol_rate(severity):
    print("Blocking protocol rate")

#Not yet listed yet by any detection rule set, but just wanted to prep since these are common responses. 

async def quarantine_file(severity):
    print("Quarantining malicious file")

async def isolate_host(severity):
    print("Isolating host from the network")

async def disable_account(severity):
    print("Disabling compromised account")

async def revoke_sessions(severity):
    print("Revoking active sessions for the affected account")

async def pull_email(severity):
    print("Pulling malicious email from user mailboxes")
    
# ---- Playbooks: threat type tied to action function ------------------------------

PLAYBOOKS = {
    "ENABLE_RATE_LIMITING": rate_limit,
    "NOTIFY_ONCALL": notify_oncall,
    "DROP_CONNECTIONS": drop_connections,
    "ENABLE_SYN_COOKIES": enable_syn_cookies,
    "CHALLENGE_ENDPOINT": challenge_endpoint,
    "BLOCK_PROTOCOL_RATE": block_protocol_rate,
    "BLOCK_IP": block_ip,
    "OPEN_TICKET": open_ticket,
    "QUARANTINE_FILE": quarantine_file,
    "ISOLATE_HOST": isolate_host,
    "DISABLE_ACCOUNT": disable_account,
    "REVOKE_SESSION": revoke_sessions,
    "PULL_EMAIL": pull_email,
}