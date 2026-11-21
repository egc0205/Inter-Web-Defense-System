# Inter-Web Defense System (IWDS)

IWDS is a set of rule-based detectors (ARP, DNS, HTTP, DDoS, injection and phishing) with an automated-response playbook. This README covers the requirements, how to run the rules on their own, and how to wire the whole pipeline into [Shuffle](https://github.com/Shuffle/Shuffle) for automated detection and response.

## Contents

- [Disclaimer](#disclaimer)
- [Requirements](#requirements)
- [Installation and running](#installation-and-running)
  - [Before you start](#before-you-start)
  - [Part 1. Check the IWDS code runs on its own](#part-1-check-the-iwds-code-runs-on-its-own)
  - [Part 2. Install and start Shuffle](#part-2-install-and-start-shuffle)
  - [Part 3. Connect the repo to Shuffle](#part-3-connect-the-repo-to-shuffle)
  - [Part 4. Install the iwds app](#part-4-install-the-iwds-app)
  - [Part 5. Build the workflow](#part-5-build-the-workflow)
  - [Part 6. Send logs](#part-6-send-logs)
  - [Part 7. Check the results in Shuffle](#part-7-check-the-results-in-shuffle)
- [Troubleshooting](#troubleshooting)
- [Next steps](#next-steps)

---

## Disclaimer

Avoided using generative AI throughout the process, but a lot of the issues that came up with Docker were not very well documented online in forums. Utilized Claude to help troubleshoot issues as they came up and help come up with code revisions where something wasn't working. As a result, I also used Claude to help format the steps to boot the project, but most importantly, a troubleshooting section at the bottom in case you come across the same... large.. quantity of issues I came across while integrating the app with Shuffle.

---

## Requirements

**Operating system:** Any Windows, Linux, or Mac installation works for the IWDS code. The Shuffle setup guide below is written for **Windows (PowerShell + Docker Desktop)**.

**Programming language:** An up-to-date Python installation (3.10 or newer).

**Software and dependencies:**

- Python 3.10+, on PATH. No Python packages need installing: the IWDS code and the sender script only use the standard library.
- Docker Desktop (WSL 2 backend) with Docker Compose, for running Shuffle.
- Node.js and npm (carried over from the original requirements; the steps below don't use them).
- Roughly 4–8 GB of free memory for Shuffle.

---

## Installation and running

### Before you start

You need these three things. Run each check in PowerShell; if one fails, install that tool before continuing.

| Requirement | Check | Expected |
|---|---|---|
| **This repo**, pulled with git | `cd C:\path\to\Inter-Web-Defense-System` then `git status` | `On branch main` (no error) |
| **Python 3.10 or newer**, on PATH | `python --version` | `Python 3.10` or higher |
| **Docker Desktop**, running (WSL 2 backend) | `docker version` | A `Client` **and** a `Server` section |

Also check `docker compose version` prints a version.

Notes:

- No Python packages need installing: the IWDS code and the sender script only use the standard library.
- Docker Desktop must be **running** (bottom-left says *Engine running*) whenever you use Shuffle. After a restart,
  start Docker Desktop first.
- Shuffle needs roughly 4–8 GB of free memory.

---

### Part 1. Check the IWDS code runs on its own

Before involving Shuffle, check the repo works with plain Python. Go to the repo folder
(**change this** to where you pulled it):

```powershell
cd C:\path\to\Inter-Web-Defense-System
```

Run the DNS rules on the sample DNS log:

```powershell
python spoofing_rules\dns_spoofing_rules.py spoofing_rules\dns_synthetic.log
```

SUCCESS: The output ends with `5 alert(s)` followed by the responses, and `5/5 responses succeeded`.

If this fails, fix it before going further: Shuffle runs exactly this code.

---

### Part 2. Install and start Shuffle

1. Pick a folder for Shuffle. **A path without spaces is safest**, e.g. `C:\Shuffle`. Download Shuffle there:

   ```powershell
   git clone https://github.com/Shuffle/Shuffle C:\Shuffle
   cd C:\Shuffle
   mkdir shuffle-database, shuffle-apps -Force
   ```

2. Make sure **swarm mode is off**. Open `C:\Shuffle\docker-compose.yml` in a text editor and find
   `SHUFFLE_SWARM_CONFIG`. The line must start with `#`:

   ```yaml
         # - SHUFFLE_SWARM_CONFIG=run
   ```

3. Start Shuffle:

   ```powershell
   cd C:\Shuffle
   docker compose up -d
   ```

   The first start downloads several images (a few minutes).

4. Check that everything is running:

   ```powershell
   docker compose ps
   ```

   SUCCESS: `shuffle-backend`, `shuffle-frontend`, `shuffle-orborus` and `shuffle-opensearch` all show **Up** (or *running*).

   FAILED: If `shuffle-opensearch` keeps restarting, see [Troubleshooting → Shuffle](#shuffle).

5. Wait 1–2 minutes, then open **http://localhost:3001** in your browser and **create the admin account**
   (any username and password). Log in.

---

### Part 3. Connect the repo to Shuffle

This tells Shuffle to mount our repo into the `iwds` app's containers. It's a single line in Shuffle's `.env` file.

1. Set two variables (they only last for this PowerShell window). `$REPO` is filled in from the folder you're in,
   so run this **from the repo folder**; **change `$SHUF`** if Shuffle isn't in `C:\Shuffle`:

   ```powershell
   cd C:\path\to\Inter-Web-Defense-System
   $REPO = (Get-Location).Path
   $SHUF = "C:\Shuffle"
   ```

2. Build the line. Shuffle needs a Linux-style path, so this converts e.g. `C:\PATH\TO\Inter-Web-Defense-System`
   into `/run/desktop/mnt/host/c/PATH/TO/Inter-Web-Defense-System`:

   ```powershell
   $bind = "/run/desktop/mnt/host/" + $REPO.Substring(0,1).ToLower() + ($REPO.Substring(2) -replace '\\','/')
   $line = "SHUFFLE_VOLUME_BINDS=${bind}:/iwds_repo:ro"
   $line
   ```

   SUCCESS: It prints something like
   `SHUFFLE_VOLUME_BINDS=/run/desktop/mnt/host/c/PATH/TO/Inter-Web-Defense-System:/iwds_repo:ro`.

3. Check that `.env` doesn't already have the setting:

   ```powershell
   Select-String -Path "$SHUF\.env" -Pattern "SHUFFLE_VOLUME_BINDS"
   ```

   - **Nothing printed:** add the line:

     ```powershell
     Copy-Item "$SHUF\.env" "$SHUF\.env.bak"
     Add-Content -Path "$SHUF\.env" -Value "`n$line"
     ```

   - **A line was printed:** open `$SHUF\.env` in a text editor and replace that line with the one from step 2.

4. Apply it by recreating Orborus (the Shuffle component that starts containers):

   ```powershell
   cd $SHUF
   docker compose up -d --force-recreate orborus
   ```

What the line means: the part before `:/iwds_repo` is the repo on your PC, `/iwds_repo` is where it appears inside
the app container, and `ro` makes it read-only so Shuffle can't change your files. If you ever move the repo, redo
this part.

---

### Part 4. Install the iwds app

1. Copy the app into Shuffle's app folder and restart the backend (which builds it). **Change the paths** if your
   repo or Shuffle folder is somewhere else:

   ```powershell
   cd C:\path\to\Inter-Web-Defense-System
   Copy-Item shuffle_integration\iwds C:\Shuffle\shuffle-apps -Recurse -Force
   cd C:\Shuffle
   docker compose restart backend
   ```

2. Wait about a minute, then check the build:

   ```powershell
   docker compose logs backend | Select-String "iwds"
   ```

   SUCCESS: A line containing `Successfully built image frikky/shuffle:iwds_1.0.0`.

   FAILED: No such line after 3–4 minutes: see [Troubleshooting → Installing the app](#installing-the-app-part-4).

3. In the Shuffle UI, open **Apps** (left bar), search **`iwds`** (search all apps, not only *My apps*), open it and
   click **Activate** if that button is shown. If not, then don't worry about this step.

---

### Part 5. Build the workflow

1. Go to **Workflows** → **Create workflow** (or the `+` button). Name it `IWDS Pipeline` and open it.

2. **Webhook (the trigger).** In the left panel, open **Triggers** and drag **Webhook** onto the canvas.
   Click it and **copy the URI** shown in its settings. It looks like
   `http://localhost:3001/api/v1/hooks/webhook_1234abcd-....` Keep it somewhere; you'll need it in Part 6.

3. **detect node.** In the left panel's app list, search `iwds` and drag it onto the canvas. Click it and set:

   | Field | Value (type exactly) |
   |---|---|
   | Name (at the top) | `detect` |
   | Action (dropdown) | `detect` |
   | `log_type` | `$exec.log_type` |
   | `log_data` | `$exec.events` |
   | `log_data_2` | `$exec.conn_events` |

4. **respond node.** Drag `iwds` onto the canvas again. Click it and set:

   | Field | Value (type exactly) |
   |---|---|
   | Name | `respond` |
   | Action | `respond` |
   | `alert` | `$detect.alerts.#` |

   The `.#` at the end makes Shuffle run `respond` **once for every alert** that `detect` found.

5. **Connect them.** Drag from the edge of **Webhook** to **detect**, then from **detect** to **respond**, so
   you have `Webhook → detect → respond`.

6. Click **Save** (bottom or `Ctrl+S`).

7. **Start the webhook.** Click the Webhook node and press **Start**. Its status should change to *running*.

The names matter: `respond` reads `$detect.alerts`, which only works if the first node is named exactly `detect`.

---

### Part 6. Send logs

#### 6.1 The sender script

From the repo folder, set the webhook URI once per PowerShell window (**change this** to the URI you copied
in Part 5):

```powershell
cd C:\path\to\Inter-Web-Defense-System
$URL = "http://localhost:3001/api/v1/hooks/webhook_PASTE-YOUR-ID-HERE"
```

Then send a log:

```powershell
python shuffle_integration\send_to_shuffle.py --url $URL --type dns --log spoofing_rules\dns_synthetic.log
```

Options:

| Option | Meaning |
|---|---|
| `--url` | The webhook URI (required) |
| `--type` | Which rules to run: `arp`, `dns`, `http`, `ddos`, `injection` or `phishing` (required) |
| `--log` | The log file (required). For `ddos` this is the Zeek **http.log** |
| `--conn-log` | Only for `ddos`: the Zeek **conn.log** |
| `--max-events N` | Only send the first N events of each file |

Please note: the most important options are `--url`, `--type` and `--log`. You need to provide all of these to actually route it correctly.

#### 6.2 What the output means

```
200 {"success": true, "execution_id": "d42bad08-e325-41e8-b604-b57b08bc4e33"}
sent 9 events
```

| Part | Meaning |
|---|---|
| `200` | Shuffle's webhook received the request |
| `"success": true` | Shuffle started a run of the workflow |
| `"execution_id"` | The ID of that run. It also appears in the names of the containers for that run |
| `sent 9 events` | How many log events were sent |

**This does not tell you what was detected.** The webhook answers as soon as the run starts. The alerts and
responses are in Shuffle: see [Part 7](#part-7-check-the-results-in-shuffle).

---

### Part 7. Check the results in Shuffle

1. Open the workflow (**Workflows** → `IWDS Pipeline`).
2. Open the list of runs (the **runs / executions** icon or tab in the workflow view) and click the newest one.
   It should say **FINISHED** after a few seconds to a minute (longer for more alerts).
3. Click the **detect** node result:

   ```json
   {"success": true, "log_type": "dns", "count": 5,
    "alerts": [ {"rule_id": "DNS-003", "severity": "Medium", "message": "...", "response_codes": [...], ...}, ... ],
    "parser_output": ["Successfully processed 9 events to /tmp/.../parsed.jsonl"]}
   ```

   - `count`: number of alerts
   - `alerts`: the alerts exactly as our rules produced them
   - `parser_output`: what `log_parser.py` printed. If `count` is unexpectedly 0, look here first.

4. Click the **respond** node result. It has one entry per alert:

   ```json
   {"rule_id": "DNS-002", "severity": "High", "key": "192.168.10.17",
    "alert_sent": ["send_alert: [High] DNS-002: ..."],
    "actions": [
      {"code": "BLOCK_IP",      "status": "executed", "output": ["Blocking offending source IPs"]},
      {"code": "NOTIFY_ONCALL", "status": "executed", "output": ["Notifying On Call SOC"]},
      {"code": "OPEN_TICKET",   "status": "executed", "output": ["Opening incident ticket"]}],
    "success": true}
   ```

   - `alert_sent`: what `send_alert()` printed
   - `actions`: one entry per response code, in order. `status` is `executed` or `failed` (with a `reason`)
   - `output`: what that playbook function printed
   - `success`: `true` if every action executed

---

## Troubleshooting

Find the stage where it goes wrong, then the symptom.

### Python

| Symptom | Cause | Fix |
|---|---|---|
| `python` opens the Microsoft Store, or `python is not recognized` | Python isn't on PATH, or Windows' Store shortcut is in the way | Use `py` instead of `python` in every command. Or: Settings → Apps → Advanced app settings → **App execution aliases** → turn off both *python* entries, then reinstall Python with **Add python.exe to PATH** ticked |
| `can't open file ... send_to_shuffle.py` / `No such file or directory` | You're not in the repo folder | `cd C:\path\to\Inter-Web-Defense-System` first |

### Docker

| Symptom | Cause | Fix |
|---|---|---|
| `failed to connect to the docker API at npipe:////./pipe/dockerDesktopLinuxEngine` | Docker Desktop isn't running | Start it, wait for *Engine running* |
| `docker compose` complains about the API version / `client version ... is too new` | Docker client and server versions don't match | Add `DOCKER_API_VERSION=1.44` to `C:\Shuffle\.env`, and to the `environment:` list of `orborus` in `docker-compose.yml` as `- DOCKER_API_VERSION=1.44`. Then `docker compose up -d` |

### Shuffle

| Symptom | Cause | Fix |
|---|---|---|
| http://localhost:3001 doesn't load | Shuffle is still starting, or not running | Wait 2 minutes. Run `docker compose ps` in `C:\Shuffle`; if containers are missing, `docker compose up -d` |
| `shuffle-opensearch` keeps restarting; its log mentions `max virtual memory areas vm.max_map_count` | OpenSearch needs a kernel setting | `wsl -d docker-desktop sysctl -w vm.max_map_count=262144`, then `docker compose restart opensearch backend` (repeat after each PC restart) |
| `shuffle-opensearch` keeps restarting with out-of-memory errors | Not enough memory for Docker | Close other programs. Shuffle needs roughly 4–8 GB free |
| Backend log shows `timeout awaiting response headers` / `Failed saving execution` | OpenSearch is overloaded, often by sample workflows | Delete or disable workflows you don't use; `docker compose restart opensearch backend` |
| Windows Security flags `EICAR_Test_File` in `C:\Shuffle\shuffle-files\` | A Shuffle sample workflow stored the standard antivirus test file | Harmless. Delete the file and the sample workflow that made it |

### Connecting the repo (Part 3)

| Symptom | Cause | Fix |
|---|---|---|
| `detect` returns `repo not found at /iwds_repo` | The mount didn't reach the app container | Check the line: `Select-String -Path "C:\Shuffle\.env" -Pattern "VOLUME_BINDS"`. It must start with `/run/desktop/mnt/host/` (not `C:\`). Then `docker compose up -d --force-recreate orborus` |
| Still `repo not found` after that | The worker rejected the bind | `docker ps -a --filter "name=worker" --format "{{.Names}}"`, then `docker logs <one of those names>` and look for `Appending bind` (good) or `Volume bind ... invalid` (the path is wrong) |

### Installing the app (Part 4)

| Symptom | Cause | Fix |
|---|---|---|
| No `Successfully built image frikky/shuffle:iwds_1.0.0` line | The app wasn't found or failed to build | Check the folder exists: `Test-Path C:\Shuffle\shuffle-apps\iwds\1.0.0\api.yaml` (should print `True`). Then `docker compose logs backend \| Select-String "iwds\|error"` |
| Backend log: `YAML field ... doesn't exist` | `api.yaml` is missing a required field | `name`, `description`, `app_version` and `contact_info.name` must all be present |
| `iwds` doesn't appear in the workflow editor | The app isn't activated | Apps → search all apps for `iwds` → **Activate** |
| Changes to `app.py` don't take effect | Shuffle is still using the old image | Redo Part 4. To force a rebuild: `cd C:\Shuffle\shuffle-apps\iwds\1.0.0; docker build -t frikky/shuffle:iwds_1.0.0 .` |

### Building the workflow (Part 5)

| Symptom | Cause | Fix |
|---|---|---|
| A field shows a dropdown and won't accept `$exec...` | The node came from an older version of the app | Delete the node and drag `iwds` in again |
| A node fails with `unexpected keyword argument` | Same as above: the node still sends a field the app no longer has | Delete the node and add it again |

### Sending logs (Part 6)

| Symptom | Cause | Fix |
|---|---|---|
| `HTTP Error 401: Unauthorized` | Wrong URI (e.g. the placeholder was left in), or the webhook isn't started | Copy the URI from the Webhook node again; press **Start** on it |
| `ConnectionRefusedError` / `WinError 10061` | Shuffle isn't running | Start Docker Desktop; `cd C:\Shuffle; docker compose up -d` |
| `The '<' operator is reserved for future use` | A `<placeholder>` from this guide was pasted literally | Replace it with the real value |
| The request is very slow or times out | Too many events in one request | Use the `small\` sample logs, or `--max-events` |

### Runs in Shuffle (Part 7)

| Symptom | Cause | Fix |
|---|---|---|
| Run stays **EXECUTING** forever | The `iwds` container crashed | `docker ps -a --filter "name=iwds" --format "{{.Names}}"`, then `docker logs <newest name>` shows the Python error |
| Container log: `No module named 'shuffle_sdk'` | The SDK isn't in the image | `shuffle_integration\iwds\1.0.0\requirements.txt` must contain `shuffle_sdk==0.0.40`; redo Part 4 |
| `detect` returns `count: 0` and `parser_output` says `Missing fields on line N` | The events don't have the fields the parser needs: wrong `--type` for that file, or an old `app.py` | Check `--type` matches the log. Redo Part 4 to install the current `app.py` (it undoes Shuffle renaming `id.orig_h` to `id_orig_h`) |
| `detect` returns `count: 0` with no errors | No attacks in what you sent | E.g. `--max-events` cut the log before the attacks. Use the `small\` sample logs |
| `detect` returns `unknown log_type` | The `--type` isn't one of the six, or the node's `log_type` isn't `$exec.log_type` | Check both |
| `respond` never runs | Nodes not connected, or `alert` is wrong | Connect detect → respond; `alert` must be exactly `$detect.alerts.#`; the first node must be named `detect` |
| `respond` shows `failed` / `unknown response code` | A rule produced a code that isn't in `PLAYBOOKS` | Add it to `PLAYBOOKS` in `automated_response.py`, or fix the rule |
| A run takes very long | Many alerts: `respond` starts one container per alert | Use the `small\` sample logs |

---

## Next steps

- Integrate the responses into real functions. For example, hook it up to Gmail to email a person if we need a human response or want to alert the SOC.
- Build out more types of alerts so that we have a wider breadth of protection.