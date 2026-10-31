# MASTER PROMPT: Kill Chain and Attack Path Analysis Tool (50 GB tier)

Docker Compose is mandatory in this version: build, run, test and measurement all happen in containers.
Copy everything below the line into your AI coding agent (Cursor, Claude Code, etc.).
Before you start, put these in the repo: the 100 MB dev sample (`data/sample/`), the ground-truth file if one was shared (`data/ground_truth/`), and the earlier `rules/detect.yaml` and `tagger.py` if you have them.

---

```text
================================================================================
ROLE AND OPERATING RULES
================================================================================
You are a principal security software engineer and distributed-systems engineer.
Build, test and package a complete tool called "Kill Chain and Attack Path Analysis".
Work autonomously end to end.

Non-negotiable rules:
1. Deliver working, runnable files. No pseudo-code, no TODO stubs, no "left as an exercise".
2. Run and test everything you write. Show real command output and real measured numbers. Never invent metrics.
3. If any target below fails, say so plainly and fix it. Do not hide or round up a failure.
4. Commit after every stage with a clear message and print a one-paragraph status (what works, what was measured).
5. Keep it simple. The whole tool must be buildable and demoable in about 10 hours. Prefer fewer moving parts.
6. Detection, labeling, correlation, path order and risk score are deterministic RULE-BASED code. An LLM must never be on the 50 GB path and never decide labels, path order or risk.
7. DOCKER IS MANDATORY. The tool must build, run, be tested and be measured entirely through Docker Compose. A judge with only Docker installed must be able to run it. Never require a host Python, pip install, or manual setup. Every command you show and every measurement you report must be run INSIDE the containers.

================================================================================
1. PRODUCT GOAL
================================================================================
Read a very large pile of RAW TEXT security logs (Linux auth.log / syslog, firewall and flow lines, Windows-style text events, web logs; NOT JSON), find the attack hidden inside, and show it as one clear story: where the attacker started, what they did, and where they can go next.

Pipeline:
raw logs -> parallel scanner (prefilter + regex + threshold rules) -> partial Parquet files
-> DuckDB alerts table -> sequence rules -> correlation (union-find) -> incidents
-> precomputed path + risk + report per incident -> FastAPI -> static dark web UI

Key design principle: reduce 50 GB to a small alert table ONCE, then do all smart work (correlation, graph, API) on that small data. Everything after the scan must be fast.

================================================================================
2. TARGET TIER AND HARD TARGETS (the "Great" column of the PRD)
================================================================================
Tier: EXTREME, 50 GB uncompressed, multiple files possible, same planted attacks at every tier.

| Metric                    | Must reach                                    |
|---------------------------|-----------------------------------------------|
| Detection                 | > 90% of planted attack steps found           |
| Correct labels            | > 85% of found steps with right ATT&CK technique |
| Attack path               | ALL planted attacks rebuilt, right steps, right order |
| False alarms              | < 10% of reported incidents are not real      |
| Processing time (50 GB)   | < 1 hour                                      |
| Peak memory (all procs)   | < 8 GB, must run on a normal laptop           |
| Open one incident path    | < 500 ms (p95)                                |

PRD functional requirements, ALL must be met:
- FR-1 Stream the data set without loading it into memory.
- FR-2 Detect suspicious events (example: 50 failed logins on one account, then a success).
- FR-3 Map each detection to a MITRE ATT&CK technique AND a kill chain stage (example: "Brute Force (T1110)" -> Credential Access).
- FR-4 Link related events into one incident by host, user, IP and time (failed logins + new admin account + upload to outside IP = one attack).
- FR-5 Show the attack path as a timeline AND as a graph of hosts and users (Laptop HR-07 -> file server FS-02 -> domain controller DC-01).
- FR-6 Show what the attacker could reach next (example: "this account has admin rights on 3 more servers").
- FR-7 Simple API or page plus a short README (example: GET /incidents/12/path). `docker compose up` must work.
Bonus, implement all: B-1 risk score (worst incident on top), B-2 plain-English incident report, B-3 raw-alert count per incident, B-4 add detection rules by editing a YAML config (no code change), B-5 live mode (new log lines update the attack path within seconds; optional, build last).

================================================================================
3. STEP 0: INSPECT THE DATA BEFORE WRITING ANY REGEX
================================================================================
- Read the dev sample and the ground-truth file (if present). List every distinct log format, file name pattern and timestamp format. Write them to docs/FORMATS.md with 3 example lines each.
- Syslog timestamps have no year: derive the year from the data or a config value.
- Work out the ground-truth schema (which fields identify an attack, its steps, order, technique IDs). evaluate.py is built around it.
- Check which hosts look like workstations, file servers, domain controllers and what naming patterns exist (HR-07, FS-02, DC-01 style). This drives asset criticality.
- Write all regexes against REAL lines from the sample. If rules/detect.yaml and tagger.py already exist, reuse and extend them, and fix regexes that do not match the sample.

================================================================================
3b. KNOWN LOG FORMAT (from the real dev sample) - THIS OVERRIDES ANY SYSLOG ASSUMPTION
================================================================================
The data is FortiGate firewall logs: ONE event per line, space-separated key=value pairs, values quoted when they contain text. Example keys:
  date= time= eventtime=<19-digit nanosecond epoch> tz="+0530" devname= devid= logid= type= subtype= level= vd=
  srcip= srcport= srcintf= srcintfrole= dstip= dstport= dstintf= dstintfrole= sessionid= proto= action= policyid= service= srccountry= dstcountry=
  traffic logs add: app= appcat= apprisk= duration= sentbyte= rcvdbyte= sentpkt= rcvdpkt=
Log types seen (type/subtype): traffic/forward (the majority), utm/dns (hostname=), utm/webfilter (hostname= url= catdesc=), utm/ips (attack= attackid= severity=), utm/virus (virus= hostname= url=), utm/app-ctrl, event/system (logdesc="Admin login failed" user= ui= method= reason= status= msg=), event/vpn, and noise (DHCP, HA, sd-wan, connector, performance stats).
Rules for this format:
- Timestamp = first 10 digits of eventtime (no date parsing, no year problem). Never parse date/time strings.
- There are NO hostnames and mostly NO usernames. The asset identity is the IP address (srcip / dstip). Users exist only in firewall admin-login events. Entities for correlation are therefore IPs, /24 subnets and admin usernames; devname is always the same firewall.
- Asset criticality comes from subnets (confirm from the sample): 10.10.99.0/24 mgmt = highest, 10.10.20.0/24 dmz servers = high, 10.10.10/30/40/50.0/24 LAN = normal. Put this in correlate.yaml as a subnet table, not hostname regexes.
- The service= and app=/appcat= fields look randomly generated and disagree with dstport (service="RDP" on port 443). Detect on dstport, srcip/dstip, sentbyte, severity, logdesc, reason, catdesc, not on service or app.
- Admin login failures are a large share of the sample, each source IP appears once or twice, but sources cluster in the same /24 (45.74.28.x, 77.91.71.x, 185.136.15.x) with a different username each time. Per-IP thresholds will never fire: group by src /24 and count DISTINCT usernames (distributed password spraying). reason="name_invalid" = unknown username; reason="passwd_invalid" = valid account with wrong password (the real "50 failures then success" brute force). Success is logdesc="Admin login successful".
- Volume: aggregate. Failed logins and DNS/traffic lines are far too numerous for one alert per line. Emit one alert per threshold hit (count, distinct, first/last time), never per raw line. Purge idle sliding-window keys every ~200k lines so memory stays bounded.
- Traffic from LAN to wan1 is background noise; the sample contains no internal-to-internal flows, so any internal-to-internal flow on 22/445/3389/5985 is a strong lateral-movement signal. Sample background sentbyte tops out near 8.5 MB, so exfiltration thresholds belong at the p99.9 of the data (use profile.py), not a guess.
- FR-6 "could reach next": firewall logs have no user-to-host logins. Derive it from observed flows: internal hosts/subnets a compromised IP has already talked to, plus the mgmt subnet and admin ports reachable from it, plus the firewall admin accounts it logged in with.
Ship rules/detect.yaml and tagger.py (already written for this format; extend, do not rewrite) and run profile.py on the sample first; tune thresholds from its output. Rules marked seen_in_sample: false are unverified: confirm each against the full sample and the ground-truth file, and delete or fix any that never match. Ask for samples of every OTHER log file type in the data set (the PRD says the data spans several files); write rules for each.

================================================================================
4. REPOSITORY LAYOUT (create exactly this)
================================================================================
backend/
  scanner.py       parallel byte-range scanner, writes partial Parquet
  rules.py         YAML loader, validator, RuleEngine (match / threshold / distinct_threshold)
  store.py         DuckDB schema, load Parquet, indexes
  correlate.py     sequence rules, union-find incidents, suppression, risk
  graph.py         NetworkX DiGraph per incident, next-hop prediction, report text
  api.py           FastAPI app
  evaluate.py      accuracy + performance scoring against ground truth
  ai_filter.py     optional Ollama triage (off by default)
  live.py          optional tail mode
frontend/
  index.html       single-file UI (already written, see section 12)
rules/
  detect.yaml  sequence.yaml  correlate.yaml  report.yaml
docs/FORMATS.md
tests/
docker-compose.yml
backend.Dockerfile
requirements.txt   (pinned: fastapi, uvicorn, duckdb, pyarrow, networkx, pyyaml, pydantic, requests, psutil, tqdm)
README.md

================================================================================
5. SCANNER (FR-1, FR-2) - the performance-critical part
================================================================================
- List every file under the log directory. Split each file into ~64 MB byte ranges, each aligned forward to the next newline. Add ~1 MB overlap at the start of each range so threshold windows survive chunk boundaries; dedupe alerts that fall in the overlap.
- All ranges across all files go into ONE multiprocessing pool. Worker count = min(cpu_count, whatever keeps total RSS under 7 GB). Each worker holds roughly 150-300 MB.
- Open files in BINARY mode. Use bytes regexes. Decode only the captured fields of matched lines.
- Two-stage match: (a) a cheap literal / combined-alternation prefilter that rejects >95% of lines, (b) the detailed regex only on prefilter hits. Optionally shell out to ripgrep for the prefilter if it is installed, but the pure Python path must work.
- Workers keep ONLY alerts in memory, never lines or chunks. Each worker writes its own partial Parquet file into a temp dir. The parent never receives large payloads over pipes.
- Stateful rules inside a worker use per-key sliding windows (deque). Noisy rules emit AGGREGATED alerts (rule, user, host, src_ip, first_ts, last_ts, count) rather than one alert per raw line.
- Checkpointing: a table of finished (file, start, end) chunks so a crashed run resumes instead of restarting.
- Progress: bar with MB/s, ETA, files done and live peak RSS (sum of parent + workers).
- Benchmark mode: `docker compose run --rm backend python -m backend.scanner --benchmark 50GB` concatenates/streams the sample repeatedly to a fake 50 GB file to prove time and memory. State clearly that ground truth is meaningless in that mode.
- Throughput target: at least ~15 MB/s sustained overall (50 GB in under an hour). Measure MB/s per core on the sample and report the extrapolation.

================================================================================
6. RULES IN YAML (FR-3, B-4) - four layers under rules/
================================================================================
detect.yaml
  - tactics table: tactic -> {order, kill_chain}. kill_chain is derived from the tactic and is NEVER repeated inside each rule. Tactics: Reconnaissance, Initial Access, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact. Kill chain stages: Reconnaissance, Delivery, Exploitation, Installation, Command and Control, Actions on Objectives.
  - rules: id, name, type, prefilter (literal), match (regex with named groups), where (conditions such as bytes ">100000000", dst_ip not_private, src_ip is_private), group_by, count, window, distinct, technique, technique_name, tactic, weight.
  - rule types: match | threshold | distinct_threshold.
  - Use RFC1918 + loopback + link-local ONLY for "private". Do NOT use Python's is_private blindly: it treats documentation ranges (203.0.113.0/24, 198.51.100.0/24) as private, which synthetic data often uses for attackers.
  - Context decides the tactic: a successful login from an external IP = T1078 Initial Access; from an internal IP = T1021 Lateral Movement. Write separate rules with `where` conditions.
  - Minimum coverage (only keep ones whose pattern actually exists in the sample, plus anything else found in it):
      T1110.001 password guessing (threshold, group by user+src_ip)
      T1110.003 password spraying (distinct users per src_ip)
      T1078 valid accounts (login success from external IP)
      T1021 remote services (login from internal host)
      T1046 network service discovery (distinct ports per src_ip/dst_ip)
      T1136.001 create local account (useradd, net user /add, event 4720)
      T1548.003 sudo / privilege use (sudo to root, event 4672)
      T1560 archive collected data (tar, zip, rar, 7z)
      T1041 exfiltration over C2 channel (large outbound to external IP)
      T1071 application layer protocol (periodic small beacons)
      T1070 indicator removal (log cleared, history -c, event 1102)
sequence.yaml
  - Ordered patterns over ALERTS (run on the alerts table, not raw logs): steps [rule ids], same: [user|host|src_ip], within seconds, bonus_score. Examples: brute force -> successful login (same user, 1 h); login -> account creation -> large outbound transfer (same host, 24 h).
correlate.yaml
  - link_on: [user, host, src_ip, dst_ip]; max_gap_seconds; min_alerts; min_weight_override (a single alert at or above this weight still counts); allowlists (scanner IPs, service accounts, backup hosts); asset_criticality as ordered regex -> value (DC 3, file server 2, default 1); risk_formula; kill chain order; next_hop rules.
report.yaml
  - Plain-English sentence template per tactic, e.g. Credential Access: "brute-forced {user} from {src_ip}", Persistence: "created account {new_user} on {host}", Lateral Movement: "moved from {src_host} to {dst_host}", Exfiltration: "sent {bytes_human} to {dst_ip}".
Startup validation (fail loudly, exit non-zero):
  - technique ID matches ^T\d{4}(\.\d{3})?$ AND exists in the official MITRE ATT&CK enterprise dataset (download once, cache locally; if offline use the cached copy),
  - tactic exists in the tactics table, every regex compiles, every referenced rule id in sequence.yaml exists, every `where` key is a field the rule captures.
Hot reload not required; re-running the scan with edited YAML must pick the changes up (this is B-4).

================================================================================
7. STORAGE
================================================================================
DuckDB file. Tables (create indexes on the join and filter columns):
- alerts(alert_id, ts, host, user, src_ip, dst_ip, dst_port, new_user, bytes, count, rule_id, rule_name, technique, technique_name, tactic, kill_chain, stage_order, weight, file, offset)
- chunks(file, start, end, status)  -- checkpointing
- incidents(incident_id, risk, alert_count, first_seen, last_seen, stages, hosts, users, ips, summary, status, suppress_reason, sequence_ids)
- incident_paths(incident_id, path_json, report_text)  -- PRECOMPUTED, served as-is
- access_history(user, host, rule_id, first_seen, last_seen, count)  -- login and sudo facts for next-hop prediction
- ai_verdicts(incident_id, verdict, confidence, reason)  -- optional
Keep `file` and `offset` on each alert so the analyst can trace any alert back to its raw line.

================================================================================
8. CORRELATION (FR-4, B-3)
================================================================================
- Union-find with ENTITIES as nodes: every user, host and IP an alert touches is unioned with the others in the same alert.
- Only link alerts within max_gap_seconds so unrelated activity stays separate.
- Each connected component = one incident. Store raw_alert_count (B-3: "342 alerts -> 1 incident").
- Apply sequence rules; incidents that match get their alerts flagged high-confidence and a risk bonus.
- Reduce false alarms with rules only: drop single weak alerts, allowlisted entities, and incidents below min_alerts unless one alert is severe. Never silently discard: store status=suppressed with a suppress_reason so the UI can show a "Suppressed" tab.
- Must handle shared entities that would wrongly merge everything (e.g. a shared gateway IP, a service account, localhost). Add an entity "degree cap" / stoplist in correlate.yaml so a hub entity does not glue unrelated attacks into one mega-incident.

================================================================================
9. ATTACK PATH GRAPH (FR-5, FR-6)
================================================================================
- NetworkX DiGraph per incident. Nodes: hosts, users, IPs (with type and criticality). Edges: alerts, labelled technique, tactic, kill_chain, time, rule_id.
- Order edges by time and validate against the tactic order. Flag out-of-order steps rather than hiding them.
- "Could reach next" (FR-6): rule driven graph lookups, NOT guesses:
    a) hosts the compromised user has logged into successfully or run sudo/admin on anywhere in the data set (from access_history),
    b) users who have logged into each compromised host.
  Return them as predicted edges with the evidence ("jdoe has sudo on FS-02, FS-03, DC-01").
- PRECOMPUTE the complete path (nodes, edges, timeline, next_hops, report) at build time and store it in incident_paths, so the API only reads one row.

================================================================================
10. RISK AND REPORT (B-1, B-2)
================================================================================
- risk = sum(weight) * distinct_kill_chain_stages * max(asset_criticality) + sequence_bonus, formula configurable in correlate.yaml. Incidents sorted by risk descending.
- Plain-English report built only from the report.yaml templates, in time order, using ONLY facts from the path. Example: "Attacker brute-forced jdoe from 203.0.113.9, logged in to HR-07, moved to FS-02, created account backup2, sent 2.1 GB to 198.51.100.4." Never invent facts.

================================================================================
11. API (FR-7) - FastAPI, read-only DuckDB connection
================================================================================
GET  /health
GET  /overview                    home dashboard payload (section 12)
GET  /stats                       scan time, MB/s, peak memory, files, alert count, incident count, suppressed count
GET  /incidents                   sorted by risk desc; fields: id, risk, alert_count, stages, hosts, users, first_seen, last_seen, summary, status
GET  /incidents/{id}/path         nodes, edges, timeline, next_hops, report; send header X-Latency-Ms; MUST be < 500 ms
GET  /incidents/{id}/report       plain-English report
GET  /incidents/{id}/alerts       raw alerts with file/offset
POST /scan                        body {path}; starts a background scan
GET  /scan/status                 progress, MB/s, ETA, peak RSS
POST /incidents/{id}/ai-report    optional, falls back to the template report
Add CORS and validation. Return JSON errors. Add pagination to /incidents.

================================================================================
12. UI - Stellar Cyber "XDR Kill Chain" home dashboard + attack path graph
================================================================================
frontend/index.html is ALREADY WRITTEN (single file, no build step, no CDN, no vis-network, inline SVG graph, dark theme, works offline). Do NOT redesign it. Wire the backend to it and keep its contract. If a data shape is missing, extend the backend, not the page. When the API is unreachable the page shows built-in demo data with a banner; remove nothing.
Design reference: Stellar Cyber "Using the XDR Kill Chain (Home Page)". Layout the page implements:
- Top bar: logo, menu, search, log folder input, Scan button, scan status.
- Status cards: Incidents, Alerts, Assets, Users (critical or risky count against total, with a meter) and Last scan (MB/s, peak memory, duration). Critical = score >= 75.
- Kill chain loop in the centre: five stages, each with "critical | total" alert counts, hover tooltip listing the tactics of the stage, click to filter every panel by that stage, pause-animation button.
    Stage 0 Initial Attempts: Reconnaissance, Initial Access, external Credential Access
    Stage 1 Persistent Foothold: Execution, Persistence, Defense Evasion, Command and Control
    Stage 2 Exploration: Discovery, Collection
    Stage 3 Propagation: Privilege Escalation, Lateral Movement, internal Credential Access
    Stage 4 Exfiltration & Impact: Exfiltration, Impact
  rules/detect.yaml already maps every tactic to one of these stage names (kill_chain field). Each alert keeps tactic, technique and stage.
- Left: Top incidents as collapsible capsules (risk score badge, "N alerts merged into 1 incident" for B-3, stage chips, time range, plain-English summary, "Open attack path" button).
- Right: Top risky assets (IP, internal/external, score 0-100, per-stage counts, most severe alert).
- Bottom: Alerts-by-tactic bar chart in kill chain order, bars coloured by stage, All/Critical/Other toggle, click to filter by stage.
- Incident page (#incident/ID): score, raw-alert count, per-stage strip, ATTACK PATH GRAPH (FR-5) with one column per kill chain stage, hosts and IPs as nodes (circle = external IP, square = internal asset), numbered solid edges coloured by stage (what happened, in time order), dashed red edges for "could reach next" (FR-6), click a node or step to trace it; right side timeline (technique ID, name, tactic, time, rule ID, severity), plain-English incident report and the list of reachable next assets.
API the page calls (nginx must proxy /api/ to the backend and strip the /api prefix: `proxy_pass http://backend:8000/;`):
  GET /overview  -> {totals:{incidents,incidents_critical,alerts,alerts_critical,assets,assets_risky,users,users_risky}, stages:[{critical,total} x5], tactics:[{tactic,critical,non_critical}], incidents:[{id,name,score,alert_count,stage_counts:[x5],first,last,hosts,ips,summary}], assets:[{ip,score,stage_counts:[x5],top:{desc,tech}}], scan:{mbps,peak_gb,seconds}}
  GET /incidents/{id}/path -> {id,name,score,alert_count,report, timeline:[{ts,rule,tech,tname,tactic,stage,src,dst,sev,desc}], next_hops:[{from,to,why}]}   (sev = rule weight x 10; the page builds the graph from timeline src/dst)
  POST /scan {path}, GET /scan/status -> {running,percent,mbps,eta}
Precompute /overview during correlation and cache it in DuckDB so the home page loads instantly. Verify with the real data that every incident renders, long incident names do not overflow, and an incident with 300+ nodes stays usable (cap displayed nodes and add a "show more" control if needed).

================================================================================
13. OPTIONAL AI LAYER (hybrid, OFF by default: ai_filter.enabled: false)
================================================================================
Only build after everything else passes. Runs AFTER the scan so it never counts toward scan memory.
- Separate Ollama container, compose profile "ai", model qwen2.5:1.5b-instruct-q4_K_M, temperature 0.05, JSON output.
- Three lanes decided by deterministic rules: CONFIRMED (sequence match, any alert weight >= 8, or 3+ distinct stages) never touches AI; NOISE dropped by rules; only UNCERTAIN incidents go to the AI.
- Send a compact structured summary (counts, stages, a few events), NEVER raw logs.
- Prompt: "You are a SOC triage assistant. Use ONLY the facts provided. Respond with JSON only: {verdict: attack|noise|unsure, confidence: 0-100, reason: one sentence citing the given facts}."
- Suppress only if verdict == noise AND confidence >= 85. Never delete, show in a "Suppressed by AI" tab. The AI never changes technique, tactic, path order or risk. If Ollama is down or times out, nothing is filtered.
- Cache verdicts in ai_verdicts. evaluate.py reports results with and without the AI filter. Keep the AI filter only if false alarms drop and detection does not.

================================================================================
14. LIVE MODE (B-5, optional, build last)
================================================================================
`docker compose run --rm backend python -m backend.live --path /data/auth.log` tails a file, feeds new lines through the same RuleEngine, upserts alerts, re-runs correlation for the touched incidents only, and updates their precomputed path within seconds. Expose it via a /scan/live toggle.

================================================================================
15. evaluate.py (accuracy is half the score)
================================================================================
Compare produced incidents against the ground truth and print a table with PASS/FAIL against Good and Great thresholds:
- Detection: share of planted attack steps found
- Label accuracy: exact technique match AND parent-technique match (report both; say which one the ground-truth format implies)
- Attack path: share of planted attacks rebuilt with the right steps in the right order
- False-alarm rate: share of incidents that are not real attacks
- Total processing time and MB/s
- Peak memory including all worker processes
- p50 and p95 latency of GET /incidents/{id}/path over every incident
Also print a per-attack breakdown showing which steps were missed or mislabeled, so rules can be tuned. Then iterate on the YAML rules until the Great column passes.

================================================================================
16. TESTS (must pass)
================================================================================
Unit tests for: each rule type, `where` conditions (incl. private-IP edge cases), threshold windows across a chunk boundary and overlap dedupe, union-find with a hub entity, sequence matching, path ordering, report generation, YAML validation failures (bad technique id, unknown tactic, broken regex must all fail loudly).

================================================================================
17. DOCKER (MANDATORY) AND README
================================================================================
Docker Compose is the ONLY supported way to run this tool. Nothing may depend on host Python, host packages, or host paths other than the mounted data folder.

Services (docker-compose.yml, compose spec v2):
  - backend    : built from backend.Dockerfile; runs FastAPI (uvicorn) and the scanner. Also used for one-off jobs via `docker compose run --rm backend ...`.
      * mem_limit: 8g and memswap_limit: 8g (hard cap, so "peak memory < 8 GB" is enforced by Docker, not just claimed)
      * cpus: use all by default, overridable with an env var BACKEND_CPUS
      * volumes: ./data:/data:ro (read-only log input), a named volume `kc_db` for the DuckDB file and temp Parquet, ./rules:/app/rules (so editing YAML needs no rebuild; B-4)
      * environment: LOG_PATH=/data, DB_PATH=/db/kc.duckdb, WORKERS=auto, AI_FILTER=false
      * healthcheck on GET /health, restart: unless-stopped, runs as a non-root user
  - frontend   : nginx:alpine serving frontend/index.html (single file, no CDN) and proxying /api/ to backend:8000 with the prefix stripped (proxy_pass http://backend:8000/;). Exposed on host port 8080.
  - ollama     : image ollama/ollama, ONLY under `profiles: ["ai"]`, its own mem_limit, model qwen2.5:1.5b-instruct-q4_K_M pulled automatically on first start via an entrypoint script, volume for model cache. Never started by default.
  - Optional one-shot service `evaluate` (profile "tools") that runs evaluate.py inside the backend image.

backend.Dockerfile:
  - Base python:3.11-slim, multi-stage if it shrinks the image. Pinned requirements.txt, `pip install --no-cache-dir`, PYTHONUNBUFFERED=1, a non-root user, WORKDIR /app, COPY backend/ rules/ docs/. Bake the cached MITRE ATT&CK dataset into the image at build time (so startup validation works offline).
  - If ripgrep is used as an optional prefilter, apt-install it in the image; the pure Python path must still work.
  - Include a .dockerignore (exclude data/, .git, __pycache__, *.parquet, *.duckdb).

Everything runs through these exact commands, and you must verify each one from a clean checkout (run `docker compose down -v` first):
  1. Start:            docker compose up --build -d
  2. Scan a folder:    docker compose exec backend python -m backend.scanner --path /data
                       (or click Scan in the UI at http://localhost:8080, which calls POST /scan)
  3. Tests:            docker compose run --rm backend pytest -q
  4. Accuracy:         docker compose --profile tools run --rm evaluate
  5. Benchmark:        docker compose run --rm backend python -m backend.scanner --benchmark 50GB
  6. Optional AI:      docker compose --profile ai up -d
  7. Stop and clean:   docker compose down        (add -v to wipe the DB volume)
The data folder is configurable: `DATA_DIR=/path/to/50gb docker compose up -d` maps it to /data (default ./data).

Docker-specific measurements (report real numbers from these, not estimates):
  - Peak memory: sample `docker stats --no-stream` (or the cgroup file /sys/fs/cgroup/memory.peak) every second during the scan and report the maximum; it must stay under the 8g limit with no OOM kill. Also confirm with `docker inspect` that OOMKilled is false.
  - Throughput: MB/s and total scan time measured inside the container against the mounted data (state the host disk type, e.g. SSD).
  - Latency: p50/p95 of GET /incidents/{id}/path measured through the nginx proxy on port 8080.
Handle Docker pitfalls explicitly: bind-mounted data on Docker Desktop (Mac/Windows) is slower, so document that the 50 GB run should be on Linux or a native volume; set the container's file-descriptor limit high enough for many workers; make sure partial Parquet temp files go to the named volume, not the container's writable layer, so the 50 GB run cannot fill the container filesystem; make the backend wait for the DB volume and create the schema on first start.

README.md (short, Docker-first): prerequisites (only Docker + Docker Compose), quickstart (the commands above), how to point at the 50 GB folder, how to add a rule by editing rules/detect.yaml (no rebuild), how to run tests and evaluate.py in Docker, optional AI profile, a troubleshooting list (OOM, slow bind mounts, port already in use), and a "measured results" table filled with REAL numbers vs the PRD Good/Great targets.

================================================================================
18. BUILD ORDER (follow it, commit and report after each stage)
================================================================================
 0. Inspect sample + ground truth -> docs/FORMATS.md
 1. rules/*.yaml + rules.py validator + unit tests
 2. scanner.py + Parquet + DuckDB load + checkpoint + benchmark mode; measure MB/s and RSS
 3. correlate.py (union-find, sequences, suppression, risk)
 4. graph.py (path, next-hops, report) + precomputation
 5. api.py + latency test
 6. frontend/index.html
 7. evaluate.py + tune rules until Great targets pass
 8. Docker image, compose, healthchecks, README with real numbers (from here on, run EVERYTHING through Docker; re-run stages 2, 5 and 7 inside the containers and report the Docker numbers)
 9. Optional: AI filter, then live mode
At the end print: (a) the evaluate.py table, (b) the fake-50GB benchmark result, (c) the exact Docker commands to run everything, plus the `docker stats` peak-memory evidence, and (d) any PRD target that is NOT yet met and why.

================================================================================
DEFINITION OF DONE
================================================================================
- Docker is the only requirement: on a machine with just Docker installed, `docker compose up --build -d` from a clean checkout starts the backend, the UI on http://localhost:8080, and all healthchecks go green.
- Tests, evaluate.py and the benchmark all run via `docker compose run`, with no host Python.
- Peak memory is measured with Docker (docker stats / cgroup) under the 8g mem_limit, with no OOM kill.
- A scan of the real 50 GB finishes in < 1 hour with peak memory < 8 GB.
- evaluate.py shows Detection > 90%, Labels > 85%, all attacks rebuilt, false alarms < 10%.
- GET /incidents/{id}/path is < 500 ms at p95.
- The UI shows incidents sorted by risk, a graph with solid path edges and dashed could-reach-next edges, a timeline with technique and stage on every row, and a plain-English report.
- Adding a new rule by editing rules/detect.yaml works with no code change.
Begin with Step 0 now.
```
