# KillChain XDR

Deterministic firewall and endpoint log analysis: streaming detection, ATT&CK labels, incident correlation, attack graphs, evidence locations, reports and a dark analyst dashboard. See [detection coverage and accepted formats](docs/DETECTIONS.md) for all eleven requested behaviors.

**Status: functional development build. Production readiness and the PRD's 50 GB accuracy/performance gates are not certified.** Docker startup, nginx/API routing and all 119 local and container tests have been verified. Performance measurements retain their native or Docker scope; see [VALIDATION.md](docs/VALIDATION.md) and [REQUIREMENTS.md](docs/REQUIREMENTS.md).

## Run with Docker

The core scope is detection, correct labels, connected attack stories, a readable timeline/graph, evidence-backed next access, accuracy and streaming at 15 GB or more. The earlier 50 GB target remains an additional acceptance target. UI polish, login/user management, cloud deployment and attack blocking are outside the required scope. Independent ground truth, permission inventory, correlation tuning and cold large-file validation remain open; see [the scope and acceptance checklist](docs/REQUIREMENTS.md). The latest correlation update passed 105 local and Docker tests; its resumed EDR validation and limitations are recorded in [CORRELATION.md](docs/CORRELATION.md).

The latest resumed Docker run completed the full supplied 6.54 GB file (12,398,551 lines) in 196.12 seconds using all 98 extraction checkpoints. The container memory peak was 2,826,027,008 bytes. This is resumed processing, not cold file-reading throughput. Cold full-file and 50 GB release gates remain unverified. See [PERFORMANCE.md](docs/PERFORMANCE.md).

Prerequisites: Docker Engine/Desktop with Compose v2. Allocate enough disk for source data, Parquet candidates and DuckDB spill, and at least 8 GB to the backend container. Runtime dependencies are pinned; no host Python or Node is required. Python 3.14 is used consistently with the tested dependency set rather than the plan's older 3.11 base.

```sh
docker compose up --build -d
docker compose exec backend python -m backend.scanner --path /data
```

Open **http://localhost:8080**. The Scan logs button submits the same background job. Initial startup shows an empty dashboard; connection failures are displayed without substituting demo incidents. Scan progress, failure messages, active/suppressed incidents, evidence byte offsets and JSON export are available in the UI.

Place supported `.log`, `.txt`, `.syslog`, `.jsonl`, `.ndjson`, `.xml` or extensionless text files under `data/`. Contents must match the supported adapters in [DETECTIONS.md](docs/DETECTIONS.md). To mount another folder, set `DATA_DIR` before starting Compose, for example:

```sh
DATA_DIR=/srv/security-logs docker compose up --build -d
```

PowerShell: `$env:DATA_DIR='D:/security-logs'` followed by `docker compose up --build -d`. Scan accepts container paths beneath `/data`. To also accept Windows paths in the dashboard, set `HOST_LOG_PATH` to the absolute Windows folder mounted at `/data` in `.env` (for example, `HOST_LOG_PATH=E:/KillChain/data`) and recreate the backend. Update it when changing `DATA_DIR`. Only paths within that folder are mapped; traversal outside `/data` remains blocked. Inputs must remain unchanged during a batch scan.

```sh
docker compose run --rm --no-deps backend pytest -q
docker compose exec backend python -m backend.profile --path /data --lines 200000
docker compose --profile tools run --rm evaluate
docker compose logs -f backend
docker compose down
```

The evaluation service expects `/data/ground_truth/attacks.json`; missing truth exits with code 2 and reports unverified accuracy. See [EVALUATION.md](docs/EVALUATION.md) for the schema and interpretation. The backend database and checkpoints persist in named volume `kc_db`. `docker compose down -v` permanently removes that analysis volume; it is not needed for ordinary restarts.

Scan optimization and measurements: [PERFORMANCE.md](docs/PERFORMANCE.md). Unchanged completed scans reuse published results. Suppressed graphs are generated when opened; source evidence is retained.

## Rules and evidence

Optional [Gemini incident review and local false-positive validation](docs/AI_REVIEW.md) are available. AI review uses a separate `GEMINI_API_KEY`, sends only a bounded pseudonymized sample on demand, and never changes detection or measured accuracy. The authored local validation suite currently exposes a legitimate-backup false alarm; it does not claim a passing real-data accuracy gate.

Edit `rules/detect.yaml`, `sequence.yaml`, `correlate.yaml` or `report.yaml` and rescan. Detection changes invalidate extraction checkpoints. No image rebuild is needed for mounted rule changes. The original FortiGate rules remain, with per-IP spraying corrected, distributed spraying retained separately, and endpoint coverage added. Rules record whether they were observed in the supplied sample. Startup rejects unknown technique IDs, tactics, invalid regexes, unsupported conditions and invalid sequence references. The compact ID catalog in `rules/techniques.json` was derived from the official MITRE enterprise STIX bundle; it records source bundle ID and SHA-256. Runtime validation needs no network.

The engine supports match, threshold, distinct-threshold and periodic timing rules, named regex captures, explicit private-IP conditions, time windows and configurable grouping. Detection thresholds operate across files and chunks. Every reduced detection retains its representative source file/offset and a separate evidence relation for every contributing candidate line. Raw-event counts are matching-event counts per detection; a line matching multiple rules can contribute multiple matches.

## API

The [home-page overview graph](docs/HOME_GRAPH.md) combines all scoped incidents into one interactive evidence map, with node/edge detail panels, related incident links, impact-signal counts, Find/zoom/pan/fullscreen and optional activity animation. Remaining unaffected assets and confirmed exploitation stay unknown until independent evidence and inventory support those claims.

The [incident evidence explorer](docs/GRAPH.md) provides grouped connections, zoom/pan, node and link inspection, time/stage filters, fullscreen, SVG export and full-incident metrics. Run its checks with `node --test tests/test_graph.cjs` when Node is available; Node is not required to run the application.

The nginx `/api/` prefix is stripped before forwarding to FastAPI:

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | Rule/catalog and DB health |
| GET | `/api/overview` | Cached dashboard, top 100 incidents per status and top 100 assets |
| GET | `/api/incidents?status=active&limit=50&offset=0&search=admin` | Paginated incident search |
| GET | `/api/incidents/{id}/path` | Precomputed graph, timeline, evidence locations, report, next hops |
| GET | `/api/incidents/{id}/report` | Template report |
| GET | `/api/incidents/{id}/alerts` | Paginated reduced alerts |
| GET | `/api/evidence?file=auth.log&offset=123` | Locate active findings covering a raw line |
| GET | `/api/stats` | Last completed run metrics |
| POST | `/api/scan` | Start scan: `{"path":"/data"}` |
| GET | `/api/scan/status` | In-process progress/error state |

Only one scan runs at a time. Keep one Uvicorn process: DuckDB is embedded and is not a distributed database. During final aggregation/publication, readers wait for the database lock. See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for limitations and recovery behavior.

## Benchmark and release measurements

The [validation-engine audit](docs/VALIDATION_ENGINE_AUDIT.md) passed its direct-vs-HTTP checks and the final 168-test Docker suite. The synthetic legitimate-backup case still fails the detector's false-incident target; real-data accuracy remains unverified without independent truth. Reproduce the isolated audit with `python -m backend.validation_audit --output tmp/validation-engine-audit`.

Stop the normal backend before an independent benchmark writer uses the same database volume:

```sh
docker compose stop backend
docker compose run --rm --no-deps backend python -m backend.scanner --path /data --benchmark 50GB
docker compose up -d backend
docker stats --no-stream
docker inspect --format '{{.State.OOMKilled}}' $(docker compose ps -q backend)
```

A repeated-input benchmark writes a synthetic file on the DB volume and measures throughput/memory only. It does not establish detection accuracy or prove behavior on diverse real 50 GB input. Repeated timestamps also change aggregation density. Reserve at least 50 GB plus working-space headroom for this command. Capture stats/OOM evidence while the relevant benchmark container exists; `--rm` removes it at exit, so omit `--rm` and name the container for retained inspection evidence.

## Deployment and troubleshooting

The published port binds to `127.0.0.1` by default and the backend has no published host port. For authenticated access set `API_TOKEN` in the environment before Compose startup and enter it through **Access key** in the dashboard. The token stays in tab session storage. For access across machines, provision a TLS/authenticated reverse proxy and define the deployment's retention and access controls.

- **OOM / disk pressure:** decrease `WORKERS` and `BACKEND_CPUS`, allow adequate Docker memory, inspect `/db` usage and tune noisy rules. Correlation explicitly refuses more than 1M reduced alerts or 100K detections in one incident. Old checkpoint generations are retained; apply a deliberate retention policy.
- **Slow bind mount:** Windows/macOS Docker Desktop mounts can limit throughput. Measure on the intended disk; Linux/native storage is preferable for the 50 GB release run. Disk type was not established on the implementation machine.
- **Port in use:** set `PORT=8081` (or another available port) before startup.
- **Docker command missing on Windows:** restart VS Code/your terminal after installing Docker Desktop. For an existing per-user installation, the CLI is under `%LOCALAPPDATA%\Programs\DockerDesktop\resources\bin`. In the current PowerShell terminal, refresh it with `$env:Path = "$env:LOCALAPPDATA\Programs\DockerDesktop\resources\bin;$env:Path"`, then run `docker version` and `docker compose version`.
- **DB lock error:** use the running API/CLI delegation; do not start a second independent writer or multiple Uvicorn workers.
- **Missing format:** FortiGate, normalized/ECS/Winlogbeat JSONL, single-line Windows Event XML and ISO-prefixed Linux authentication formats are supported. See [DETECTIONS.md](docs/DETECTIONS.md) for exact fields, timestamp requirements and exclusions. Unsupported/oversized line counts appear in scan metrics.
- **Accuracy unknown:** supply planted-attack truth and tune against it. Broad UTM/DNS rules produce many candidate findings in the sample; those are not verified attacks.

Live mode and optional AI triage are deferred until the core release gates pass. All implemented detection, path ordering, risk and reporting are rule-based.

Final AI analysis: the home page can generate an evidence-linked report after scanning and download it as Markdown. See [setup, privacy and API details](docs/FINAL_AI_REPORT.md).
