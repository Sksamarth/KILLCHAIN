# KillChain XDR

Deterministic FortiGate log analysis: streaming detection, ATT&CK labels, incident correlation, attack graphs, evidence locations, reports and a dark analyst dashboard.

**Status: functional development build. Production readiness and the PRD's 50 GB accuracy/performance gates are not certified.** Docker was unavailable on the implementation machine. Native tests and sample measurements are documented in [VALIDATION.md](docs/VALIDATION.md); coverage and release gates are in [REQUIREMENTS.md](docs/REQUIREMENTS.md).

## Run with Docker

Prerequisites: Docker Engine/Desktop with Compose v2. Allocate enough disk for source data, Parquet candidates and DuckDB spill, and at least 8 GB to the backend container. Runtime dependencies are pinned; no host Python or Node is required. Python 3.14 is used consistently with the tested dependency set rather than the plan's older 3.11 base.

```sh
docker compose up --build -d
docker compose exec backend python -m backend.scanner --path /data
```

Open **http://localhost:8080**. The Scan logs button submits the same background job. Initial startup shows an empty dashboard; explicit preview data appears only when the API cannot be reached. Scan progress, failure messages, active/suppressed incidents, evidence byte offsets and JSON export are available in the UI.

Place supported `.log`, `.txt`, `.syslog` or extensionless text files under `data/`. To mount another folder, set `DATA_DIR` before starting Compose, for example:

```sh
DATA_DIR=/srv/security-logs docker compose up --build -d
```

PowerShell: `$env:DATA_DIR='D:/security-logs'` followed by `docker compose up --build -d`. Paths passed to Scan are container paths beneath `/data`, never host paths. Inputs must remain unchanged during a batch scan.

```sh
docker compose run --rm --no-deps backend pytest -q
docker compose exec backend python -m backend.profile --path /data --lines 200000
docker compose --profile tools run --rm evaluate
docker compose logs -f backend
docker compose down
```

The evaluation service expects `/data/ground_truth/attacks.json`; missing truth exits with code 2 and reports unverified accuracy. See [EVALUATION.md](docs/EVALUATION.md) for the schema and interpretation. The backend database and checkpoints persist in named volume `kc_db`. `docker compose down -v` permanently removes that analysis volume; it is not needed for ordinary restarts.

## Rules and evidence

Edit `rules/detect.yaml`, `sequence.yaml`, `correlate.yaml` or `report.yaml` and rescan. Detection changes invalidate extraction checkpoints. No image rebuild is needed for mounted rule changes. The original detection rules are preserved and marked with their supplied verification status. Startup rejects unknown technique IDs, tactics, invalid regexes, unsupported conditions and invalid sequence references. The compact ID catalog in `rules/techniques.json` was derived from the official MITRE enterprise STIX bundle; it records source bundle ID and SHA-256. Runtime validation needs no network.

The engine supports match, threshold and distinct-threshold rules, named regex captures, explicit private-IP conditions, time windows and configurable grouping. Detection thresholds operate across files and chunks. Every reduced detection retains its representative source file/offset and a separate evidence relation for every contributing candidate line. Raw-event counts are matching-event counts per detection; a line matching multiple rules can contribute multiple matches.

## API

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
- **DB lock error:** use the running API/CLI delegation; do not start a second independent writer or multiple Uvicorn workers.
- **Missing format:** the current parser supports the observed FortiGate nanosecond key-value format. Other real-world text log families require samples, adapters and validation. Unsupported/oversized line counts appear in scan metrics.
- **Accuracy unknown:** supply planted-attack truth and tune against it. Broad UTM/DNS rules produce many candidate findings in the sample; those are not verified attacks.

Live mode and optional AI triage are deferred until the core release gates pass. All implemented detection, path ordering, risk and reporting are rule-based.
