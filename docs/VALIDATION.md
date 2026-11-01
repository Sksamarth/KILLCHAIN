# Validation evidence

Implementation machine: native Windows, Python 3.14.3, Node 24.14.1. Initial implementation reported Docker unavailable. On 1 November 2026, Docker was verified through its per-user installation outside the execution sandbox. Disk type was not verified. Dates follow the user's Asia/Calcutta timezone; work started 31 October and continued 1 November 2026.

## Docker setup verification, 1 November 2026

- Docker Desktop 4.97.0, Engine 29.9.2 and Compose 5.6.1 respond successfully through the `desktop-linux` context.
- The user PATH contains the per-user Docker CLI directory. Existing VS Code/terminal processes may need restarting to inherit it.
- `docker compose config --quiet` and `docker compose up --build -d` completed successfully. The backend is healthy and the frontend is available at http://localhost:8080.
- `docker compose run --rm --no-deps backend pytest -q`: **23 passed, 1 deprecation warning in 8.39 s**. The initial console-entry-point test run exposed an import-path and non-root cache issue; the Dockerfile now sets `PYTHONPATH=/app` and a writable pytest cache under `/tmp`.
- HTTP checks through nginx and the published host port returned success. The read-only log mount exposes all 6,543,120,032 input bytes and is readable by UID 10001 (`analyst`).
- Backend memory limit is 8,589,934,592 bytes, and its startup `OOMKilled` state is false. Docker VM memory was reported as 3,746,660,352 bytes. Startup observations are not full-scan peak-memory evidence.
- No volumes, existing native analysis results or raw logs were deleted.
- A follow-up health regression reproduced requests blocking behind database publication. The fix reports the database as busy without waiting on that transaction. The rebuilt image passed **24 tests, 1 deprecation warning in 12.46 s**. It is activated after the current real-data scan finishes.

## Completed checks

### Latest real-file Docker attempt

The full Docker test **did not pass**. It extracted all 6,543,120,032 bytes and 12,398,551 lines into 98 completed Parquet chunks, with zero unsupported or oversized lines. The first attempt stalled during correlation and Docker's engine began returning HTTP 500 errors. A subsequent restart could not launch Desktop because its installation registration was missing.

Both Docker disks were backed up offline to `tmp/docker-backup` (7,654,604,800 bytes total). The official 620,496,816-byte installer was downloaded from `desktop.docker.com`, verified with a Valid Authenticode signature identifying Docker Inc, and rerun in per-user WSL2 mode with the existing `E:\DockerData` root. The installer returned 0, and the engine recovered without a factory reset or volume deletion.

The application was rebuilt with a nonblocking health probe and a configurable 1 GB DuckDB query budget. **24 Docker tests passed, with one deprecation warning, in 6.21 seconds.** All 98 extraction chunks survived and were reused. The resumed attempt also stalled during correlation and the Docker API stopped responding. Its root cause, including whether an OOM occurred, was not established.

That second attempt was stopped and Docker Desktop relaunched. Final verification returned backend `healthy`, `/api/health` with `database: ready`, and an idle scan state at http://localhost:8080. The saved chunk metadata still totals 12,398,551 lines with no unsupported or oversized lines. No complete Docker incident result, cold processing time, final cgroup peak, or real-data Docker path latency is claimed. The earlier native results below remain native-only evidence. Correlation resource handling needs further investigation before repeating a full-file Docker run.

Structured evidence: `docker-validation-results.json`. The raw logs, original Docker disks, and their offline backups remain available.

- **23 pytest tests passed.** Tests cover explicit private-IP ranges including public documentation ranges; condition operators; regex/technique/tactic/field validation; cross-file and byte-range threshold correctness; distinct-user windows and expiry; exact evidence counts; temporal and hub-safe correlation; ordered sequences; report facts; accuracy/path-order mechanics; API validation/authentication/search; end-to-end incident construction; checkpoint reuse; prior-result preservation; and zero-candidate input.
- JavaScript syntax checked with Node. Dashboard and SVG graph templates executed against a real API overview in a JavaScript VM. This checks execution, not visual layout.
- All three source PRD pages were extracted; the requirements and score tables on pages 2 and 3 were rendered and visually inspected.
- Prefix profile: 200,000 real lines, 12 FortiGate type/subtype combinations. Three examples per observed combination are recorded in FORMATS.md.
- Official MITRE enterprise STIX downloaded and reduced to an offline catalog of 867 technique IDs with bundle ID and source SHA-256.

## Measured runs

| Measurement | Observed value | Scope / qualification |
|---|---:|---|
| Initial prefix run | 100,000,000-byte target; 99,999,914 complete-line bytes | Real log prefix, not synthetic |
| Prefix processing | 26.509 s, 3.772 MB/s | Earlier implementation, native; full extraction + aggregation + correlation |
| Prefix memory | 300,908,544 bytes | Sampled parent + child RSS across pipeline; not cgroup memory |
| Prefix incident-path HTTP p50 | 66.765 ms | First 100 active risk-sorted incidents |
| Prefix incident-path HTTP p95 | 85.494 ms | Temporary Python reverse proxy; not nginx or Docker |
| Full input extraction | 6,543,120,032 bytes; 18.995 MB/s | All input ranges completed, 4 workers; extraction only |
| Full resumed pipeline | 277.323 s; 12,398,551 lines | Reused 98 extraction checkpoints after optimization; not a cold-run throughput claim |
| Full resumed memory | 2.105 GB sampled RSS | Across aggregation/correlation; no Docker cgroup evidence |
| Full results | 589,183 detections; 184 active and 588,430 suppressed incidents | Counts, not accuracy estimates; details in full-run-results.json |
| Full-result incident-path HTTP p50 / p95 | 84.572 / 116.975 ms | Every one of the 184 active incidents; native HTTP through temporary Python proxy, not nginx/Docker |

The initial full-data aggregation exposed an expensive evidence join and wide candidate materialization. Those attempts were stopped, their extraction checkpoints retained, and the implementation changed to direct exact-match evidence, Parquet column projection, prefiltered threshold groups and batched result writes. This history is not omitted from the performance assessment. Resumed processing time cannot be represented as cold end-to-end throughput.

## Unverified release targets

| PRD Great target | Status |
|---|---|
| Detection >90% | Unmeasured: no planted-attack labels supplied |
| Exact technique labels >85% | Unmeasured: no planted-attack labels supplied |
| All attack paths correct | Unmeasured: no planted-attack labels supplied |
| False alarms <10% | Unmeasured; prefix produced many noisy incidents |
| Real 50 GB in <1 hour | Unverified: only 6.54 GB supplied; no completed cold 50 GB run |
| Peak memory <8 GB | Full-scan Docker cgroup / stats / OOMKilled evidence pending |
| Path p95 <500 ms | Prefix local sample passes; all-incident Docker/nginx gate unverified |

No 50 GB synthetic benchmark has been executed. Docker build, tests, startup health and nginx routing have been verified. Optional live mode and AI triage remain deferred. Browser visual QA was attempted, but computer use stopped because it could not reliably determine Chrome's current URL; no screenshot-based UI pass is claimed.

`evaluation-results.json` records the full-result API run. All 184 active paths loaded successfully. Its `great_gate` is `UNVERIFIED`, and accuracy is explicitly `NOT MEASURED`. Resumed throughput is kept separate from cold throughput; the API returns `mbps: null` for resumed runs.

The user identified `data/firex-10G.log` when asked for ground truth. It is the same raw-event input, not an independent planted-attack answer key, so accuracy remains unmeasured.

## Eleven-technique detection coverage update

The updated implementation passed 87 tests in Docker (22.29 seconds, one existing Starlette/httpx deprecation warning). This includes all eleven requested behaviors, positive and negative command examples, Windows account scope, Linux authentication, global distinct/threshold/cadence windows across chunk/file boundaries, original-source evidence, and an endpoint attack chain through incident reports and sequence detection. The Windows run passed 87 tests before the added sequence assertions; the updated sequence integration test then passed separately. See DETECTIONS.md for schemas and interpretation limits.

These results validate small fixtures, not full-file accuracy or throughput. Parser/rule changes invalidate older extraction generations. The full-file Docker correlation issue remains unresolved, and no full-file rerun was performed for this update.

## Completed resumed Docker run after performance work

The optimized backend passed 88 Docker tests (34.94 seconds, one existing deprecation warning). It then completed analysis of all 6,543,120,032 bytes / 12,398,551 lines using 98 saved extraction checkpoints: 196.12 seconds pipeline time, 98.60 seconds aggregation, 96.88 seconds correlation. Container cgroup peak was 2,826,027,008 bytes; unsupported/oversized lines were zero. This supersedes the earlier non-completing resumed attempts, but does not establish cold raw-reading throughput or diagnose the original engine stalls. See PERFORMANCE.md and docker-performance-results.json for validation and API metrics.

Post-run checks passed for all 297 active paths (p95 59.84 ms through nginx), report consistency, alerts and raw source evidence. Three suppressed paths were reconstructed on request. Completed-result reuse passed in 2.63 seconds request-to-completion. Expanded-rule totals differ from the historical native rule generation; same-alert optimization invariance is recorded separately in performance-results.json.
