# EDR JSONL scan repair and validation

The failed browser scan was using the legacy preview on port 18766, whose API upstream was an older native process on 18765. The Docker app on 8080 did not have that failed job. The preview now forwards API requests to the current Docker app, preserving the `/api` prefix and authentication header. Preview HTML is revalidated on refresh. The canonical app URL remains http://localhost:8080.

The supplied `data/killchain_security_logs.jsonl` uses the generator's ECS-like telemetry and pre-labelled EDR reports. The adapter now accepts `process_created`, `network_connection`, event telemetry, and provider reports with technique arrays. Configured rules R200–R204 map the five action/technique pairs, including the Impact tactic. Unknown or mismatched reports are counted as unmapped instead of promoted into arbitrary detections.

Provider records are displayed as **Upstream EDR report (provider annotation)**. Source flags mark the simulated records in the dashboard. An aggregated failed-login report is kept as one report; its `failed_count_5min` field is not expanded into invented raw log events. Missing login source IPs and logon types are not invented. `network.bytes` is not assumed to be bytes sent. Endpoint names remain in stored alert evidence; the current asset summary counts IP identities, not a deduplicated endpoint inventory.

The API records the selected path and exposes short ValueError/OS error details for actionable scan failures. Full exceptions remain in backend logs.

## Full-file check

The complete file was submitted using its Windows path through port 18766, validating the repaired route and Docker path mapping:

| Check | Result |
|---|---:|
| Source bytes | 1,000,000,314 |
| Records | 1,591,447 |
| Unsupported / oversized records | 0 / 0 |
| Reported EDR alerts | 317,529 |
| Records flagged simulated | 317,529 |
| Unmapped provider reports | 0 |
| Pipeline time | 193.76 s |
| Extraction / aggregation / correlation | 160.62 / 1.32 / 31.82 s |
| Reused extraction chunks | 0 (cold run) |
| Workers | 2 |
| Container cgroup peak | 1,323,118,592 bytes |
| Active / suppressed report incidents | 62,970 / 254,559 |

Six active/suppressed paths passed graph/report and original JSONL byte-offset checks. The complete validator, including polling and those checks, took 208.01 seconds. See [edr-jsonl-validation.json](edr-jsonl-validation.json) for raw results. All 95 Docker tests passed in 21.40 seconds, with one existing Starlette/httpx deprecation warning.

This file is generated telemetry. Successful ingestion and agreement with its provider annotations do not measure independent detection accuracy or prove real attacks.
