# PRD coverage and release checklist

The required outcome is to find planted attacks, correctly label their steps, connect hosts/users/IPs/time, explain the story with a timeline and graph, and show evidence for possible next access. Accuracy requires independent planted-attack ground truth; provider alert annotations and unit tests cannot establish it.

The current request requires at least 15 GB on a normal 16 GB laptop. The previously requested Extreme target remains 50 GB in under one hour, under 8 GB peak memory across all processing processes, detection >90%, correct technique labels >85%, all planted paths reconstructed in order, false alarms <10%, and path HTTP p95 <500 ms. Neither scale has a certified cold-run result. The available firewall file is 6,543,120,032 bytes; the separate generated endpoint file is about 1 GB. A target is not marked passed without evidence at the required scale.

## Scope and non-goals

Prioritize detection quality, bounded memory, correlation and understandable evidence. A simple working page/API is sufficient. Polished UI, login/user management, cloud deployment and blocking/stopping attacks are not required. Existing optional access-key support does not make authentication an acceptance gate. Live mode is an optional bonus after the core requirements.

| Requirement | Implementation | Validation / remaining work |
|---|---|---|
| FR-1 streaming input | Bounded binary reads, multiprocessing, Parquet, DuckDB spill and checkpoints | Native processing passed; full supplied-file Docker analysis now passes on resume (196.12 s, 98 reused chunks, 2.63 GiB container peak); cold scan and 50 GB release gate pending |
| FR-2 detection | YAML match, threshold, distinct-threshold and periodic rules; eleven requested behaviors across firewall and endpoint adapters | Positive/negative cases, chunk/file boundaries, timing and endpoint report/evidence integration tested; see DETECTIONS.md. Real ground-truth accuracy unknown |
| FR-3 technique and stage | Official cached ATT&CK ID catalog, tactic and regex validation, five display stages | IDs validated; semantic labels need planted-attack truth |
| FR-4 correlation | Typed entities, temporal union-find, hub cap with joint host/account fallback, created-account linkage, bounded incident span, sequences and suppression | Temporal, hub separation, lateral movement, created-account and overlapping-interval tests; real attack reconstruction unknown |
| FR-5 graph and timeline | NetworkX multigraph, IP/host/account nodes, ordered timeline, stage regression flags | API integration verified; browser visual QA blocked by computer-use URL detection |
| FR-6 reachable next | Observed successful access facts with evidence and timestamps | Historical-access evidence only; permission/asset inventory absent |
| FR-7 API/page/docs | FastAPI, static dashboard, nginx and Compose | Docker build, healthy startup, nginx/API routing and all 95 container tests verified |
| B-1 risk | Deterministic weighted score and descending priority | Implemented, heuristic requires operational calibration |
| B-2 report | Templates using stored event facts | Implemented and tested |
| B-3 counts | Contributing matching-event count and reduced detection count shown separately | Threshold counts tested across files/chunks |
| B-4 config | Mounted YAML; changed rules invalidate extraction checkpoints | Validation tests pass; rescan required |
| B-5 live mode | Deferred | Optional in PRD; needs persistent incremental candidate state and bounded incident rebuilds |

## Required before a production claim

1. Supply planted-attack ground truth and any additional source formats; document and adapt the actual schema.
2. Tune rules, correlation and suppression against that truth. Check missing steps, incorrect labels, order, merged/split attacks and extra unrelated steps. Joint host/account fallback addresses the old global-hub singleton behavior; its effect on the generated EDR input and real path accuracy still needs validation.
3. Run Compose from a clean checkout and verify non-root volume ownership, health, proxy, all tests and failure recovery.
4. Run a cold scan of representative 15 GB input on the intended laptop without exhausting memory, then real 50 GB input: under one hour and under 8 GB total cgroup peak. Retain hardware, Docker stats and OOMKilled evidence. Reusing extraction checkpoints does not satisfy cold-run acceptance.
5. Measure p95 path latency through nginx across every active incident; target under 500 ms.
6. Verify that an analyst can understand representative incidents within a minute using the timeline, graph, report and evidence. Visual polish is not required.
7. Supply an asset/account permission inventory and validate reachable-next results. Historical successful access must remain identified as historical evidence, not a claim of current admin rights.

Retention, authentication/TLS and cloud deployment can be considered separately if a shared deployment is later requested. They are outside this PRD's required scope. The shipped port binding is localhost-only.

No missing result is treated as a pass. No accuracy numbers are inferred from synthetic tests or repeated benchmark input.
