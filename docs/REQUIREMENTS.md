# PRD coverage and release checklist

Reference: supplied three-page PRD dated 30 October 2026. The implementation targets its Extreme 50 GB tier, but available input is 6,543,120,032 bytes. A target is not marked passed without evidence at the required scale.

| Requirement | Implementation | Validation / remaining work |
|---|---|---|
| FR-1 streaming input | Bounded binary reads, multiprocessing, Parquet, DuckDB spill and checkpoints | Cross-boundary tests pass; 50 GB and Docker measurements pending |
| FR-2 detection | YAML match, threshold and distinct-threshold rules | Synthetic correctness tests pass; real ground-truth accuracy unknown |
| FR-3 technique and stage | Official cached ATT&CK ID catalog, tactic and regex validation, five display stages | IDs validated; semantic labels need planted-attack truth |
| FR-4 correlation | Typed entities, temporal union-find, hub cap, sequences, suppression | Synthetic temporal, hub and sequence tests; real attack reconstruction unknown |
| FR-5 graph and timeline | NetworkX multigraph, IP/host/account nodes, ordered timeline, stage regression flags | API integration verified; browser visual QA blocked by computer-use URL detection |
| FR-6 reachable next | Observed successful access facts with evidence and timestamps | Historical-access evidence only; permission/asset inventory absent |
| FR-7 API/page/docs | FastAPI, static dashboard, nginx and Compose | Native smoke tests; Docker unavailable on build machine |
| B-1 risk | Deterministic weighted score and descending priority | Implemented, heuristic requires operational calibration |
| B-2 report | Templates using stored event facts | Implemented and tested |
| B-3 counts | Contributing matching-event count and reduced detection count shown separately | Threshold counts tested across files/chunks |
| B-4 config | Mounted YAML; changed rules invalidate extraction checkpoints | Validation tests pass; rescan required |
| B-5 live mode | Deferred | Optional in PRD; needs persistent incremental candidate state and bounded incident rebuilds |

## Required before a production claim

1. Supply planted-attack ground truth and any additional source formats; document and adapt the actual schema.
2. Tune rules and suppression against that truth. Review the high incident volume observed in the prefix sample.
3. Run Compose from a clean checkout and verify non-root volume ownership, health, proxy, all tests and failure recovery.
4. Run real 50 GB input: under one hour and under 8 GB total cgroup peak; retain Docker stats and OOMKilled evidence.
5. Measure p95 path latency through nginx across every active incident; target under 500 ms.
6. Verify UI in a browser at desktop/mobile widths with empty, suppressed, large and failed-scan states.
7. Set disk retention, authentication/TLS and deployment controls for the intended environment. The shipped port binding is localhost-only.

No missing result is treated as a pass. No accuracy numbers are inferred from synthetic tests or repeated benchmark input.
