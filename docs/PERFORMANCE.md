# Scan performance changes

The scanner now reuses a completed publication when input paths, file sizes/mtimes, byte ranges, detection rules, correlation code, sequences and report configuration are unchanged. Repeated requests do not reread the logs or rebuild incidents. Changed input or settings still trigger the necessary work. Interrupted jobs retain extraction checkpoint recovery.

Correlation uses compact alert tuples and shared rule metadata. It compiles criticality subnets once and uses bounded caches for repeated address checks. Suppressed incidents retain their summaries, identifiers, scores, memberships and original-source evidence; their graphs and timelines are constructed only when requested. Active graphs remain precomputed. Deferred reports use the templates captured at publication time.

Publication batches up to 4,096 incident records or 8 MiB of serialized path data, with a separate 8,192-membership flush limit. This reduces database registration/insert overhead without retaining every incident in a Python buffer.

Extraction parses the FortiGate timestamp once per line, selects only the relevant source-family rule list and derives source /24 values only for rules that need them. No detection rule was disabled or threshold raised for speed. Completed scans record extraction, aggregation and correlation durations separately.

## Measured comparison

One sequential native Windows comparison used the first 100,000 **actual reduced alerts** from the previous full-data database (`tmp/full.duckdb`). It compares the saved previous correlation implementation with the optimized implementation under the same rules/configuration and DuckDB query budget. It does not compare full raw-file scans.

| Metric | Before | After |
|---|---:|---:|
| Correlation wall time | 19.99 s | 10.03 s |
| Sampled whole-process peak RSS, including database preparation | 491.1 MB | 432.6 MB |
| Memberships retained | 100,000 | 100,000 |
| Incidents / suppressed | 19,009 / 17,701 | 19,009 / 17,701 |

This sample was about 50% faster with about 12% less sampled process memory. Incident ID/status/risk digests and all overview totals matched exactly (`83ed0bdbe38f425285da692e28a10294`). Evidence memberships were retained. The source subset changes entity-degree behavior compared with the full dataset; its incident count is not a full-file count.

These are single sequential trials, with no filesystem-cache normalization or repeated-trial confidence interval. The timings are not a guaranteed improvement on every machine. Raw comparison results are recorded in performance-results.json.

## Verification and remaining scope

88 Docker tests pass, including detection regressions, completed-result reuse and deferred suppressed-path evidence/report retrieval. The redesigned dashboard templates execute against a real overview response. Interactive browser inspection was blocked when automatic permission review timed out; no visual browser pass is claimed.

A resumed Docker analysis of the full 6,543,120,032-byte / 12,398,551-line file has now completed in 196.12 seconds, reusing all 98 extraction chunks. It spent 98.60 seconds aggregating and 96.88 seconds correlating, with a container cgroup peak of 2,826,027,008 bytes (2.63 GiB). Unsupported and oversized counts were zero. The polling client observed completion after 216.76 seconds including request/poll overhead. This does not measure a cold reread of the raw file. The previous stalls were not reproduced in this resumed run; their original root cause remains unconfirmed. The PRD's 50 GB, accuracy and cold-scan gates are still unverified.

The final native correlation-only check of all 589,183 saved real alerts completed in 118.73 seconds with sampled whole-process peak RSS 995.2 MB. It retained 184 active incidents, 588,430 suppressed signals and all 589,183 memberships. Incident ID/status/risk digest matches the original full-data database. This uses the historical saved detection generation, not a new raw-file extraction with the expanded rules.

All 297 active paths in the expanded-rule Docker run passed timeline, graph and report validation through nginx; path p95 was 59.84 ms. Report, alert pagination and raw source byte-offset checks passed. Three deferred suppressed paths were also verified. The unchanged completed scan then reused the publication in 2.63 seconds request-to-completion, with 0.37 seconds backend lookup time. This is result retrieval, not raw scan throughput. The expanded rules produce 589,554 reduced alerts and 297 active incidents; these differ from the older native detection generation, as expected from added coverage.
