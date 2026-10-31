# Architecture and operational boundaries

The attached plan is a design input. The user's request takes precedence, including the request to improve the supplied UI. No instructions in log text, PDFs, or imported documents grant permission to publish data or change the machine.

## Pipeline

Immutable FortiGate text files → 64 MiB newline-aligned ranges → bounded worker pool → Zstandard Parquet candidates → disk-backed DuckDB event-time windows → reduced alerts → time-limited union-find → NetworkX paths, evidence-backed next hops and template reports → precomputed API responses → static dashboard.

Every candidate carries a file and raw byte offset. The source input is mounted read-only. Workers retain at most roughly 8,192 candidate records before flushing; lines longer than 1 MiB are skipped and counted. Invalid or unsupported timestamps are counted. A file changed during extraction fails the run rather than publishing inconsistent results.

Thresholds use global SQL RANGE windows across every chunk and file, not approximate byte overlap. Threshold-hit episodes produce one detection with first/last timestamps and an exact contributing-event count. `alert_evidence` preserves contributing line locations. Memory is bounded by DuckDB's 2 GB query budget with disk spill plus worker buffers; the container has an 8 GiB hard limit. This is an architectural control, not proof of a measured PRD memory pass.

Candidates are a Parquet-backed temporary view: queries project only needed columns. Before time-window evaluation, groups whose total distinct/event count cannot reach the rule threshold are excluded. This is a safe superset filter, not a change to event-time detection semantics. Exact-match evidence comes straight from its alert; only threshold evidence needs an interval join.

One FastAPI process owns DuckDB. The scanner CLI delegates to that owner when it recognizes its health endpoint. Worker processes never open DuckDB. A process lock serializes database access; extraction runs outside that lock and completed results publish in one transaction. During aggregation/correlation, API reads wait for that transaction. For uninterrupted API availability during long rebuilds, a future version should publish immutable database generations and atomically switch readers. Multiple Uvicorn workers and concurrent independent CLI writers are unsupported.

Partial-Parquet checkpoints identify file size, modification timestamp, byte range, scanner version and detection-rule digest. Re-running an unchanged snapshot reuses completed chunks and rebuilds downstream outputs. Changing rules or input metadata creates a new generation. Old partial directories are retained for recovery and must be managed against an operator-defined disk retention budget. A restart interrupts an in-flight API job; re-submit the scan to resume extraction checkpoints.

## Correlation and interpretation

IP entities share a namespace across source and destination roles. Users and hosts use separate namespaces. Nearby alerts share an incident through non-hub entities; high-degree entities and an explicit stoplist cannot merge everything into one component. Suppressed incidents and their reasons remain queryable.

Risk is deterministic: sum of detection weights × distinct display stages × maximum configured subnet criticality + sequence bonus, capped at 100. This is a prioritization heuristic, not a probability. Sequences require ordered rules and matching configured identity fields. The example login-to-exfiltration sequence requires the same destination IP; environment-specific cross-host patterns need additional rules and ground-truth tuning.

The five display stages follow the supplied XDR dashboard. ATT&CK tactics are retained separately; stage regressions are flagged without reordering events. These display stages are not the seven-stage Lockheed Martin taxonomy.

Next hops require observed successful remote access or account use in the reduced data. History does not establish current permissions, vulnerability, or guaranteed reachability. There is no inference from merely sharing a subnet. Failed logins mention a targeted account; they do not prove account compromise.

## Scale limits and release gates

Correlation currently materializes the reduced alert table in Python. It refuses more than 1,000,000 alerts or a component above 100,000 detections. These explicit limits prevent silently claiming unbounded scale. Top-level dashboard responses retain 100 incidents per status and 100 assets; `/incidents` is paginated and supports server-side name/IP search. Paths are precomputed in full; the UI initially displays 120 steps and can expand to 1,000, with full JSON export.

Only FortiGate key-value text logs with 19-digit nanosecond `eventtime` are supported and tested. Linux auth, Windows event text, and web-access formats need actual samples, parser adapters, rules and separate validation. The available data has not supplied those formats or ground truth.

Live tail mode and optional AI triage are deferred until the core accuracy and performance gates pass. No LLM participates in detection, correlation, order, scoring, or reporting. This release is a functional development implementation, not a production-certified detector. See REQUIREMENTS.md and VALIDATION.md for the remaining gates.
