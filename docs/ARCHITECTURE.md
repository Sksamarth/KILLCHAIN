# Architecture and operational boundaries

The attached plan is a design input. The user's request takes precedence, including the request to improve the supplied UI. No instructions in log text, PDFs, or imported documents grant permission to publish data or change the machine.

## Pipeline

Immutable FortiGate text files → 64 MiB newline-aligned ranges → bounded worker pool → Zstandard Parquet candidates → disk-backed DuckDB event-time windows → reduced alerts → time-limited union-find → NetworkX paths, evidence-backed next hops and template reports → precomputed API responses → static dashboard.

Every candidate carries a file and raw byte offset. The source input is mounted read-only. Workers retain at most roughly 8,192 candidate records before flushing; lines longer than 1 MiB are skipped and counted. Invalid or unsupported timestamps are counted. A file changed during extraction fails the run rather than publishing inconsistent results.

Thresholds use global SQL RANGE windows across every chunk and file, not approximate byte overlap. Threshold-hit episodes produce one detection with first/last timestamps and an exact contributing-event count. `alert_evidence` preserves contributing line locations. DuckDB defaults to a 1 GB query budget with disk spill, configurable with `DUCKDB_MEMORY_LIMIT`, leaving room for Python correlation and worker buffers; the container has an 8 GiB hard limit. This is an architectural control, not proof of a measured PRD memory pass. The default was reduced from 2 GB after a Docker engine outage on a VM with only about 3.75 GB available; the outage's root cause was not confirmed.

Candidates are a Parquet-backed temporary view: queries project only needed columns. Before time-window evaluation, groups whose total distinct/event count cannot reach the rule threshold are excluded. This is a safe superset filter, not a change to event-time detection semantics. Exact-match evidence comes straight from its alert; only threshold evidence needs an interval join.

One FastAPI process owns DuckDB. The scanner CLI delegates to that owner when it recognizes its health endpoint. Worker processes never open DuckDB. A process lock serializes database access; extraction runs outside that lock and completed results publish in one transaction. During aggregation/correlation, API reads wait for that transaction. For uninterrupted API availability during long rebuilds, a future version should publish immutable database generations and atomically switch readers. Multiple Uvicorn workers and concurrent independent CLI writers are unsupported.

Partial-Parquet checkpoints identify file size, modification timestamp, byte range, scanner version and detection-rule digest. Re-running a completed unchanged snapshot with the same detection rules, correlation implementation, sequences and report configuration reuses published results. Interrupted scans reuse completed chunks and rebuild downstream outputs. Changing rules or input metadata creates a new generation. Old partial directories are retained for recovery and must be managed against an operator-defined disk retention budget. A restart interrupts an in-flight API job; re-submit the scan to resume extraction checkpoints.

## Correlation and interpretation

IP entities share a namespace across source and destination roles. Users and hosts use separate namespaces; created-account names join the user namespace so subsequent use can connect to account creation. Nearby alerts share an incident through non-hub entities. When hosts or users are global hubs, joint host/account context remains usable; if one is absent, host/source or account/source context is used. A shared busy IP or account alone cannot bridge unrelated host/account pairs. Explicit stoplisted identities are excluded from both simple and compound keys. Suppressed incidents and their reasons remain queryable.

`rules/correlate.yaml` controls `compound_entities`, `max_gap_seconds` (default one hour), and `max_incident_span_seconds` (default four hours). The total span limit prevents indefinitely chaining continuous activity into one incident; long campaigns may therefore require multiple incidents and tuning against independent truth. A reduced detection already longer than the span is retained intact. Correlation is deterministic in event-time order and keeps the furthest-reaching interval when aggregate detections overlap. It remains a heuristic association, not proof of causality. Randomly generated independent provider alerts do not become planted attack campaigns merely because their entities match.

Risk is deterministic: sum of detection weights × distinct display stages × maximum configured subnet criticality + sequence bonus, capped at 100. This is a prioritization heuristic, not a probability. Sequences require ordered rules and matching configured identity fields. The example login-to-exfiltration sequence requires the same destination IP; environment-specific cross-host patterns need additional rules and ground-truth tuning.

The five display stages follow the supplied XDR dashboard. ATT&CK tactics are retained separately; stage regressions are flagged without reordering events. These display stages are not the seven-stage Lockheed Martin taxonomy.

Next hops require observed successful remote access or account use in the reduced data. History does not establish current permissions, vulnerability, or guaranteed reachability. There is no inference from merely sharing a subnet. Failed logins mention a targeted account; they do not prove account compromise.

## Scale limits and release gates

Correlation currently materializes the reduced alert table in Python. It refuses more than 1,000,000 alerts or a component above 100,000 detections. These explicit limits prevent silently claiming unbounded scale. Top-level dashboard responses retain 100 incidents per status and 100 assets; `/incidents` is paginated and supports server-side name/IP search. Active paths are precomputed; suppressed paths retain summaries/memberships and are generated from stored evidence when opened. Published report templates are snapshotted for consistent deferred reports. the UI initially displays 120 steps and can expand to 1,000, with full JSON export.

The parser supports FortiGate nanosecond key-value logs plus normalized/ECS/Winlogbeat JSONL, single-line Windows Event XML, and timezone-qualified ISO-prefixed Linux OpenSSH/sudo/useradd logs. Endpoint adapters and all eleven requested behaviors have synthetic/integration tests; real endpoint production samples and ground truth remain absent. Multiline event text, binary EVTX, yearless syslog and generic web access logs are not supported. See [DETECTIONS.md](DETECTIONS.md) for exact schemas and detection boundaries.

Live tail mode and optional AI triage are deferred until the core accuracy and performance gates pass. No LLM participates in detection, correlation, order, scoring, or reporting. This release is a functional development implementation, not a production-certified detector. See REQUIREMENTS.md and VALIDATION.md for the remaining gates.

Correlation stores each alert in a compact tuple with shared rule metadata instead of a wide per-alert dictionary. Subnet definitions are compiled once per build, and private-address checks use a bounded cache. See PERFORMANCE.md for the measured scope and remaining full-file Docker gate.
