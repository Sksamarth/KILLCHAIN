# Correlation changes and verification

The correlator retains rare host, account and IP links across source/destination roles. Busy entities additionally use joint host/account context, or host/source and account/source when one identity is absent. Created accounts share the account namespace with later account use. Explicit stoplists still apply. This groups evidence by context; it does not assert causality or invent missing attack steps.

`rules/correlate.yaml` enables compound context and bounds incident duration to four hours, with a one-hour maximum gap. Tune these values against independent planted-attack truth. A campaign longer than the configured span can split across incidents. Correlation retains all reduced alerts and source evidence. Overlapping aggregate detections use the longest-reaching interval rather than losing a link behind a shorter event.

Verification: 105 tests passed locally and in the rebuilt Docker backend, including busy-entity separation, lateral movement, created-account use, event ordering, overlapping aggregates, idle gaps, stoplists and bounded continuous activity. The existing Starlette/httpx deprecation warning remains.

The generated `killchain_security_logs.jsonl` file was reprocessed through the nginx API: 1,591,447 records, 317,529 provider-reported simulated alerts, 15 reused extraction checkpoints, 24.55 seconds total and 22.79 seconds correlation. Container peak was 1,411,735,552 bytes; container tests ran concurrently, so this is not an isolated benchmark. This was a resumed run, not cold throughput or a 15/50 GB scale pass.

The result now has 224 active context groups instead of the historical 62,970 active and 254,559 suppressed singletons. This is a change in grouping, not evidence of better attack accuracy. The generator randomly assigns alerts to 28 hosts and eight users within about 38 seconds and supplies no independent campaign membership. Those 224 groups must not be called reconstructed planted attacks.

All 224 groups reach the existing risk-score cap because it sums many alert weights. Risk calibration remains open; repeated provider reports should not automatically establish critical incident confidence. Three sampled paths retained 1,369–1,460 ordered detections each and returned through nginx in 313–432 ms, including client decoding. This sample is not a p95 measurement across all incidents. Raw results: [correlation-validation.json](correlation-validation.json).

Next acceptance work is independent ground truth: measure missing steps, labels, path membership/order, merged/split attacks and false alarms, then tune grouping and risk. Historical successful access still does not establish current permissions.
