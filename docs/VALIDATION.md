# Validation evidence

Implementation machine: native Windows, Python 3.14.3, Node 24.14.1. Docker CLI/daemon are unavailable. Disk type was not verified. Dates follow the user's Asia/Calcutta timezone; work started 31 October and continued 1 November 2026.

## Completed checks

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
| Full pipeline | See full-run-results.json when present | Restarted from checkpoints after optimization; not a cold-run throughput claim |

The initial full-data aggregation exposed an expensive evidence join and wide candidate materialization. Those attempts were stopped, their extraction checkpoints retained, and the implementation changed to direct exact-match evidence, Parquet column projection, prefiltered threshold groups and batched result writes. This history is not omitted from the performance assessment. Resumed processing time cannot be represented as cold end-to-end throughput.

## Unverified release targets

| PRD Great target | Status |
|---|---|
| Detection >90% | Unmeasured: no planted-attack labels supplied |
| Exact technique labels >85% | Unmeasured: no planted-attack labels supplied |
| All attack paths correct | Unmeasured: no planted-attack labels supplied |
| False alarms <10% | Unmeasured; prefix produced many noisy incidents |
| Real 50 GB in <1 hour | Unverified: only 6.54 GB supplied; no completed cold 50 GB run |
| Peak memory <8 GB | No Docker cgroup / stats / OOMKilled evidence |
| Path p95 <500 ms | Prefix local sample passes; all-incident Docker/nginx gate unverified |

No 50 GB synthetic benchmark has been executed. No Docker test/build/health/proxy claim has been made. Optional live mode and AI triage remain deferred. Browser visual QA was attempted, but computer use stopped because it could not reliably determine Chrome's current URL; no screenshot-based UI pass is claimed.

The user identified `data/firex-10G.log` when asked for ground truth. It is the same raw-event input, not an independent planted-attack answer key, so accuracy remains unmeasured.
