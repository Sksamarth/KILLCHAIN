# Accuracy evaluation

Ground truth must be independent of the detector and provider annotations. Copying reported ATT&CK tags into truth is circular validation. Missing truth now exits before API traversal; attack IDs must be unique.

An incident containing matched steps from multiple independent planted attacks fails reconstruction for each affected attack. `merged_incidents` reports this failure separately. Each truth attack should describe one expected incident. Set `exhaustive_steps: true` only when the manifest lists every expected reduced detection/step. Then extra or duplicate detections inside a matched incident also fail reconstruction. Without this declaration, extra steps are reported but exact membership remains unchecked. Known-benign references inside a planted incident always fail its reconstruction.

The evaluator calls the API through nginx, paginates every active incident, loads precomputed paths and measures HTTP p50/p95 latency. It reports exact and parent-technique label accuracy separately. Missing truth is unverified, never 100% or PASS.

Expected ground truth:

```json
{
  "synthetic": false,
  "exhaustive_steps": true,
  "attacks": [
    {
      "id": "attack-1",
      "steps": [
        {"file": "fortigate.log", "offset": 0, "technique": "T1110.001", "stage": 0},
        {"file": "fortigate.log", "offset": 6543, "technique": "T1078", "stage": 0}
      ]
    }
  ]
}
```

Offsets are exact binary byte offsets in the mounted unmodified source files. The array order is the planted attack order. Use unique filenames or include a relative path suffix; ambiguous references to repeated basenames are rejected. Absolute paths must match the actual source path; relative references match a complete path suffix. Windows separators are normalized. This is an explicit input contract, not an assertion that the unavailable original truth uses this schema. Adapt the original truth before reporting accuracy. IDs must be unique, references valid, and steps nonduplicated; a line cannot simultaneously be marked a planted step and known benign.

Optional `benign: [{"file":"fortigate.log","offset":123,"case":"authorized_backup"}]` references let the evaluator detect contamination inside an otherwise real attack path. For large benign manifests the HTTP evaluator makes one evidence request per referenced line; the local scenario runner resolves these through DuckDB instead. Evaluation currently retains active paths in memory; this is not a bounded-memory certification of the evaluator on arbitrary incident volumes.

Expected `stage` values are 0 Initial Attempts, 1 Persistent Foothold, 2 Exploration, 3 Propagation, 4 Exfiltration & Impact. `stages` reports correctness among found steps with expected stages; `stage_coverage` reports how much of the manifest has stage expectations. Missing expected stages are unmeasured, not implicitly correct. These are the project's five display stages, not the seven-stage Lockheed Martin taxonomy.

`/evidence` resolves every contributing line of an aggregate detection to its reduced alert, not just the representative first line. A step is found when its line is attached to an active incident. A label is correct only on an exact technique match; parent matches are reported separately. A path passes when all planted steps are exactly labeled, occur in the same incident, and appear in strictly increasing timeline positions. Multiple supplied steps representing one aggregate detection therefore cannot establish separate ordered path edges: ground truth should represent distinct attack steps, not every repeated failure line.

False-alarm rate is the proportion of active incidents matching no planted step. This assumes the truth exhaustively labels the attacks in the dataset. Mixed true/benign incidents are additionally identified with `known_benign_incidents`; `unmatched_detections` counts findings that could not be assigned to a supplied step. Inspect the per-attack membership flags rather than interpreting the incident false-alarm rate as a per-event false-positive rate.

The evaluator emits `rubric.metrics` with all seven official metrics, each with a measured value, units, Good/Great targets, `PASS`, `FAIL` or `UNVERIFIED`, and a reason when evidence is missing. `overall_good` and `overall_great` fail if a measured requirement fails; otherwise they remain unverified until all evidence is available. Synthetic scenarios can show measured accuracy grades but cannot certify the real dataset. `great_gate` mirrors `overall_great` for existing consumers.

| Metric | Good | Great |
|---|---|---|
| Detection | >70% | >90% |
| Exact ATT&CK labels among found steps | >60% | >85% |
| Exact ordered planted paths | >=50% | 100% |
| False incidents / all active incidents | <30% | <10% |
| Full-tier cold processing | <10,800 seconds | <3,600 seconds |
| Processing cgroup peak | <16,000,000,000 bytes | <8,000,000,000 bytes |
| Incident-path HTTP p95 | <2,000 ms | <500 ms |

Bounds are strict where the rubric says over/under. Decimal GB are used. The default chosen tier remains Extreme 50 GB; explicitly choose another tier with `--tier-gb 15`. Processing and memory remain unverified for smaller or checkpoint-resumed runs; there is no extrapolated pass. Sampled parent/child RSS does not substitute for the processing cgroup peak. HTTP p95 covers the active paths requested during this evaluation, not an assumed cold-cache benchmark.

Example after scanning the full chosen dataset:

```powershell
docker compose --profile tools run --rm --no-deps evaluate python -m backend.evaluate --truth /data/ground_truth/attacks.json --tier-gb 50
```

Stage correctness and stage-truth coverage remain supplemental FR-3 checks, rather than adding an eighth official metric. When expected stages are supplied, incorrect stages still fail the corresponding path. Exact path membership requires `exhaustive_steps: true`. Missing/invalid numbers, zero processing time/memory and missing truth are unverified. Retain raw metrics, Docker OOMKilled evidence and benchmark provenance. A manifest's independence, completeness and correspondence to the scanned files require review; its declarations are not evidence by themselves.

## Auditing the validation engine

Run `python -m backend.validation_audit --output tmp/validation-engine-audit`. This generates synthetic scenarios in an isolated database, starts a temporary localhost-only API against that database, runs the ordinary HTTP evaluator as a subprocess, compares its metrics to direct database scoring, and shuts the API down. It disables AI and API tokens only in that temporary child process. It never replaces the dashboard dataset. Audit exit 0 means the evaluator agrees across both paths, even when the detector's accuracy gate and the release gate correctly fail. Evaluation CLI exit 1 means failed/unverified release requirements; exit 2 means missing ground truth.

The available 6.54 GB log file has no supplied planted-attack labels. Real detection accuracy, label accuracy, path accuracy and false alarms remain unknown. Synthetic unit tests validate mechanics only.
