# Accuracy evaluation

The evaluator calls the API through nginx, paginates every active incident, loads precomputed paths and measures HTTP p50/p95 latency. It reports exact and parent-technique label accuracy separately. Missing truth is unverified, never 100% or PASS.

Expected ground truth:

```json
{
  "attacks": [
    {
      "id": "attack-1",
      "steps": [
        {"file": "fortigate.log", "offset": 0, "technique": "T1110.001"},
        {"file": "fortigate.log", "offset": 6543, "technique": "T1078"}
      ]
    }
  ]
}
```

Offsets are exact binary byte offsets in the mounted unmodified source files. The array order is the planted attack order. Use unique filenames or include a relative path suffix; repeated basenames can make a basename-only reference ambiguous. This is an explicit input contract, not an assertion that the unavailable original truth uses this schema. Adapt the original truth before reporting accuracy.

`/evidence` resolves every contributing line of an aggregate detection to its reduced alert, not just the representative first line. A step is found when its line is attached to an active incident. A label is correct only on an exact technique match; parent matches are reported separately. A path passes when all planted steps are exactly labeled, occur in the same incident, and appear in strictly increasing timeline positions. Multiple supplied steps representing one aggregate detection therefore cannot establish separate ordered path edges: ground truth should represent distinct attack steps, not every repeated failure line.

False-alarm rate is the proportion of active incidents matching no planted step. This assumes the truth exhaustively labels the attacks in the dataset. It does not prove that every extra step in a matched incident is correct; inspect the per-attack breakdown and graph manually. Duplicate findings are not silently counted as separate ground-truth attacks.

Great targets require detection >90%, exact labels >85%, all planted paths, false alarms <10%, measured processing <1 hour on at least 50,000,000,000 bytes, cgroup peak <8,000,000,000 bytes and HTTP path p95 <500 ms. Retain raw metrics, Docker OOMKilled evidence and benchmark provenance. An absent memory value, absent truth or smaller dataset cannot pass the release gate.

The available 6.54 GB log file has no supplied planted-attack labels. Real detection accuracy, label accuracy, path accuracy and false alarms remain unknown. Synthetic unit tests validate mechanics only.
