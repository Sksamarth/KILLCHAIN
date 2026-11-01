# Validation engine audit

The validation engine is working for the tested cases. This is distinct from the detector meeting its accuracy targets: the authored legitimate-backup case still fails the incident false-alarm requirement.

## Official seven-metric scorecard

The evaluator now grades both **Good** and **Great** using the exact hackathon boundaries. The JSON report contains seven measured values and separate PASS / FAIL / UNVERIFIED grades, with reasons for missing evidence. `--tier-gb` explicitly selects the full chosen tier; the default remains 50 GB. A small fixture or resumed scan cannot establish processing or memory compliance. Stage accuracy remains a supplemental FR-3 check, and expected-stage errors still invalidate an attack path.

The latest synthetic audit still fails **both** false-alarm targets: 1 of 3 incidents is benign (33.33%, against <30% / <10%). Detection, exact labels and paths pass on that fixture only. Real accuracy needs independent planted-attack truth; 50 GB time and memory need a measured cold run. The evaluator does not replace these missing facts with AI judgments or throughput extrapolation.

## Checks and fixes

The audit added expected kill-chain-stage scoring, explicit stage coverage, strict extra/duplicate-step checks for exhaustive truth, known-benign contamination checks, unique source-path resolution and validation of malformed manifests. Missing stages are unmeasured rather than implicitly correct. Missing/invalid measurements, resumed runs and synthetic truth cannot certify a real-data release pass. Expected display stages are authored separately from runtime detection YAML.

Fault-injection checks reject missing steps, incorrect techniques (including parent-only matches), incorrect stages, reversed order, split/merged attacks, extra/duplicate steps and benign findings inside real paths. Controls verify exact false-incident denominators, aggregate evidence whose contributing line is in another file, empty results, ambiguous basenames, malformed/contradictory truth, and every release threshold boundary. A hypothetical complete unit fixture passes the gate; it is never presented as a measured benchmark.

Latest verification: **201 tests passed natively and in the rebuilt Docker evaluator**, including **82 focused evaluator, scenario and rubric checks**. The native and Docker HTTP audits also pass all four scorecard consistency checks. Evidence: [native scorecard audit](rubric-engine-audit-native.json), [Docker scorecard audit](rubric-engine-audit-docker.json). The existing Starlette/httpx deprecation warning remains. No AI call participates in truth, scoring or the audit.

## Real HTTP audit

`python -m backend.validation_audit --output tmp/validation-engine-audit` generated a small synthetic fixture in a separate DuckDB database, started a temporary localhost-only FastAPI server, invoked the ordinary evaluation CLI over real HTTP, compared it with direct database scoring and shut the temporary server down. Both native and Docker runs agreed on all 11 checked metrics. The fixture has 80 background-process records plus extra benign flow/backup records; it is not a production accuracy or performance benchmark.

| Metric | Direct scoring | HTTP evaluator |
|---|---:|---:|
| Detection | 100% | 100% |
| Exact technique labels | 100% | 100% |
| Kill-chain stages / coverage | 100% / 100% | 100% / 100% |
| Ordered, exact planted paths | 2/2 | 2/2 |
| False incidents | 1/3 (33.33%) | 1/3 (33.33%) |
| Known-benign incidents | 1 | 1 |
| Unmatched detections | 2 | 2 |

The two unmatched findings are the legitimate archive and backup transfer. The **engine audit passes** because the independent execution routes agree and report the failures correctly. The **scenario accuracy gate fails** because 33.33% exceeds the <10% incident false-alarm target. The **release gate fails/unverified** because accuracy and real 50 GB cold-run evidence are not satisfied. The normal evaluator returns exit 1 in this case; the audit runner returns exit 0 when its consistency checks pass.

The larger authored scenario reruns (seeds 701 and 809, 2,202 benign records each) also found all 12 expected steps with correct techniques and stages, reconstructed both planted paths and exposed the same false incident. Seed variation changes background records, not the attack families; this is not an independent attack-family holdout.

Evidence: [native HTTP audit](validation-engine-audit-native.json), [Docker HTTP audit](validation-engine-audit-docker.json), [missing-truth check](validation-missing-truth-check.json), [scenario reruns](scenario-validation-results.json).

## Real dataset status

No independent ground-truth manifest was found under the mounted data folder. The normal Docker evaluation service returned `great_gate: UNVERIFIED`, `accuracy_status: NOT MEASURED: no ground truth supplied`, and exit 2 before traversing the API. Real detection/label/path accuracy and false alarms remain unknown. The live dashboard database was not replaced by any test run.

Evaluation assumptions and remaining limitations are documented in [EVALUATION.md](EVALUATION.md). Exhaustive truth and provenance declarations require review. The evaluator still retains active paths in memory, and large benign manifests require many individual HTTP evidence requests. Passing these engine checks does not establish 15/50 GB scalability, production readiness, or independent real-data accuracy.
