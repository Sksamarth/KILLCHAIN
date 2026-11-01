# Optional AI review and independent validation

Gemini review is an optional second opinion on an incident. It never modifies rules, correlations, labels, risk, suppression or accuracy metrics. The original deterministic report remains available when the provider fails or no key is configured. A live review and cached repeat have now passed: 4,355 bytes of pseudonymized metadata, schema-validated output and valid evidence citations. This does not certify the model's conclusions or detection accuracy. See [ai-live-validation.json](ai-live-validation.json).

## Configure a free-tier key

Create your own key in [Google AI Studio](https://aistudio.google.com/apikey), using a free-tier project without enabling paid billing. Save these settings in the ignored local `.env` file; never paste keys into source code or the dashboard's Access key field:

```dotenv
GEMINI_API_KEY=your_private_key_here
GEMINI_MODEL=gemini-3.5-flash-lite
```

Then run `docker compose up --build -d backend`. Open an incident and select **Review with Gemini**. `/api/ai/status` reports configuration without returning credentials. This key is separate from the optional `API_TOKEN` used to restrict access to the local analysis API.

The default model has a free-tier entry on [Google's pricing page](https://ai.google.dev/gemini-api/docs/pricing); availability, limits and terms are controlled by Google and can change. The application cannot determine whether your Google project has billing enabled, so it cannot guarantee zero charges for a billed project. There is no paid fallback, automatic retry, bulk review, or automatic AI call during a scan. Ten uncached attempts per UTC day are permitted locally; valid reviews are cached by model and metadata digest. Failed attempts also consume that limit.

## What leaves the machine

The user authorized small pseudonymized detection metadata. Each request includes at most 24 sampled detections and at most 12,000 bytes of detection metadata. Requests above that bound are rejected before network access. Evidence sampling covers rule diversity plus the timeline; truncation and total/sample counts are explicit. Fields include technique/rule IDs, anonymous entity/account labels, internal/external classifications, relative times, provider-annotation status and matching-event counts. No raw source lines, source paths, original addresses, names, commands or free-text log descriptions are sent. The citation map between `e1` etc. and alert IDs remains local.

Google's free-tier pricing states that content may be used to improve its products. Pseudonymization reduces identifying content; it does not remove all sensitivity from detection patterns. The fixed provider destination is Google's HTTPS Gemini generateContent endpoint. The API key travels in a header, not a URL. Errors do not expose provider response bodies or credentials.

The output must match a validated schema and cite only supplied evidence IDs in every finding. A valid citation does not prove that a conclusion is true. AI assessments such as `possibly_benign` are suggestions, not adjudicated false positives. No model is permitted to establish ground truth or infer current permissions.

## Local false-positive validation

Run `python -m backend.validation --output tmp/validation-701 --seed 701`. It writes an authored, deterministic JSONL dataset and an independent `truth.json` **before** scanning, then uses the ordinary parser, YAML rules, aggregation, correlation and evaluator in a separate DuckDB database. It never replaces dashboard results or edits the user's generators.

The two campaigns exercise all eleven requested behavior families. Background commands include benign lookalikes and repeated single-port flows. A contextual hard negative models a legitimate archive and large backup transfer. That legitimate business purpose exists in ground truth; it is deliberately not secretly added to detector allowlists.

Initial seed 701: detection 100%, exact technique labels 100%, both ordered paths rebuilt, no merged attacks, but **one of three active incidents is a false alarm (33.33%)**. Two of 2,202 benign records contributed to that incident (0.091%). These are different denominators; the low event-level percentage does not satisfy the incident-level false-alarm target. The accuracy gate correctly fails. This is small synthetic validation, not a real-data accuracy claim or 15/50 GB release pass.

Seed 809 varied the background telemetry and reproduced the same metrics; it is not an independent attack-family holdout. Results for both runs are retained in [scenario-validation-results.json](scenario-validation-results.json). All 119 local and container tests passed; mocked provider tests cover caching, citation checks, malformed output, timeout, quota, payload limits, redaction and API behavior. Ten focused tests passed after switching the default model to Gemini 3.5 Flash-Lite. The former 2.5 Flash-Lite model was rejected by Google for new users; 3.5 Flash-Lite succeeded with the configured credential. The key remains only in ignored local configuration and the backend environment.

Next work is environment-supported backup/administration context and independently reviewed validation cases, without globally excluding archive creation or large outbound traffic. Hold out additional scenarios before tuning. AI can suggest which context to investigate; measured metrics continue to come from truth and raw evidence, not AI verdicts.
