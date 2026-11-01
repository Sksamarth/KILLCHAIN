# Final AI analysis

After a scan started from the dashboard completes, the home page automatically requests a final report if Gemini is configured. You can also use **Generate report** and **Download report** in the Final AI analysis panel. A page refresh requires Generate report again; validated provider responses are cached on the server.

The report contains an executive summary, evidence-linked findings, benign alternatives, prioritized investigation steps and limitations. It samples up to eight highest-risk active incidents and at most 24 detections. This is not an exhaustive review of the dataset. A selected incident may have only its first, middle and final detection reviewed; the report states the sample size.

`POST /api/ai/final-report` (through nginx) or `POST /ai/final-report` directly on the backend returns structured JSON. It requires completed scan statistics, active detection evidence and GEMINI_API_KEY. Running scans return 409; missing evidence returns 422; missing configuration returns 503. Provider quota/invalid responses are visible failures, not fabricated reports.

Only pseudonymized detection metadata, counts and numeric scan statistics leave the machine, capped at 12,000 bytes. Original IPs, account names, incident IDs, source paths, commands and raw logs stay local. Local evidence references link the response back to the original incident/alert. Entity aliases are scoped per incident and must not be interpreted as cross-incident matches. Google free-tier content may be used to improve products.

The existing local limit of ten uncached attempts per UTC day is shared with incident AI reviews. Failures count; validated cached reports avoid another provider request. There are no automatic retries or model fallbacks. AI output cannot change detections, suppression, risk scores, ground truth or the seven-metric scorecard. Its report explicitly labels real-data accuracy unverified because the endpoint is not supplied independent truth.

Verification: 205 Python tests and 13 Node tests passed locally, including final-report packet privacy, sampling bounds, schema validation, caching, scan-state handling, escaped rendering, stale responses and one automatic request on scan completion. Browser visual inspection has not been performed for this new panel.
