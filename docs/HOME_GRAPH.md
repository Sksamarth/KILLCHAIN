# Home-page attack activity overview

The home page now shows one graph across the selected dataset's incidents, above the kill-chain stage summary. It is independent of the incident table's top-100 overview list and its text search. Use the graph's own Active/Suppressed/All scope, stage selector and Find box. Find centers and zooms to a displayed host, account or IP.

## Nodes, edges and interactive panel

Nodes represent account identities, named hosts and IP endpoints. Private IPs are placed with asset identities; names and IP addresses remain separate identities because no inventory proves they represent the same machine. A selected node opens technique IDs/names/tactics, detection and matching-event counts, asset identities linked, impact signals, provider-report counts, first/last timestamps, up to 12 related incidents and the first eight source evidence references. Incident links open the existing detailed incident graph.

Edges are grouped source/host, host/destination, account/host and hostless-network associations. With no hostname, an account associates with the destination or source IP recorded in its event. They do not establish causality or successful lateral movement. Select or hover a connection to see its count; selection highlights its neighborhood and opens the detail panel. Details use the same scoped alert set as the graph so counts match.

**Impact signals** means detections mapped to the Impact tactic, including unverified provider annotations. It does not mean confirmed exploitation, confirmed data loss, or damage. **Remaining unaffected** and **Confirmed exploited** are explicitly unknown: these need a complete asset inventory and independently adjudicated evidence. Asset identity counts are not physical-machine counts; IP/name aliases are not silently deduplicated.

## Animation and navigation

**Animate activity** enables moving dashed associations and node pulses; **Pause animation** stops them. It is illustrative association flow, not a timestamp replay or proof that an attack moved along a connection. Animation starts off, stops when leaving the home graph and respects reduced-motion preferences. Zoom, pan, Fit, Clear and fullscreen are supported. Keyboard Enter/Space selects focused nodes and links; +/− and arrows manipulate the focused canvas; Home fits it. The graph remains entirely local apart from requests to the local analysis API; it makes no AI-provider calls.

## Scale and verification

`GET /api/overview/graph` aggregates reduced detections and memberships directly in DuckDB; it does not deserialize every incident graph. Totals cover the entire selected incident scope. The drawing includes up to 600 entities and 1,500 associations, with explicit drawn/total counts and a cap notice if needed. Responses are cached in the browser by scan/publication generation and query (32 entries maximum). Node/edge evidence queries are fetched on demand. This can take seconds on first load and shares the database lock; it is not an uninterrupted-query architecture.

The deployed dataset at verification had 295 active incidents, 1,003 reduced detections, 1,040,109 matching events, 98 asset identities, 258 accounts and zero Impact-tactic detections. All 479 entities and 453 associations were included without drawing truncation. The summary request took about 3.13 seconds in one native HTTP measurement; layout/SVG generation took about 115 ms in Node and produced about 672 KB of SVG. These are single-run measurements, not browser frame-rate or API p95 claims. An edge with 216 detections returned exactly 216 detections in its evidence panel. Results are in [home-graph-validation.json](home-graph-validation.json).

Tests cover API scope, counts, typed entities, hostless network data, stage filters, empty data, authentication, parameter validation, source offsets, safe escaping, summary rendering, click-detail loading and animation toggling. Run `pytest -q tests/test_overview_graph.py` and `node --test tests/test_overview_graph.cjs tests/test_graph.cjs`. Browser visual inspection of this new home map has not been completed; prior incident-graph browser checks apply only to that separate view.
