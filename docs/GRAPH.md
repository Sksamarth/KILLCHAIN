# Incident evidence explorer

Open an incident at http://localhost:8080. The evidence map groups repeated connections instead of drawing one overlapping line per detection. Endpoint and account cards have separate identities. Hostnames appear as assets/hosts rather than being classified as external IPs. Node rows use stable label ordering within their type.

## Interaction

- Scroll over the canvas or use + / − to zoom; drag empty canvas to pan. **Fit** restores the complete drawing.
- Select an entity or link for detection counts, matching-event counts, incoming/outgoing grouped links, technique frequencies, first/last observation, activity span and the first five source evidence references.
- Selection highlights matching visible timeline entries. Selecting a timeline detection selects its grouped observed connection when that connection is drawn.
- The stage selector and time slider recalculate the graph and metrics locally from the full incident, independently of the timeline's 120/1,000-row display limit.
- Historical-access links are off by default and shown separately when enabled. They do not increase observed detection/link metrics or establish current permissions.
- **Expand** enters fullscreen; Escape returns. **Save SVG** downloads the filtered graph as a standalone vector image. Existing Export evidence still downloads full incident JSON.
- Keyboard: tab to nodes/links and press Enter/Space to inspect; focus the SVG for +/−, arrow-key pan, Home to fit and Escape to clear selection.

## What the numbers mean

Endpoints and accounts count unique observed identities in the filter. Observed links count unique directed endpoint relationships and account associations; each type is separate. Link labels count reduced detections, not original records or attack steps. Matching events sums detection counts and can overlap when one raw record matches several rules. Duration is the span from the earliest included detection timestamp to the latest included detection end time. It does not establish how long an attacker was active.

Metrics cover all filtered incident evidence. Rendering is bounded at 100 entities and 180 grouped links, with explicit drawn/total counts. A drawing limit does not imply all connections are visible; use filters and JSON export to investigate omitted entities. Edge color represents the most frequent display stage among grouped detections. Observed relationships are associations in detected events, not proof of causality.

## Verification

Six Node tests cover full-timeline counts, aggregation, time/stage filters, historical-access exclusion, render limits, safe escaping, empty incidents and self-connections. Run `node --test tests/test_graph.cjs`.

The real 1,369-detection incident generated 5 entity cards and 4 grouped links with a 38-second observation span. Model construction plus initial HTML generation took about 40 ms in one native Node run; this is not browser paint time or API p95. Initial graph plus controls was about 10 KB of markup. Native Chrome checks verified rendering, node inspection and time filtering (634 detections / 18 seconds at the tested cutoff). Existing dashboard/search VM checks also pass. No detection, correlation, risk, source evidence or AI-provider behavior changes are included.
