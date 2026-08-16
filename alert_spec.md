# SentinelMesh Alert Format Spec (updated — reconciles log-tail + Falco)

## Canonical shape

Every alert, regardless of source, has exactly these 7 top-level keys:

```json
{
  "source": "log-tail",
  "scenario": "S1",
  "severity": "CRITICAL",
  "title": "SQL Injection Authentication Bypass",
  "timestamp": "2026-08-04T12:00:00Z",
  "service": "webapp",
  "event": { "...": "raw or lightly-annotated source event" }
}
```

| Field | Type | Notes |
|---|---|---|
| `source` | string | `"falco"` or `"log-tail"` |
| `scenario` | string | `"S1"`–`"S9"` — **this is the one ID format**, used everywhere (scenario table, `ground_truth.json`, both detector types). Earlier drafts used `s01`/lowercase — that's superseded by this. |
| `severity` | string | `"WARNING"` or `"CRITICAL"` — matches Falco's own priority naming so there's one vocabulary, not two |
| `title` | string | human-readable rule name. For S3's unconfirmed fallback case, the title itself carries the caveat (see `scenario3_detector.py`) |
| `timestamp` | ISO8601 string | UTC |
| `service` | string | which app/container the event originated from |
| `event` | object | the raw or lightly-annotated source event — structure varies by scenario, this is expected and fine |

## Reconciling the two sources

- **`log-tail` alerts** (S1–S4, S9's S7 chain stage) already emit exactly this shape natively — see `common.py`'s `emit_alert()`.
- **`falco` alerts** (S5–S8) come out of Falco in Falco's own native JSON format (`rule`, `priority`, `output`, `output_fields`, etc.) — **these need a small translation step** before they match this spec: `rule` → `title`, `priority` → `severity`, `output_fields` → `event`, plus adding `scenario` and `source: "falco"`, which aren't in Falco's native output at all. This translation didn't exist as of the last draft — **needs a small shim** (e.g. via Falcosidekick's output webhook, or a thin wrapper script around Falco's JSON output) before Day 4 integration, so Person 3's harness only ever has to parse one shape.

## Status

- Log-tail detectors (S1–S4): format finalized, tested (`test_detectors.py`, 9/9 passing).
- Falco rules (S5–S8): rule logic is done, but the **output translation shim to this shape is still pending** — flag this to Person 3 now, don't let it surface as a surprise on Day 4.

