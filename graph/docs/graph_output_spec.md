# SentinelMesh Attack-Graph Output Format Specification

**Status:** Frozen  
**Version:** 1.0  
**Module:** C1 — Attack-Graph Reconstruction

---

## Overview

This is the frozen output format for the attack-graph module. All consumers (C2 Risk-Scoring, C3 Evaluation Harness) depend on this exact structure.

> **No breaking changes after freeze.**

---

## Output Structure

```json
{
  "graph_id": "string",
  "nodes": [ ... ],
  "edges": [ ... ],
  "paths": [ ... ]
}
```

### Top-Level Fields

| Field | Type | Description |
|---|---|---|
| `graph_id` | string | Unique ID (run_id + timestamp + random suffix) |
| `nodes` | array | All graph nodes |
| `edges` | array | All inferred edges |
| `paths` | array | Reconstructed attack paths |

---

## Node Schema

```json
{
  "id": "string (unique node ID)",
  "type": "container | process | network_connection | technique | cve",
  "label": "string (human-readable)",
  "properties": { }
}
```

### Node Types

| Type | Source | ID Pattern | Example |
|---|---|---|---|
| `container` | Docker metadata | `container_{service}` | `container_webapp` |
| `process` | Falco `proc.name` | `process_{service}_{name}` | `process_webapp_cat` |
| `network_connection` | Falco `fd.rip` | `network_{ip}:{port}` | `network_172.18.0.6:5432` |
| `technique` | RAG or rule table | `technique_{id}` | `technique_T1190` |
| `cve` | RAG `matched_cves` | `cve_{id}` | `cve_CVE-2022-29217` |

### Technique Node Properties

| Property | Type | Description |
|---|---|---|
| `technique_id` | string | ATT&CK ID (e.g. `T1190`) |
| `technique_name` | string | Human-readable name |
| `tactic` | string | ATT&CK tactic |
| `confidence` | float | RAG confidence (1.0 for rule-table) |
| `scenario` | string | Source scenario ID |
| `container` | string | Originating container |
| `timestamp` | string | ISO-8601 UTC |

---

## Edge Schema

```json
{
  "source": "node_id",
  "target": "node_id",
  "type": "technique_adjacency | cve_dependency | process_lineage | network_flow",
  "weight": 0.0-1.0,
  "timestamp": "ISO 8601 | null"
}
```

### Edge Types

| Type | Logic | Weight |
|---|---|---|
| `technique_adjacency` | Same tactic or within 5min on same container | 0.8 (tactic) / 0.6 (window) |
| `cve_dependency` | Technique → linked CVE | 1.0 |
| `process_lineage` | Parent → child process (same container) | 0.9 |
| `network_flow` | Cross-container IP match | 0.7 |

---

## Path Schema

```json
{
  "scenario_id": "S10",
  "ordered_stages": ["S1", "S3", "S4", "S9", "S8"],
  "technique_sequence": ["T1190", "T1078", "T1212", "T1003.008", "T1041"]
}
```

---

## Integration Contracts

| Consumer | Fields Needed | Purpose |
|---|---|---|
| C2 (Risk Scoring) | `paths[].technique_sequence`, `edges[].weight` | Adaptive action selection |
| C3 (Evaluation) | `paths[].ordered_stages` | Ground truth comparison |

---

## Examples

### Single Scenario (S1)

```json
{
  "graph_id": "graph_20260804T120000_a1b2c3d4",
  "nodes": [
    {"id": "container_webapp", "type": "container", "label": "webapp", "properties": {"service": "webapp"}},
    {"id": "technique_T1190", "type": "technique", "label": "T1190", "properties": {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access", "confidence": 0.92, "scenario": "S1", "container": "webapp", "timestamp": "2026-08-04T12:00:00Z"}}
  ],
  "edges": [],
  "paths": [{"scenario_id": "S1", "ordered_stages": ["S1"], "technique_sequence": ["T1190"]}]
}
```

### S10 Chain

```json
{
  "graph_id": "graph_20260804T120000_s10chain",
  "nodes": [
    {"id": "container_webapp", "type": "container", "label": "webapp", "properties": {"service": "webapp"}},
    {"id": "container_authservice", "type": "container", "label": "authservice", "properties": {"service": "authservice"}},
    {"id": "technique_T1190", "type": "technique", "label": "T1190", "properties": {"technique_id": "T1190", "tactic": "Initial Access", "scenario": "S1", "container": "webapp", "timestamp": "2026-08-04T12:00:00Z"}},
    {"id": "technique_T1078", "type": "technique", "label": "T1078", "properties": {"technique_id": "T1078", "tactic": "Initial Access", "scenario": "S3", "container": "authservice", "timestamp": "2026-08-04T12:01:00Z"}},
    {"id": "technique_T1212", "type": "technique", "label": "T1212", "properties": {"technique_id": "T1212", "tactic": "Credential Access", "scenario": "S4", "container": "authservice", "timestamp": "2026-08-04T12:02:00Z"}},
    {"id": "technique_T1003.008", "type": "technique", "label": "T1003.008", "properties": {"technique_id": "T1003.008", "tactic": "Credential Access", "scenario": "S9", "container": "webapp", "timestamp": "2026-08-04T12:03:00Z"}},
    {"id": "technique_T1041", "type": "technique", "label": "T1041", "properties": {"technique_id": "T1041", "tactic": "Exfiltration", "scenario": "S8", "container": "webapp", "timestamp": "2026-08-04T12:04:00Z"}},
    {"id": "cve_CVE-2022-29217", "type": "cve", "label": "CVE-2022-29217", "properties": {"cve_id": "CVE-2022-29217", "technique": "T1212"}}
  ],
  "edges": [
    {"source": "technique_T1190", "target": "technique_T1078", "type": "technique_adjacency", "weight": 0.8, "timestamp": "2026-08-04T12:00:00Z"},
    {"source": "technique_T1212", "target": "cve_CVE-2022-29217", "type": "cve_dependency", "weight": 1.0, "timestamp": "2026-08-04T12:02:00Z"}
  ],
  "paths": [{"scenario_id": "S10", "ordered_stages": ["S1", "S3", "S4", "S9", "S8"], "technique_sequence": ["T1190", "T1078", "T1212", "T1003.008", "T1041"]}]
}
```
