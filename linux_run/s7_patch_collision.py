#!/usr/bin/env python3
"""Fix: S3 and S7 both map to T1078, and technique nodes are (deliberately) unique per
technique, so S7 never got a reconstructed path. Nodes stay unique; each technique node
now also records ALL scenarios that hit it (properties['scenarios']), and per-scenario
paths are built from that. Run from the repo root."""
from pathlib import Path

HELPER = '''

def _note_scenario(node, scenario):
    """Record every scenario that maps to this technique node (nodes stay unique per technique)."""
    if node is None or not scenario:
        return
    seen = node.properties.setdefault("scenarios", [node.properties.get("scenario")] if node.properties.get("scenario") else [])
    if scenario not in seen:
        seen.append(scenario)
'''

def sub(s, old, new, label):
    assert s.count(old) == 1, f"{label}: expected 1 match, found {s.count(old)}"
    return s.replace(old, new)

# ---- graph_only_baseline.py
p = Path("graph/graph_only_baseline.py"); s = p.read_text()
if "_note_scenario" in s: print(f"{p}: already patched")
else:
    s = sub(s, '                ))\n\n            # CVE node\n',
               '                ))\n            _note_scenario(graph.get_node(tech_node_id), scenario)\n\n            # CVE node\n', "graph_only node")
    s = sub(s, "def _flat_get(d: dict, key: str, default=None):", HELPER.lstrip("\n") + "\n\ndef _flat_get(d: dict, key: str, default=None):", "graph_only helper")
    p.write_text(s); print(f"{p}: patched")

# ---- attack_graph.py (RAG-grounded variant + shared path registration)
p = Path("graph/attack_graph.py"); s = p.read_text()
if "_note_scenario" in s: print(f"{p}: already patched")
else:
    s = sub(s, '                ))\n\n        # CVE nodes\n',
               '                ))\n            _note_scenario(graph.get_node(tech_node_id), scenario)\n\n        # CVE nodes\n', "attack_graph node")
    s = sub(s, "def _get_attr_or_key(obj, key, default=None):", HELPER.lstrip("\n") + "\n\ndef _get_attr_or_key(obj, key, default=None):", "attack_graph helper")
    old = '''        seen_ids: List[str] = []
        for sid in scenarios:
            if sid not in seen_ids:
                seen_ids.append(sid)
        for sid in seen_ids:
            sid_nodes = [n for n in tech_nodes if n.properties.get("scenario") == sid]
            sid_stages = [n.properties.get("scenario", "") for n in sid_nodes]'''
    new = '''        def _node_scenarios(n):
            return n.properties.get("scenarios") or ([n.properties["scenario"]] if n.properties.get("scenario") else [])
        seen_ids: List[str] = []
        for n in tech_nodes:
            for sid in _node_scenarios(n):
                if sid not in seen_ids:
                    seen_ids.append(sid)
        for sid in seen_ids:
            sid_nodes = [n for n in tech_nodes if sid in _node_scenarios(n)]
            sid_stages = [sid for _ in sid_nodes]'''
    s = sub(s, old, new, "attack_graph paths")
    p.write_text(s); print(f"{p}: patched")
