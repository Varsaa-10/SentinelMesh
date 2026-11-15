"""Automated detector-aware knowledge generation (SentinelMesh-X, improvement item 3).

Input : a detector artefact (a Falco rule file or a Python log-tail detector) plus the ATT&CK technique the
        operator registers it under (the same idea as Sigma's `tags: attack.t1110`).
Output: a structured DetectorKnowledge object with
        * executable constraints (used by the field-matching channel of the retriever),
        * a standardised, ATT&CK-compatible detection description (used by the semantic channel),
        * a record fragment in the kb_master `detection_signatures` schema, so it can be compared against
          the hand-written annotations.

No human-written description is read. Python detectors are analysed with `ast` (idioms: event.get() aliases,
guard clauses that return None, `in` / `==` comparisons, compiled regexes, loops over candidate fields,
len(window) >= THRESHOLD, annotation keys added to the emitted event). Falco rules are parsed with falco_cond.
LIMITATION: arbitrary Python control flow is not supported; a detector outside these idioms yields fewer
constraints (reported in `coverage_notes`) rather than a wrong one.
"""
from __future__ import annotations
import ast
import json
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

import yaml

from .falco_cond import parse_condition, leaves, score as fscore, eval_leaf, expand_lists

# ---------------------------------------------------------------------------------------------------------
# Small generic lexicon (NOT scenario specific). Every entry is a public convention (IANA ports, well-known
# sensitive paths, SQL syntax). It is ablated as "+lexicon" in the experiments so its effect is measurable.
# ---------------------------------------------------------------------------------------------------------
PORT_SERVICES = {5432: "PostgreSQL database service remote service", 3306: "MySQL database service remote service",
                 22: "SSH remote service", 3389: "RDP remote service", 445: "SMB remote service",
                 80: "HTTP web traffic", 443: "HTTPS web traffic", 53: "DNS"}
PATH_HINTS = [(r"/etc/shadow", "password hash file credential dumping /etc/passwd and /etc/shadow"),
              (r"\.ssh/", "SSH private key credential file unsecured credentials"),
              (r"\.aws/credentials", "cloud credentials file unsecured credentials"),
              (r"/var/log", "log file indicator removal on host log tampering"),
              (r"/etc/", "system configuration file")]
SQL_TOKENS = {"'": "quote", "--": "comment", ";": "statement separator", "or": "OR", "union": "UNION", "and": "AND", "select": "SELECT"}
EVENT_HINTS = {"login_attempt": "authentication login attempt valid accounts credentials",
               "jwt_verification": "token signature verification credential forgery"}
SOURCE_DATA_SOURCES = {"log_tail": "Application Log: Application Log Content", "falco_file": "File: File Access",
                       "falco_net_out": "Network Traffic: Network Connection Creation",
                       "falco_net_in": "Network Traffic: Network Traffic Content"}


@dataclass
class DetectorKnowledge:
    detector_id: str
    kind: str                       # "falco" | "log_tail"
    technique: str                  # registered ATT&CK id
    rule_name: str = ""
    severity: str = ""
    event_types: List[str] = field(default_factory=list)
    branches: List[List[dict]] = field(default_factory=list)   # alternatives; each = conjunction of constraints
    thresholds: Dict[str, Any] = field(default_factory=dict)
    annotations: Dict[str, Any] = field(default_factory=dict)
    cond_ast: Any = None            # falco condition AST
    data_sources: List[str] = field(default_factory=list)
    coverage_notes: List[str] = field(default_factory=list)
    text_plain: str = ""
    text_lexicon: str = ""

    def text(self, lexicon: bool = True) -> str:
        return self.text_lexicon if lexicon else self.text_plain


# ------------------------------------------------------------------ Python (log-tail) analyser ------------
class _Py:
    def __init__(self, src: str):
        self.tree = ast.parse(src)
        self.consts: Dict[str, Any] = {}
        for n in self.tree.body:
            if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
                v = self.cval(n.value)
                if v is not None:
                    self.consts[n.targets[0].id] = v
        self.notes: List[str] = []

    def cval(self, n):
        if isinstance(n, ast.Constant):
            return n.value
        if isinstance(n, (ast.Tuple, ast.Set, ast.List)):
            vals = [self.cval(e) for e in n.elts]
            return tuple(vals) if all(v is not None for v in vals) else None
        if isinstance(n, ast.Name) and n.id in getattr(self, "consts", {}):
            return self.consts[n.id]
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "compile" and n.args:
            p = self.cval(n.args[0])
            if isinstance(p, str):
                return ("__regex__", p)
        return None

    # key paths of an expression that reads from the event
    def paths(self, n, alias, ev) -> Optional[List[str]]:
        if isinstance(n, ast.Name):
            return alias.get(n.id)
        if isinstance(n, ast.BoolOp) and isinstance(n.op, ast.Or):
            out = []
            for v in n.values:
                p = self.paths(v, alias, ev)
                if p:
                    out += p
            return out or None
        if isinstance(n, ast.IfExp):
            return self.paths(n.body, alias, ev)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
            if n.func.attr == "get" and n.args:
                key = n.args[0]
                keys = [key.value] if isinstance(key, ast.Constant) and isinstance(key.value, str) else \
                    (alias.get(key.id) if isinstance(key, ast.Name) else None)
                base = n.func.value
                if isinstance(base, ast.Name) and base.id == ev:
                    return list(keys) if keys else None
                bp = self.paths(base, alias, ev)
                if bp and keys:
                    return [f"{b}.{k}" for b in bp for k in keys]
            if n.func.attr in ("lower", "upper", "strip"):
                return self.paths(n.func.value, alias, ev)
        return None

    def atoms(self, test, alias, ev, neg=False) -> List[dict]:
        """Conjunction of atomic constraints for `test` (negated when neg). Unknown parts are dropped."""
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return self.atoms(test.operand, alias, ev, not neg)
        if isinstance(test, ast.BoolOp):
            is_and = isinstance(test.op, ast.And) != neg
            parts = [self.atoms(v, alias, ev, neg) for v in test.values]
            if is_and:
                return [a for p in parts for a in p]
            parts = [p for p in parts if p]
            return [{"kind": "or", "items": [x for p in parts for x in p]}] if parts else []
        if isinstance(test, ast.Compare) and len(test.ops) == 1:
            op, right = test.ops[0], test.comparators[0]
            left = test.left
            if isinstance(left, ast.Call) and isinstance(left.func, ast.Name) and left.func.id == "len":
                thr = self.cval(right)
                var = left.args[0].id if left.args and isinstance(left.args[0], ast.Name) else "?"
                sym = {ast.GtE: ">=", ast.Gt: ">", ast.Lt: "<", ast.LtE: "<="}.get(type(op))
                if sym and isinstance(thr, (int, float)):
                    if neg:
                        sym = {">=": "<", ">": "<=", "<": ">=", "<=": ">"}[sym]
                    return [{"kind": "window_count", "var": var, "op": sym, "value": thr}]
                return []
            p = self.paths(left, alias, ev)
            v = self.cval(right)
            if p and v is not None:
                vals = list(v) if isinstance(v, tuple) else [v]
                if isinstance(op, (ast.Eq, ast.NotEq)):
                    n2 = isinstance(op, ast.NotEq) != neg
                    return [{"kind": "in", "paths": p, "values": vals, "neg": n2}]
                if isinstance(op, (ast.In, ast.NotIn)):
                    n2 = isinstance(op, ast.NotIn) != neg
                    return [{"kind": "in", "paths": p, "values": [str(x) for x in vals], "neg": n2}]
            return []
        if isinstance(test, ast.Call) and isinstance(test.func, ast.Attribute) and test.func.attr in ("search", "match", "fullmatch"):
            rx = self.cval(test.func.value)
            if isinstance(rx, tuple) and rx and rx[0] == "__regex__" and test.args:
                p = self.paths(test.args[0], alias, ev) or (alias.get(test.args[0].id) if isinstance(test.args[0], ast.Name) else None)
                return [{"kind": "regex", "paths": p or ["*"], "pattern": rx[1], "neg": neg}]
        return []

    def emits(self, call):
        kw = {k.arg: k.value for k in call.keywords}
        info = {"severity": self.cval(kw["severity"]) if "severity" in kw else None,
                "title": self.cval(kw["title"]) if "title" in kw else None, "ann": {}, "event_map": {}}
        if "title" in kw and info["title"] is None and isinstance(kw["title"], ast.Constant):
            info["title"] = kw["title"].value
        if "title" in kw and info["title"] is None:           # implicit string concatenation / f-strings: take literal parts
            info["title"] = "".join(c.value for c in ast.walk(kw["title"]) if isinstance(c, ast.Constant) and isinstance(c.value, str))
        ev = kw.get("event")
        if isinstance(ev, ast.Dict):
            for k, v in zip(ev.keys, ev.values):
                if k is None:
                    continue
                kk = k.value if isinstance(k, ast.Constant) else None
                if isinstance(v, ast.Call) and isinstance(v.func, ast.Name) and v.func.id == "len" and v.args and isinstance(v.args[0], ast.Name):
                    info["ann"][kk] = ("len", v.args[0].id)
                elif isinstance(v, ast.Name) and v.id in self.consts:
                    info["ann"][kk] = ("const", self.consts[v.id])
                else:
                    for nm in ast.walk(v):
                        if isinstance(nm, ast.Name):
                            info["event_map"][nm.id] = kk
        return info

    def analyse(self) -> Dict[str, Any]:
        fn = None
        for n in self.tree.body:
            if isinstance(n, ast.FunctionDef) and any(isinstance(c, ast.Call) and getattr(c.func, "id", "") == "emit_alert" for c in ast.walk(n)):
                if n.name in ("check", "check_line") or fn is None:
                    fn = n
        if fn is None:
            return {"branches": [], "notes": ["no function calling emit_alert was found"], "emits": []}
        ev = fn.args.args[0].arg if fn.args.args else "event"
        branches, emits = [], []

        def walk(stmts, guards, alias):
            alias = dict(alias)
            guards = list(guards)
            for st in stmts:
                if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name):
                    p = self.paths(st.value, alias, ev)
                    if p:
                        alias[st.targets[0].id] = p
                elif isinstance(st, ast.If):
                    emitting = any(isinstance(c, ast.Call) and getattr(c.func, "id", "") == "emit_alert" for b in st.body for c in ast.walk(b))
                    if emitting:
                        walk(st.body, guards + self.atoms(st.test, alias, ev), alias)
                    elif len(st.body) == 1 and isinstance(st.body[0], ast.Return):
                        guards += self.atoms(st.test, alias, ev, neg=True)
                elif isinstance(st, ast.For) and isinstance(st.target, ast.Name):
                    it = self.cval(st.iter)
                    a2 = dict(alias)
                    if isinstance(it, tuple):
                        a2[st.target.id] = list(it)
                    walk(st.body, guards, a2)
                elif isinstance(st, (ast.Return, ast.Expr)) and isinstance(getattr(st, "value", None), ast.Call) \
                        and getattr(st.value.func, "id", "") == "emit_alert":
                    info = self.emits(st.value)
                    branches.append({"constraints": guards, "emit": info, "alias": alias})
                    emits.append(info)

        walk(fn.body, [], {})
        # resolve helper parameter -> event key (e.g. check_line(line) -> raw_log_line), len(window) annotation keys
        for b in branches:
            for atom in _flat(b["constraints"]):
                if atom["kind"] == "regex" and atom["paths"] == ["*"]:
                    atom["paths"] = list(b["emit"]["event_map"].values()) or ["*"]
                if atom["kind"] == "window_count":
                    for key, spec in b["emit"]["ann"].items():
                        if spec == ("len", atom["var"]):
                            atom["paths"] = [key]
        return {"branches": branches, "emits": emits, "notes": self.notes}


def _flat(cs):
    for c in cs:
        yield c
        if c["kind"] == "or":
            yield from _flat(c["items"])


def _humanise_regex(pat: str) -> str:
    toks = re.findall(r"\\b([A-Za-z_]+)\\b|([A-Za-z_]{3,})|(--|;|')", pat)
    words = []
    for a, b, c in toks:
        w = a or b or c
        if w and w.lower() not in ("compile", "and", "d", "s") or w in ("'", "--", ";"):
            words.append(w)
    return " ".join(dict.fromkeys(words))


def analyse_log_tail(path: Path, technique: str) -> DetectorKnowledge:
    src = path.read_text(encoding="utf-8")
    res = _Py(src).analyse()
    dk = DetectorKnowledge(detector_id=str(path.name), kind="log_tail", technique=technique, data_sources=[SOURCE_DATA_SOURCES["log_tail"]])
    for b in res["branches"]:
        cons = [c for c in b["constraints"]]
        dk.branches.append(cons)
        em = b["emit"]
        dk.severity = dk.severity or (em["severity"] or "")
        dk.rule_name = dk.rule_name or (em["title"] or "")
        for a in _flat(cons):
            if a["kind"] == "in" and any(p in ("event_type", "event") for p in a["paths"]) and not a["neg"]:
                dk.event_types += [v for v in a["values"] if v not in dk.event_types]
            if a["kind"] == "window_count":
                dk.thresholds["count"] = a["value"]
        for k, spec in em["ann"].items():
            if spec[0] == "const":
                dk.annotations[k] = spec[1]
    for name, v in _Py(src).consts.items():
        if name.endswith("WINDOW_SECONDS"):
            dk.thresholds["window_seconds"] = v
    if not dk.branches:
        dk.coverage_notes.append("no emit_alert branch analysed")
    _render_log_tail(dk)
    return dk


def _cons_phrase(a: dict) -> str:
    if a["kind"] == "in":
        f = "/".join(dict.fromkeys(a["paths"]))
        vals = ", ".join(str(v) for v in a["values"])
        return f"{f} {'not in' if a['neg'] else 'in'} ({vals})"
    if a["kind"] == "regex":
        return f"{'no match of' if a['neg'] else 'match of'} pattern [{a['pattern']}] on field {'/'.join(dict.fromkeys(a['paths']))}"
    if a["kind"] == "window_count":
        return f"event count {a['op']} {a['value']}"
    if a["kind"] == "or":
        return " or ".join(_cons_phrase(i) for i in a["items"])
    return ""


def _render_log_tail(dk: DetectorKnowledge) -> None:
    parts = [f"Application log detector, source log_tail, watches {', '.join(dk.event_types) or 'application'} events."]
    for i, br in enumerate(dk.branches):
        cs = [x for x in (_cons_phrase(a) for a in br if not (a['kind'] == 'in' and any(p in ('event_type', 'event') for p in a['paths']))) if x]
        if cs:
            parts.append(f"Condition {i+1}: " + "; ".join(cs) + ".")
    if dk.thresholds:
        parts.append("Threshold: " + ", ".join(f"{k}={v}" for k, v in dk.thresholds.items()) + ".")
    parts.append(f"Data source: {dk.data_sources[0]}.")
    plain = " ".join(parts)
    lex = [plain]
    for et in dk.event_types:
        if et in EVENT_HINTS:
            lex.append(EVENT_HINTS[et] + ".")
    for br in dk.branches:
        for a in _flat(br):
            if a["kind"] == "regex":
                toks = [t for t in re.findall(r"[A-Za-z]+|--|'|;", a["pattern"]) if t.lower() in SQL_TOKENS]
                if len(toks) >= 3:
                    lex.append("SQL injection syntax tokens (" + ", ".join(SQL_TOKENS[t.lower()] for t in dict.fromkeys(toks)) + ") in user supplied field, exploit public-facing application.")
            if a["kind"] == "in" and not a["neg"] and any("algorithm" in p for p in a["paths"]):
                lex.append("unsafe token algorithm accepted, signature check bypassed, exploitation for credential access.")
            if a["kind"] == "in" and not a["neg"] and any(p in ("result",) for p in a["paths"]) and any(str(v) in ("fail", "failure") for v in a["values"]):
                lex.append("repeated failed logins password guessing brute force.")
            if a["kind"] == "regex" and "login" in a["pattern"].lower():
                lex.append("web console login with default or anonymous access, valid accounts.")
    if dk.thresholds.get("count"):
        lex.append("repeated attempts within a time window.")
    dk.text_plain, dk.text_lexicon = plain, " ".join(lex)


# ------------------------------------------------------------------ Falco analyser -----------------------
_TECH_TAG_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
STOCK_RULE_FILES = ("falco_rules.yaml", "falco-incubating_rules.yaml", "falco-sandbox_rules.yaml")


def _clean_list_item(item: str) -> str:
    if len(item) >= 2 and item[0] == item[-1] and item[0] in ('"', "'"):
        return item[1:-1]
    return item


def _tag_technique(rule: dict) -> str:
    for t in rule.get("tags") or []:
        s = str(t)
        if _TECH_TAG_RE.fullmatch(s):
            return s
    return ""


def load_falco_rules(
    path: Union[Path, Sequence[Path]],
    registry: Optional[Dict[str, str]] = None,
    unknown_leaves: Optional[List[Tuple[str, str]]] = None,
) -> List[DetectorKnowledge]:
    paths = [Path(path)] if isinstance(path, (str, Path)) else [Path(p) for p in path]
    lists: Dict[str, List[str]] = {}
    macros: Dict[str, str] = {}
    rule_entries: List[Tuple[Path, dict]] = []
    rule_idx: Dict[str, int] = {}

    for p in paths:
        items = yaml.safe_load(p.read_text(encoding="utf-8")) or []
        for it in items:
            if not isinstance(it, dict):
                continue
            if "list" in it:
                name = str(it["list"])
                cleaned = [_clean_list_item(str(x)) for x in (it.get("items") or [])]
                if it.get("append") and name in lists:
                    lists[name].extend(cleaned)
                else:
                    lists[name] = cleaned
            elif "macro" in it:
                name = str(it["macro"])
                cond = " ".join(str(it["condition"]).split())
                if it.get("append") and name in macros:
                    macros[name] = f"({macros[name]}) {cond}"
                else:
                    macros[name] = cond
            elif "rule" in it:
                name = str(it["rule"])
                if it.get("append") and name in rule_idx:
                    idx = rule_idx[name]
                    src_p, prev = rule_entries[idx]
                    merged = dict(prev)
                    merged["condition"] = f"({prev['condition']}) {it['condition']}"
                    rule_entries[idx] = (src_p, merged)
                else:
                    rule_idx[name] = len(rule_entries)
                    rule_entries.append((p, dict(it)))

    lists = expand_lists(lists)
    out = []
    for src_path, it in rule_entries:
        cond = " ".join(str(it["condition"]).split())
        ast_ = parse_condition(
            cond,
            lists,
            macros,
            rule_name=it["rule"],
            unknown_leaves=unknown_leaves,
        )
        technique = registry[it["rule"]] if (registry and it["rule"] in registry) else _tag_technique(it)
        dk = DetectorKnowledge(
            detector_id=str(src_path.name),
            kind="falco",
            technique=technique,
            rule_name=it["rule"],
            severity=str(it.get("priority", "")),
            cond_ast=ast_,
        )
        dk.cond_ast = ast_
        _render_falco(dk, it, ast_, lists)
        out.append(dk)
    return out


def load_stock_falco_rules(
    stock_dir: Path,
    registry: Optional[Dict[str, str]] = None,
    unknown_leaves: Optional[List[Tuple[str, str]]] = None,
) -> List[DetectorKnowledge]:
    stock_dir = Path(stock_dir)
    return load_falco_rules(
        [stock_dir / name for name in STOCK_RULE_FILES],
        registry=registry,
        unknown_leaves=unknown_leaves,
    )


def _render_falco(dk: DetectorKnowledge, rule: dict, ast_, lists) -> None:
    ls = leaves(ast_)
    desc = ["Kernel runtime detector, source falco."]
    lex = []
    kinds = set()
    for (_, f, op, val, neg) in ls:
        if op == "unknown":
            continue
        v = ", ".join(map(str, val)) if isinstance(val, list) else str(val)
        if f == "evt.type":
            dk.event_types += [x.strip() for x in v.split(",")]
            kinds |= set(x.strip() for x in v.split(","))
            desc.append(f"System call {v}.")
        elif f == "evt.is_open_read":
            desc.append("File opened for reading.")
        elif f == "evt.is_open_write":
            desc.append("File opened for writing.")
        elif f == "fd.sport" or f == "fd.lport":
            desc.append(f"Server port {v}.")
            try:
                if int(v) in PORT_SERVICES:
                    lex.append(PORT_SERVICES[int(v)] + ".")
            except ValueError:
                pass
        elif f == "fd.name":
            desc.append(f"File path {op} {v}.")
            for pat, hint in PATH_HINTS:
                if re.search(pat, v):
                    lex.append(hint + ".")
                    break
        elif f in ("fd.sip", "fd.rip", "fd.cip") and op == "in":
            desc.append(f"Peer address {'not ' if neg else ''}in allow-list of {len(val)} addresses.")
            lex.append("connection from or to an address outside the allowed peer list, " + ("outbound to external destination." if f == "fd.sip" else "unexpected client."))
        elif f == "container.name":
            desc.append(f"Container {op} {v}.")
        else:
            desc.append(f"{f} {op} {v}.")
    if kinds & {"accept"}:
        dk.data_sources = [SOURCE_DATA_SOURCES["falco_net_in"]]
    elif kinds & {"connect"}:
        dk.data_sources = [SOURCE_DATA_SOURCES["falco_net_out"]]
    else:
        dk.data_sources = [SOURCE_DATA_SOURCES["falco_file"]]
    if any(k in kinds for k in ("open", "openat", "openat2")) and any(l[1] == "evt.is_open_write" for l in ls):
        lex.append("unexpected process writes to a protected directory.")
    desc.append(f"Priority {dk.severity}. Data source: {dk.data_sources[0]}.")
    dk.text_plain = " ".join(desc)
    dk.text_lexicon = dk.text_plain + " " + " ".join(dict.fromkeys(lex))


# ------------------------------------------------------------------ registry + driver --------------------
def build_registry(root: Path) -> Dict[str, str]:
    """detector artefact name -> ATT&CK id, from the operator-registered mapping in eval/ground_truth.json.
    Falco rules are keyed by rule name through the scenario tag in the rule file (tags: [.., s5, ..])."""
    gt = json.loads((root / "eval/ground_truth.json").read_text(encoding="utf-8"))["scenarios"]
    reg = {}
    for sid, g in gt.items():
        if sid == "S10":
            continue
        det = g.get("detection", {}).get("detector", "")
        reg[sid] = (g["technique_id"], det)
    return reg


def generate_all(root: Path) -> List[DetectorKnowledge]:
    reg = build_registry(root)
    by_scen = {sid: t for sid, (t, _) in reg.items()}
    out: List[DetectorKnowledge] = []
    for p in sorted((root / "detection/log-tail").glob("scenario*_detector.py")):
        sid = "S" + re.search(r"scenario(\d+)", p.name).group(1)
        out.append(analyse_log_tail(p, by_scen[sid]))
    for p in sorted((root / "detection/falco-rules").glob("*.yaml")):
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
        for dk in load_falco_rules(p):
            rule = next(i for i in raw if isinstance(i, dict) and i.get("rule") == dk.rule_name)
            tag = next((t for t in rule.get("tags", []) if re.fullmatch(r"s\d+(-.*)?", t)), "")
            sid = "S" + re.match(r"s(\d+)", tag).group(1)
            dk.technique = by_scen[sid]
            out.append(dk)
    return out


# ------------------------------------------------------------------ evaluation against annotations --------
def _tokens(s: str) -> set:
    return {t for t in re.findall(r"[a-z0-9_]+", (s or "").lower()) if len(t) > 2}


def compare_to_expert(dks: List[DetectorKnowledge], kb_dir: Path) -> List[dict]:
    """Field-level and token-level agreement with the hand-written kb_master detection_signatures.
    NOTE: the annotations were written by the lab team, so this is agreement with the team's own annotation,
    not an independent expert panel (improvement item 3 still needs that panel)."""
    rows = []
    for dk in dks:
        rec = json.loads((kb_dir / f"{dk.technique}.json").read_text(encoding="utf-8"))
        sig = rec["detection_signatures"].get(dk.kind)
        if not sig:
            rows.append({"detector": dk.detector_id, "technique": dk.technique, "kind": dk.kind, "expert_signature": False})
            continue
        expert_txt = " ".join(str(v) for v in (sig.values() if isinstance(sig, dict) else []) if not isinstance(v, dict)) + " " + \
            " ".join(f"{k} {v}" for k, v in (sig.get("match_fields") or {}).items())
        gen = _tokens(dk.text(lexicon=False))
        exp = _tokens(expert_txt)
        recall = len(gen & exp) / len(exp) if exp else 0.0
        prec = len(gen & exp) / len(gen) if gen else 0.0
        row = {"detector": dk.detector_id, "technique": dk.technique, "kind": dk.kind, "expert_signature": True,
               "token_recall_of_expert": round(recall, 3), "token_precision": round(prec, 3)}
        if dk.kind == "log_tail":
            row["event_type_exact"] = bool(sig.get("event_type")) and sig.get("event_type") in dk.event_types
            mf = sig.get("match_fields") or {}
            gen_vals = {str(v) for br in dk.branches for a in _flat(br) if a["kind"] == "in" for v in a["values"]}
            row["match_field_values_recalled"] = (sum(str(v) in gen_vals for v in mf.values()) / len(mf)) if mf else None
        else:
            row["rule_name_exact"] = sig.get("rule_name") == dk.rule_name
        rows.append(row)
    return rows


def to_kb_signature(dks: List[DetectorKnowledge], technique: str, lexicon: bool = True) -> Dict[str, Optional[dict]]:
    """Record fragment in the kb_master `detection_signatures` schema, built only from generated knowledge."""
    sig: Dict[str, Optional[dict]] = {"log_tail": None, "falco": None}
    for dk in dks:
        if dk.technique != technique:
            continue
        if dk.kind == "log_tail":
            old = sig["log_tail"]
            txt = dk.text(lexicon)
            sig["log_tail"] = {"event_type": ", ".join(dk.event_types), "pattern": (old["pattern"] + " " if old else "") + txt,
                               "detector_ref": dk.detector_id, "generated": True}
        else:
            old = sig["falco"]
            txt = dk.text(lexicon)
            sig["falco"] = {"rule_name": dk.rule_name, "trigger_condition": (old["trigger_condition"] + " " if old else "") + txt,
                            "generated": True}
    return sig
