"""M4: independent data adapters. Sigma (detection logic + ATT&CK tags authored by the Sigma community) and Atomic Red Team
(command definitions labelled by Red Canary). Neither was written by the SentinelMesh team.

HONEST SCOPE: Atomic Red Team provides test *definitions*, not captured telemetry, and there is no benign data. Events built here are
`{Image, CommandLine}` records derived from those commands; the Image field is inferred (first token / interpreter) and is an assumption.
Results therefore measure cross-source agreement between independently authored rules and labels, not performance on real attack telemetry.
"""
from __future__ import annotations
import fnmatch
import re
import tarfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml

SUPPORTED_MODS = {"contains", "startswith", "endswith", "all", "re", "i", "cased"}
FIELD_ALIASES = {"commandline": "CommandLine", "image": "Image", "parentimage": "ParentImage", "parentcommandline": "ParentCommandLine",
                 "originalfilename": "OriginalFileName", "user": "User", "currentdirectory": "CurrentDirectory"}


# ---------------------------------------------------------------- Sigma
class Unsupported(Exception):
    pass


def _tag_techniques(tags: Iterable[str]) -> List[str]:
    out = []
    for t in tags or []:
        m = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", str(t).lower())
        if m:
            out.append(m.group(1).upper())
    return out


def _tag_tactics(tags: Iterable[str]) -> List[str]:
    return [str(t)[7:] for t in (tags or []) if str(t).startswith("attack.") and not re.fullmatch(r"attack\.t\d{4}(?:\.\d{3})?", str(t).lower())]


def _match_value(ev: str, val: Any, mods: List[str]) -> bool:
    s = ev if "cased" in mods else ev.lower()
    v = "" if val is None else str(val)
    v = v if "cased" in mods else v.lower()
    if "re" in mods:
        return re.search(str(val), ev, 0 if "cased" in mods else re.I) is not None
    if "contains" in mods:
        return v in s
    if "startswith" in mods:
        return s.startswith(v)
    if "endswith" in mods:
        return s.endswith(v)
    if "*" in v or "?" in v:
        return fnmatch.fnmatchcase(s, v)
    return s == v


def _field_cond(spec: str, value: Any, event: Dict[str, Any]) -> Optional[bool]:
    parts = spec.split("|")
    name, mods = parts[0], [m.lower() for m in parts[1:]]
    if any(m not in SUPPORTED_MODS for m in mods):
        raise Unsupported(f"modifier {mods}")
    fld = FIELD_ALIASES.get(name.lower(), name)
    if fld not in event:
        return None                                           # unknown, never a mismatch
    ev = event[fld]
    vals = value if isinstance(value, list) else [value]
    res = [_match_value("" if ev is None else str(ev), v, mods) for v in vals]
    return all(res) if "all" in mods else any(res)


def _and3(xs):
    if any(x is False for x in xs): return False
    return None if any(x is None for x in xs) else True


def _or3(xs):
    if any(x is True for x in xs): return True
    return None if any(x is None for x in xs) else False


def _eval_selection(sel: Any, event: Dict[str, Any]) -> Optional[bool]:
    if isinstance(sel, dict):
        return _and3([_field_cond(k, v, event) for k, v in sel.items()])
    if isinstance(sel, list) and all(isinstance(x, dict) for x in sel):
        return _or3([_eval_selection(x, event) for x in sel])
    raise Unsupported("keyword (field-less) selection")


_TOK = re.compile(r"\(|\)|[^\s()]+")


class SigmaRule:
    def __init__(self, doc: Dict[str, Any], path: str = ""):
        self.path, self.title, self.id = path, doc.get("title", ""), doc.get("id", "")
        self.techniques = _tag_techniques(doc.get("tags")); self.tactics = _tag_tactics(doc.get("tags"))
        self.level = doc.get("level", "")
        det = doc.get("detection") or {}
        cond = det.get("condition")
        if not isinstance(cond, str):
            raise Unsupported("multiple/complex condition")
        if "|" in cond or re.search(r"\b(count|near|by)\b", cond):
            raise Unsupported("aggregation")
        self.sels = {k: v for k, v in det.items() if k not in ("condition", "timeframe")}
        self.toks = _TOK.findall(cond)
        self.unsupported = None
        self.evaluate({"CommandLine": "", "Image": ""})            # raises Unsupported now rather than at scoring time

    def _names(self, pat: str) -> List[str]:
        return list(self.sels) if pat == "them" else [k for k in self.sels if fnmatch.fnmatchcase(k, pat)]

    def evaluate(self, event: Dict[str, Any]) -> Optional[bool]:
        toks, pos = self.toks, [0]
        def peek(): return toks[pos[0]].lower() if pos[0] < len(toks) else None
        def eat(): pos[0] += 1; return toks[pos[0] - 1]
        def or_(): 
            v = [and_()]
            while peek() == "or": eat(); v.append(and_())
            return _or3(v)
        def and_():
            v = [not_()]
            while peek() == "and": eat(); v.append(not_())
            return _and3(v)
        def not_():
            if peek() == "not":
                eat(); x = not_(); return None if x is None else (not x)
            return atom()
        def atom():
            t = eat()
            if t == "(":
                v = or_(); eat(); return v
            if t.lower() in ("1", "all") and peek() == "of":
                eat(); pat = eat(); names = self._names(pat)
                if not names: raise Unsupported("of-pattern matches nothing")
                vals = [_eval_selection(self.sels[n], event) for n in names]
                return _or3(vals) if t == "1" else _and3(vals)
            if t not in self.sels: raise Unsupported(f"unknown selection {t}")
            return _eval_selection(self.sels[t], event)
        r = or_()
        if pos[0] != len(toks): raise Unsupported("trailing tokens")
        return r

    def fires(self, event: Dict[str, Any]) -> bool:
        return self.evaluate(event) is True


def load_sigma_process_creation(tgz: Path) -> Tuple[List[SigmaRule], Dict[str, int]]:
    rules, stats = [], {"files": 0, "tagged": 0, "unsupported": 0, "no_technique_tag": 0}
    with tarfile.open(tgz) as tf:
        for m in tf.getmembers():
            if not (m.isfile() and "/rules/windows/process_creation/" in m.name and m.name.endswith(".yml")):
                continue
            stats["files"] += 1
            try:
                doc = yaml.safe_load(tf.extractfile(m).read())
                if not _tag_techniques(doc.get("tags")):
                    stats["no_technique_tag"] += 1; continue
                stats["tagged"] += 1
                rules.append(SigmaRule(doc, m.name))
            except Unsupported:
                stats["unsupported"] += 1
            except Exception:
                stats["unsupported"] += 1
    return rules, stats


# ---------------------------------------------------------------- Atomic Red Team
_ARG = re.compile(r"#\{([^}]+)\}")


def load_atomic_events(index_yaml: Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    d = yaml.safe_load(Path(index_yaml).read_text(encoding="utf-8"))
    events, tests, techs = [], 0, set()
    for tactic, ts in d.items():
        for tid, v in (ts or {}).items():
            for a in v.get("atomic_tests", []) or []:
                if "windows" not in (a.get("supported_platforms") or []):
                    continue
                ex = a.get("executor") or {}
                if ex.get("name") not in ("command_prompt", "powershell") or not ex.get("command"):
                    continue
                args = {k: str((x or {}).get("default", "")) for k, x in (a.get("input_arguments") or {}).items()}
                cmd = _ARG.sub(lambda m: args.get(m.group(1), ""), ex["command"])
                tests += 1; techs.add(tid)
                for i, line in enumerate(l.strip() for l in cmd.splitlines() if l.strip() and not l.strip().startswith(("#", "REM", "::"))):
                    first = line.split()[0].strip('"') if line.split() else ""
                    if ex["name"] == "powershell":
                        image = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
                    else:
                        base = first.split("\\")[-1]
                        image = first if first.lower().endswith(".exe") and "\\" in first else f"C:\\Windows\\System32\\{base if base.lower().endswith('.exe') else base + '.exe'}"
                    events.append({"event_id": f"{a.get('auto_generated_guid', tid + str(tests))}:{i}", "test_guid": a.get("auto_generated_guid") or f"{tid}-{tests}",
                                   "technique": tid, "tactic": tactic, "test_name": a.get("name", ""), "executor": ex["name"],
                                   "Image": image, "CommandLine": line})
    return events, {"windows_tests": tests, "windows_techniques": len(techs), "events": len(events)}
