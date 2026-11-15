"""Falco condition parser and three-valued, weighted evaluator.

Supports the Falco condition language used by both the lab rules and Falco's
stock rule packs:
  and / or / not, parentheses, = == != < <= > >=, `in (list)`, startswith,
  endswith, contains, icontains, glob, iglob, pmatch, intersects, bcontains,
  bstartswith, regex, exists, macro expansion (with cycle detection), recursive
  list expansion, indexed fields (e.g. proc.aname[2]), and unquoted items with
  brackets/colons (e.g. runc:[0:PARENT]).
Fields that are absent from the alert (Falco only exports the fields named in the rule's output:
template) evaluate to UNKNOWN, never to a mismatch. Unrepresentable leaves (such as val(...))
are recorded as uncheckable ("unknown") leaves instead of failing the whole rule.
"""
from __future__ import annotations
import fnmatch
import logging
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

_LOG = logging.getLogger(__name__)

_TOK = re.compile(
    r'''\s*(?:(?P<str>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')|(?P<op><=|>=|!=|==|=|<|>)|(?P<par>[(),])|(?P<word>(?:\[[^\]]*\]|[^\s(),=<>!"']|!(?!=))+))'''
)
_KW_OPS = {
    "in",
    "startswith",
    "endswith",
    "contains",
    "icontains",
    "glob",
    "iglob",
    "exists",
    "pmatch",
    "intersects",
    "bcontains",
    "bstartswith",
    "regex",
}


class _Unrepresentable:
    def __init__(self, raw: str):
        self.raw = raw


def tokenize(s: str) -> List[Tuple[str, str]]:
    out, pos, s = [], 0, s.strip()
    while pos < len(s):
        m = _TOK.match(s, pos)
        if not m:
            raise ValueError(f"cannot tokenize Falco condition near: {s[pos:pos+30]!r}")
        pos = m.end()
        kind = m.lastgroup
        val = m.group(kind)
        if kind == "str":
            val = val[1:-1].replace('\\"', '"').replace("\\'", "'").replace("\\\\", "\\")
        out.append((kind, val))
    return out


def expand_lists(lists: Optional[Dict[str, List[str]]]) -> Dict[str, List[str]]:
    """Recursively expand list references inside other lists; raise ValueError on cycles."""
    if not lists:
        return {}
    memo: Dict[str, List[str]] = {}

    def resolve(name: str, stack: Tuple[str, ...]) -> List[str]:
        if name in memo:
            return memo[name]
        if name in stack:
            raise ValueError(f"cyclic Falco list reference: {' -> '.join([*stack, name])}")
        out: List[str] = []
        for item in lists[name]:
            if item in lists:
                out.extend(resolve(item, (*stack, name)))
            else:
                out.append(item)
        memo[name] = out
        return out

    return {k: resolve(k, ()) for k in lists}


class _Parser:
    def __init__(
        self,
        toks: List[Tuple[str, str]],
        lists: Dict[str, List[str]],
        macros: Optional[Dict[str, str]] = None,
        stack: Tuple[str, ...] = (),
        rule_name: Optional[str] = None,
        unknown_leaves: Optional[List[Tuple[str, str]]] = None,
    ):
        self.t, self.i = toks, 0
        self.lists = lists
        self.macros = macros or {}
        self.stack = stack
        self.rule_name = rule_name
        self.unknown_leaves = unknown_leaves

    def peek(self, offset: int = 0) -> Tuple[Optional[str], Optional[str]]:
        idx = self.i + offset
        return self.t[idx] if idx < len(self.t) else (None, None)

    def eat(self) -> Tuple[str, str]:
        if self.i >= len(self.t):
            raise ValueError("unexpected end of Falco condition")
        tok = self.t[self.i]
        self.i += 1
        return tok

    def parse(self):
        n = self.or_expr()
        if self.i != len(self.t):
            raise ValueError(f"unexpected trailing token in Falco condition: {self.t[self.i]!r}")
        return n

    def or_expr(self):
        parts = [self.and_expr()]
        while self.peek() == ("word", "or"):
            self.eat()
            parts.append(self.and_expr())
        return parts[0] if len(parts) == 1 else ("or", parts)

    def and_expr(self):
        parts = [self.not_expr()]
        while self.peek() == ("word", "and"):
            self.eat()
            parts.append(self.not_expr())
        return parts[0] if len(parts) == 1 else ("and", parts)

    def _is_macro_call(self) -> bool:
        kind, val = self.peek()
        if kind != "word" or val not in self.macros:
            return False
        nk, nv = self.peek(1)
        if nk == "op" or (nk == "word" and nv in _KW_OPS) or (nk == "par" and nv == "("):
            return False
        return True

    def not_expr(self, neg: bool = False):
        if self.peek() == ("word", "not"):
            self.eat()
            return self.not_expr(not neg)
        if self.peek() == ("par", "("):
            self.eat()
            n = self.or_expr()
            if self.eat() != ("par", ")"):
                raise ValueError("expected closing ')' in Falco condition")
            return _negate(n) if neg else n
        if self._is_macro_call():
            _, name = self.eat()
            if name in self.stack:
                raise ValueError(f"cyclic Falco macro reference: {' -> '.join([*self.stack, name])}")
            sub_toks = tokenize(" ".join(self.macros[name].split()))
            n = _Parser(
                sub_toks,
                self.lists,
                self.macros,
                (*self.stack, name),
                self.rule_name,
                self.unknown_leaves,
            ).parse()
            return _negate(n) if neg else n
        return self.cmp(neg)

    def _eat_parens_raw(self) -> str:
        assert self.eat() == ("par", "(")
        depth = 1
        parts: List[str] = ["("]
        while depth > 0:
            k, v = self.eat()
            if k == "par" and v == "(":
                depth += 1
            elif k == "par" and v == ")":
                depth -= 1
            parts.append(repr(v) if k == "str" else v)
        return " ".join(parts)

    def _record_unknown(self, field: str, leaf_text: str, neg: bool):
        rname = self.rule_name or "<unknown>"
        _LOG.warning("Unrepresentable Falco leaf in rule %r: %s", rname, leaf_text)
        if self.unknown_leaves is not None:
            self.unknown_leaves.append((rname, leaf_text))
        return ("cmp", field, "unknown", leaf_text, neg)

    def value(self):
        kind, val = self.eat()
        if kind == "par" and val == "(":
            items = []
            while True:
                k, v = self.eat()
                if k == "par" and v == ")":
                    break
                if k == "par" and v == ",":
                    continue
                if k == "word" and self.peek() == ("par", "("):
                    inner = self._eat_parens_raw()
                    # consume any remaining items until matching ')'
                    while True:
                        rk, rv = self.eat()
                        if rk == "par" and rv == ")":
                            break
                    return _Unrepresentable(f"({v}{inner}, ...)")
                items.append(v)
            if len(items) == 1 and items[0] in self.lists:
                return list(self.lists[items[0]])
            out = []
            for it in items:
                out.extend(self.lists.get(it, [it]))
            return out
        if kind == "word" and self.peek() == ("par", "("):
            inner = self._eat_parens_raw()
            return _Unrepresentable(f"{val}{inner}")
        if kind == "word" and val in self.lists:
            return list(self.lists[val])
        return val

    def cmp(self, neg: bool):
        _, field = self.eat()
        if self.peek() == ("par", "("):
            lhs_raw = f"{field}{self._eat_parens_raw()}"
            nk, nv = self.peek()
            if nk == "op" or (nk == "word" and nv in _KW_OPS - {"exists"}):
                _, op = self.eat()
                rhs = self.value()
                rhs_s = rhs.raw if isinstance(rhs, _Unrepresentable) else str(rhs)
                return self._record_unknown(lhs_raw, f"{lhs_raw} {op} {rhs_s}", neg)
            if nk == "word" and nv == "exists":
                self.eat()
                return self._record_unknown(lhs_raw, f"{lhs_raw} exists", neg)
            return self._record_unknown(lhs_raw, lhs_raw, neg)

        kind, op = self.eat()
        if (kind == "word" and op in _KW_OPS - {"exists"}) or kind == "op":
            val = self.value()
            if isinstance(val, _Unrepresentable):
                return self._record_unknown(field, f"{field} {op} {val.raw}", neg)
            return ("cmp", field, op, val, neg)
        if kind == "word" and op == "exists":
            return ("cmp", field, "exists", None, neg)
        if kind == "word" and op not in ("and", "or", "not"):
            nk, _ = self.peek()
            if nk in ("word", "str") or self.peek() == ("par", "("):
                rhs = self.value()
                rhs_s = rhs.raw if isinstance(rhs, _Unrepresentable) else str(rhs)
                return self._record_unknown(field, f"{field} {op} {rhs_s}", neg)
        raise ValueError(f"bad comparison at {field} {op}")


def _negate(n):
    if n[0] == "cmp":
        return (n[0], n[1], n[2], n[3], not n[4])
    kind = "or" if n[0] == "and" else "and"
    return (kind, [_negate(c) for c in n[1]])


def parse_condition(
    cond: str,
    lists: Optional[Dict[str, List[str]]] = None,
    macros: Optional[Dict[str, str]] = None,
    *,
    rule_name: Optional[str] = None,
    unknown_leaves: Optional[List[Tuple[str, str]]] = None,
):
    expanded_lists = expand_lists(lists)
    return _Parser(
        tokenize(" ".join(cond.split())),
        expanded_lists,
        macros,
        (),
        rule_name,
        unknown_leaves,
    ).parse()


def leaves(node) -> List[tuple]:
    if node[0] == "cmp":
        return [node]
    return [l for c in node[1] for l in leaves(c)]


def _leaf_value(op: str, ev: Any, val: Any) -> Optional[bool]:
    if ev is None:
        return None
    se = str(ev)
    if op in ("=", "=="):
        return se == str(val)
    if op == "!=":
        return se != str(val)
    if op == "in":
        items = val if isinstance(val, (list, tuple, set)) else [val]
        return se in {str(v) for v in items}
    if op == "startswith":
        return se.startswith(str(val))
    if op == "endswith":
        return se.endswith(str(val))
    if op == "contains":
        return str(val) in se
    if op == "icontains":
        return str(val).lower() in se.lower()
    if op == "glob":
        return fnmatch.fnmatchcase(se, str(val))
    if op == "iglob":
        return fnmatch.fnmatchcase(se.lower(), str(val).lower())
    if op == "pmatch":
        prefixes = val if isinstance(val, (list, tuple, set)) else [val]
        for raw_p in prefixes:
            p = str(raw_p)
            if p == "/":
                if se.startswith("/"):
                    return True
            else:
                pn = p.rstrip("/")
                if se == pn or se.startswith(pn + "/"):
                    return True
        return False
    if op == "intersects":
        targets = {str(v) for v in (val if isinstance(val, (list, tuple, set)) else [val])}
        if isinstance(ev, (list, tuple, set)):
            return bool({str(x) for x in ev} & targets)
        return bool(set(se.split()) & targets)
    if op in ("bcontains", "bstartswith"):
        s = str(val)
        is_hex = len(s) >= 2 and len(s) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in s)
        if isinstance(ev, (bytes, bytearray)):
            raw = bytes(ev)
            candidates = [s.encode("utf-8", errors="ignore")]
            if is_hex:
                candidates.append(bytes.fromhex(s))
            if op == "bcontains":
                return any(c in raw for c in candidates)
            return any(raw.startswith(c) for c in candidates)
        if op == "bcontains":
            if s in se or s.lower() in se.lower():
                return True
            if is_hex:
                return bytes.fromhex(s).decode("latin1") in se
            return False
        if se.startswith(s):
            return True
        if is_hex:
            return se.startswith(bytes.fromhex(s).decode("latin1"))
        return False
    if op == "regex":
        try:
            return bool(re.search(str(val), se))
        except re.error:
            return None
    if op in ("<", "<=", ">", ">="):
        try:
            a, b = float(ev), float(val)
        except (TypeError, ValueError):
            return None
        return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]
    return None


def eval_leaf(leaf, event: Dict[str, Any]) -> Optional[bool]:
    _, field, op, val, neg = leaf
    if op == "unknown":
        return None
    if op == "exists":
        r = field in event
    else:
        r = _leaf_value(op, event.get(field), val)
    return None if r is None else (not r if neg else r)


def score(node, event: Dict[str, Any], weight: Callable[[tuple], float] = lambda l: 1.0) -> Tuple[float, float, float]:
    """Return (matched_weight, checkable_weight, total_weight). OR keeps its best branch."""
    if node[0] == "cmp":
        w = weight(node)
        r = eval_leaf(node, event)
        return (w if r else 0.0, w if r is not None else 0.0, w)
    parts = [score(c, event, weight) for c in node[1]]
    if node[0] == "and":
        return tuple(sum(p[i] for p in parts) for i in range(3))
    best = max(parts, key=lambda p: (p[0] / p[2] if p[2] else 0.0, p[1]))
    return (best[0], best[1], max(p[2] for p in parts))
