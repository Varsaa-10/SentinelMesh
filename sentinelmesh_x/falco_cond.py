"""Minimal Falco condition parser and three-valued, weighted evaluator.

Only the subset of the Falco condition language that the lab rules use is supported:
  and / or / not, parentheses, = != < <= > >=, `in (list)`, startswith, endswith, contains,
  icontains, glob, named `- list:` items, bare-word values (evt.type = open).
Fields that are absent from the alert (Falco only exports the fields named in the rule's output:
template) evaluate to UNKNOWN, never to a mismatch.
"""
from __future__ import annotations
import fnmatch
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

_TOK = re.compile(r'''\s*(?:(?P<str>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')|(?P<op><=|>=|!=|=|<|>)|(?P<par>[(),])|(?P<word>[A-Za-z0-9_./:*\-]+))''')
_KW_OPS = {"in", "startswith", "endswith", "contains", "icontains", "glob", "exists"}


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
            val = val[1:-1]
        out.append((kind, val))
    return out


class _Parser:
    def __init__(self, toks, lists):
        self.t, self.i, self.lists = toks, 0, lists

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else (None, None)

    def eat(self):
        tok = self.t[self.i]
        self.i += 1
        return tok

    def parse(self):
        n = self.or_expr()
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

    def not_expr(self, neg=False):
        if self.peek() == ("word", "not"):
            self.eat()
            return self.not_expr(not neg)
        if self.peek() == ("par", "("):
            self.eat()
            n = self.or_expr()
            assert self.eat() == ("par", ")")
            return _negate(n) if neg else n
        return self.cmp(neg)

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
                items.append(v)
            if len(items) == 1 and items[0] in self.lists:
                return list(self.lists[items[0]])
            out = []
            for it in items:
                out.extend(self.lists.get(it, [it]))
            return out
        if kind == "word" and val in self.lists:
            return list(self.lists[val])
        return val

    def cmp(self, neg):
        _, field = self.eat()
        kind, op = self.eat()
        if kind == "word" and op in _KW_OPS - {"exists"} or kind == "op":
            val = self.value()
            return ("cmp", field, op, val, neg)
        if kind == "word" and op == "exists":
            return ("cmp", field, "exists", None, neg)
        raise ValueError(f"bad comparison at {field} {op}")


def _negate(n):
    if n[0] == "cmp":
        return (n[0], n[1], n[2], n[3], not n[4])
    kind = "or" if n[0] == "and" else "and"
    return (kind, [_negate(c) for c in n[1]])


def parse_condition(cond: str, lists: Optional[Dict[str, List[str]]] = None):
    return _Parser(tokenize(" ".join(cond.split())), lists or {}).parse()


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
        return se in {str(v) for v in val}
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
    if op in ("<", "<=", ">", ">="):
        try:
            a, b = float(ev), float(val)
        except (TypeError, ValueError):
            return None
        return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]
    return None


def eval_leaf(leaf, event: Dict[str, Any]) -> Optional[bool]:
    _, field, op, val, neg = leaf
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
