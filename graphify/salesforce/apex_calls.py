"""
graphify-sf: Apex cross-class call resolution (review items 9 / 16).

Graph-wide pass that links Apex classes / triggers to the Apex classes they
invoke. A per-file parser cannot do this: whether ``Foo.bar()`` is a call into
an Apex class depends on every class in the repo, so the pass runs after all
files are merged and matches against the full set of class names.

Three invocation shapes count, matched case-insensitively (Apex identifiers are
case-insensitive) on comment- and string-stripped code:

    - ``Foo.bar(...)`` / ``Outer.Inner.bar(...)`` — static call (also an
      instance call through a variable named like its class);
    - ``new Foo(...)`` / ``new Outer.Inner(...)`` — instantiation;
    - ``Foo.class`` — type literal handed to a dispatcher / framework.

A bare type declaration (``Foo x;``) is not a call and is ignored. Each caller ->
callee pair becomes one class-level ``calls`` edge, ``INFERRED``: a name match
cannot rule out a local variable that shadows a class name. Dynamic dispatch
(``Type.forName``, handler classes named in Custom Metadata) stays unresolved.

Type declarations (``class A extends B implements C, D``, also on inner
classes) add ``extends`` / ``implements`` edges, ``EXTRACTED``: to the repo's own
classes and interfaces, or to an ``sf_stub`` / ``sf_platform`` node for platform
types (``Database.Batchable``, ``Schedulable``, ``Queueable``, ``Exception``).

Method level: ``Foo.bar(...)`` where ``Foo.bar`` is a parsed method, and
unqualified ``bar(...)`` calls between methods of the same file, add ``calls``
edges from the enclosing method (or the class, outside any method) to the
callee method, ``INFERRED`` and tagged ``sf_method_level``.

CRITICAL (ADR-016): graph-wide pass, never cached per file. Reads the transient
``_source`` the Apex parser leaves on class / trigger nodes; mutates
``all_nodes`` / ``all_edges`` in place.
"""

from __future__ import annotations

import re

from graphify.salesforce.apex_enhanced import _METHOD_RE, strip_apex
from graphify.salesforce.constants import apex_method_nid, apex_nid

#: Class-level Apex code types that can be the target of a call.
_CALLABLE_TYPES = ("class", "interface", "enum")

_STATIC_CALL_RE = re.compile(r"(?<![\w.])(\w+)\s*\.\s*\w+(?:\s*\.\s*\w+)*\s*\(")
_NEW_RE = re.compile(r"\bnew\s+(\w+)(?:\s*\.\s*\w+)*\s*\(", re.IGNORECASE)
_CLASS_LITERAL_RE = re.compile(r"(?<![\w.])(\w+)\s*\.\s*class\b", re.IGNORECASE)
_TYPE_HEADER_RE = re.compile(
    r"\b(?:class|interface)\s+\w+\s*"
    r"(?:extends\s+(?P<extends>[\w.<>,\s]+?))?\s*"
    r"(?:implements\s+(?P<implements>[\w.<>,\s]+?))?\s*\{",
    re.IGNORECASE)


#: ``Foo.bar(`` — a qualified method call (group 1 = class, group 2 = method).
_METHOD_CALL_RE = re.compile(r"(?<![\w.])(\w+)\s*\.\s*(\w+)\s*\(")
#: ``bar(`` — an unqualified call, resolved only against the same file's methods.
_LOCAL_CALL_RE = re.compile(r"(?<![\w.])(\w+)\s*\(")
_NOT_CALLS = frozenset({"if", "for", "while", "switch", "catch", "return", "new", "super", "this"})


def _type_names(clause: str | None) -> list[str]:
    """Full name (generics removed) of each type in an ``extends`` / ``implements`` list."""
    if not clause:
        return []
    clause = re.sub(r"<[^<>]*>", "", re.sub(r"<[^<>]*>", "", clause))
    return [part.strip() for part in clause.split(",") if part.strip()]


def _method_spans(code: str) -> tuple[list[tuple[int, int, str]], set[int]]:
    """``(start, end, name)`` body span per method in stripped *code*, plus the
    offsets of the method names in their own signatures (not calls)."""
    spans: list[tuple[int, int, str]] = []
    declared: set[int] = set()
    for match in _METHOD_RE.finditer(code):
        declared.add(match.start(3))
        brace = re.match(r"\s*\{", code[match.end():])
        if not brace:
            continue  # abstract / interface method
        pos, depth = match.end() + brace.end(), 1
        while depth and pos < len(code):
            depth += {"{": 1, "}": -1}.get(code[pos], 0)
            pos += 1
        spans.append((match.start(), pos, match.group(3)))
    return spans, declared


def _enclosing(spans: list[tuple[int, int, str]], pos: int) -> str | None:
    """Name of the innermost method whose body contains *pos*."""
    inside = [(start, name) for start, end, name in spans if start <= pos < end]
    return max(inside)[1] if inside else None


def apex_calls_pass(all_nodes: list[dict], all_edges: list[dict]) -> None:
    """Append ``calls`` / ``extends`` / ``implements`` edges between Apex code nodes (in place)."""
    callees = {
        str(n["label"]).lower(): n["id"]
        for n in all_nodes
        if n.get("sf_code_type") in _CALLABLE_TYPES and not n.get("sf_stub")
    }
    if not callees:
        return
    node_ids = {n["id"] for n in all_nodes}

    for node in list(all_nodes):
        source = node.get("_source")
        if not source or node.get("sf_code_type") not in (*_CALLABLE_TYPES, "trigger"):
            continue
        code, _strings = strip_apex(source)
        first_seen: dict[str, int] = {}
        for pattern in (_STATIC_CALL_RE, _NEW_RE, _CLASS_LITERAL_RE):
            for match in pattern.finditer(code):
                target = callees.get(match.group(1).lower())
                if target and target != node["id"]:
                    pos = match.start()
                    if pos < first_seen.get(target, len(code)):
                        first_seen[target] = pos
        inherited: dict[tuple[str, str], int] = {}
        for match in _TYPE_HEADER_RE.finditer(code):
            for relation in ("extends", "implements"):
                for name in _type_names(match.group(relation)):
                    target = callees.get(name.split(".")[-1].lower())
                    if target is None:
                        target = apex_nid(name)
                        if target not in node_ids:
                            node_ids.add(target)
                            all_nodes.append({
                                "id": target, "label": name, "file_type": "code",
                                "source_file": node.get("source_file", ""),
                                "sf_qualified_name": name,
                                "sf_code_type": "interface" if relation == "implements" else "class",
                                "sf_stub": True, "sf_platform": True,
                            })
                    if target != node["id"]:
                        inherited.setdefault((relation, target), match.start())
        _method_calls(node, code, callees, node_ids, all_edges)
        for (relation, target), pos in sorted(inherited.items()):
            all_edges.append({
                "source": node["id"],
                "target": target,
                "relation": relation,
                "confidence": "EXTRACTED",
                "source_location": f"L{code.count(chr(10), 0, pos) + 1}",
                "source_file": node.get("source_file", ""),
            })
        for target in sorted(first_seen):
            all_edges.append({
                "source": node["id"],
                "target": target,
                "relation": "calls",
                "confidence": "INFERRED",
                "confidence_value": 0.8,
                "source_location": f"L{code.count(chr(10), 0, first_seen[target]) + 1}",
                "source_file": node.get("source_file", ""),
            })


def _method_calls(node: dict, code: str, callees: dict[str, str], node_ids: set[str],
                  all_edges: list[dict]) -> None:
    """Method-level ``calls`` edges out of one class / trigger (see module docstring)."""
    label = str(node["label"])
    spans, declared = _method_spans(code)
    own = {name.lower() for _start, _end, name in spans}
    first_seen: dict[tuple[str, str], int] = {}

    def add(pos: int, target: str) -> None:
        caller = _enclosing(spans, pos)
        source = apex_method_nid(label, caller) if caller else node["id"]
        if source not in node_ids or source == target:
            return
        key = (source, target)
        if pos < first_seen.get(key, len(code)):
            first_seen[key] = pos

    for match in _METHOD_CALL_RE.finditer(code):
        cls, method = match.group(1), match.group(2)
        if cls.lower() in callees:
            target = apex_method_nid(cls, method)
            if target in node_ids:
                add(match.start(), target)
    for match in _LOCAL_CALL_RE.finditer(code):
        name = match.group(1)
        if (match.start(1) in declared or name.lower() in _NOT_CALLS
                or name.lower() not in own
                or re.search(r"\bnew\s+$", code[max(0, match.start() - 8):match.start()])):
            continue
        target = apex_method_nid(label, name)
        if target in node_ids:
            add(match.start(), target)
    for (source, target), pos in sorted(first_seen.items()):
        all_edges.append({
            "source": source,
            "target": target,
            "relation": "calls",
            "confidence": "INFERRED",
            "confidence_value": 0.8,
            "sf_method_level": True,
            "source_location": f"L{code.count(chr(10), 0, pos) + 1}",
            "source_file": node.get("source_file", ""),
        })
