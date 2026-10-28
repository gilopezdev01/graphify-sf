"""
graphify-sf: Enhanced Apex parser (classes, triggers, SOQL/DML, governor hints).

Regex-based parser for Apex ``*.cls`` / ``*.trigger`` files (ADR-019 — regex
first, tree-sitter deferred to Phase 3). It extracts:

    - The class / trigger definition node. Identity comes from the file name
      (``<Name>.cls`` / ``<Name>.trigger``) and the kind from the extension, so
      a ``class`` / ``trigger`` word inside a comment can never rename or
      re-type the node. The raw source rides along as the transient ``_source``
      attribute for the CPQ / governor passes; ``extract_sf`` drops it.
    - Method signatures (``member_of`` edge back to the owning class).
    - ``triggers_on`` edge from a trigger to its SObject (with the DML events).
    - SOQL queries (``queries`` edge -> SObject, ``sf_in_loop`` tagged): inline
      ``[SELECT ...]`` sites are EXTRACTED; query-shaped string literals (dynamic
      SOQL) are INFERRED with ``sf_dynamic``.
    - DML operations (``dml_operates_on`` edge -> SObject, ``sf_in_loop`` tagged).
    - ``implements`` of well-known interfaces (QCP, Database.Batchable hint).
    - ``reads_setting`` edge per Custom Setting read (``Cfg__c.getInstance()`` /
      ``getOrgDefaults()`` / ``getValues()`` / ``getAll()``), plus a field read
      for ``Cfg__c.getOrgDefaults().Field__c``.
    - ``uses_label`` per ``System.Label.X`` / ``Label.X`` (strict: dropped
      unless the repo defines the label — ``label`` may be a variable).

CRITICAL (ADR-002): every SObject node ID is built via ``constants.sobject_nid()``
so the Apex, Flow and Object parsers converge on the same node in
``build_graph()``. Cross-file resolution depends on it.

The ``sf_in_loop`` flags feed the governor-limit analysis pass (Pass SF-4):
SOQL/DML detected inside a ``for``/``while`` body is the signal for
``governor_violation`` diagnostics.

Limitations (ADR-019, accepted): nested classes, generic-type element
resolution, and method overloads are not fully modelled; DML targets are
resolved from light variable-type tracking and fall back to an ``unknown``
SObject (``sf_ambiguous``) when the type cannot be inferred. No method-body AST
analysis — regex only.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from graphify.salesforce.field_refs import field_ref
from graphify.salesforce.references import APEX_LABEL_RE, named_refs
from graphify.salesforce.constants import (
    CPQ_QCP_INTERFACE,
    apex_method_nid,
    apex_nid,
    sobject_nid,
    sobject_stub,
)

# ---------------------------------------------------------------------------
# Regexes
# ---------------------------------------------------------------------------

#: Type declaration in a ``.cls`` file, matched on comment/string-stripped code.
_TYPE_DECL_RE = re.compile(r"\b(class|interface|enum)\s+(\w+)", re.IGNORECASE)

#: ``trigger <Name> on <SObject> (<events>)``, matched on stripped code.
_TRIGGER_DECL_RE = re.compile(
    r"\btrigger\s+(\w+)\s+on\s+(\w+)\s*\(([^)]*)\)", re.IGNORECASE
)

#: Method signature. A visibility modifier is REQUIRED to avoid matching control
#: flow (``else if (...)``, ``for (...)``) as methods. Captures return type,
#: name and the raw parameter list. Modifiers come in any order, return types may
#: be dotted / nested generics / arrays (``Map<Id, List<Database.SaveResult>>``),
#: and the parameter list may span several lines.
_METHOD_RE = re.compile(
    r"\b(public|private|protected|global)\s+"
    r"(?:(?:static|override|virtual|abstract|final|testmethod|webservice)\s+)*"
    r"([\w.]+(?:\s*<(?:[^<>]|<(?:[^<>]|<[^<>]*>)*>)*>)?(?:\s*\[\s*\])?)\s+(\w+)\s*\(([^)]*)\)",
    re.IGNORECASE,
)

#: ``FROM <Object>`` closing a query that was split across concatenated literals
#: (``'SELECT Id, Name ' + 'FROM Account WHERE ' + clause``). Upper-case ``FROM``
#: and a capitalized object keep ordinary prose in literals from matching.
_SPLIT_FROM_RE = re.compile(
    r"(?:^|\s)FROM\s+([A-Z]\w*)(?=\s*$|\s+(?i:WHERE|ORDER|GROUP|LIMIT|WITH|USING)\b)"
)

#: Inline SOQL ``[SELECT ... ]`` on comment/string-stripped code. The bracket
#: bounds the query, so multi-line field lists are captured and a stray
#: ``SELECT`` never runs on into the next statement's ``FROM``.
_INLINE_SOQL_RE = re.compile(r"\[\s*(SELECT\b.*?)\]", re.IGNORECASE | re.DOTALL)

#: A string literal that is itself a query (dynamic SOQL text).
_STRING_SOQL_RE = re.compile(r"\bSELECT\b.*\bFROM\s+\w+", re.IGNORECASE | re.DOTALL)

#: Semi-join ``Id [NOT] IN (SELECT AccountId FROM Contact ...)`` — a query on a
#: second object, not a child relationship.
_SEMI_JOIN_RE = re.compile(
    r"\bIN\s*\(\s*(SELECT\b(?:[^()]|\([^()]*\))*?\bFROM\s+\w+(?:[^()]|\([^()]*\))*)\)",
    re.IGNORECASE | re.DOTALL,
)

#: Child-relationship subquery ``(SELECT ... FROM Contacts ...)``. One level of
#: nested parentheses is allowed (``WHERE Status NOT IN ('A', 'B')``).
_SUBQUERY_RE = re.compile(
    r"\(\s*SELECT\b((?:[^()]|\([^()]*\))*?)\bFROM\s+(\w+)(?:[^()]|\([^()]*\))*\)",
    re.IGNORECASE | re.DOTALL,
)

#: Main ``SELECT <fields> FROM <object> <rest>`` once subqueries are removed.
_MAIN_SOQL_RE = re.compile(r"SELECT\b(.*?)\bFROM\s+(\w+)(.*)$", re.IGNORECASE | re.DOTALL)

#: A query whose text is built at run time: object unknowable statically.
_DYNAMIC_QUERY_CALL_RE = re.compile(
    r"\bDatabase\s*\.\s*(?:query|queryWithBinds|getQueryLocator|countQuery)\s*\(\s*(?!\[)",
    re.IGNORECASE,
)

#: DML statement on a variable: ``update opps;`` (stripped code only).
_DML_RE = re.compile(
    r"\b(insert|update|upsert|delete|undelete)\s+(\w+)\s*;", re.IGNORECASE
)
#: DML on a constructor: ``insert new Account(Name = 'x');``.
_DML_NEW_RE = re.compile(
    r"\b(insert|update|upsert|delete|undelete)\s+new\s+(\w+)\s*\(", re.IGNORECASE
)
#: DML on an inline query: ``delete [SELECT Id FROM Obj WHERE ...];`` /
#: ``Database.delete([SELECT ...])`` — the object is the query's ``FROM``.
_DML_QUERY_RE = re.compile(
    r"\b(insert|update|upsert|delete|undelete)\w*\s*\(?\s*\[\s*select\b[^\]]*?\bfrom\s+(\w+)",
    re.IGNORECASE,
)
#: ``Database.update(opps, false)``.
_DATABASE_DML_RE = re.compile(
    r"\bDatabase\s*\.\s*(insert|update|upsert|delete|undelete)\w*\s*\(\s*(\w+)",
    re.IGNORECASE,
)

#: for / while loop header (used to bracket loop bodies for in-loop detection).
_LOOP_RE = re.compile(r"\b(?:for|while)\s*\([^)]*\)\s*\{")

#: Collection declaration: ``List<Opportunity> opps`` -> opps maps to Opportunity.
_COLLECTION_DECL_RE = re.compile(r"(?:List|Set)\s*<\s*(\w+)\s*>\s+(\w+)")

#: Simple declaration / parameter: ``Account acc`` (type must be capitalized).
_SIMPLE_DECL_RE = re.compile(r"\b([A-Z]\w*)\s+(\w+)\s*[;:=)]")

#: Apex / collection types that are not SObjects — excluded from DML resolution.
_NON_SOBJECT_TYPES = {
    "String", "Integer", "Long", "Decimal", "Double", "Boolean", "Id",
    "Date", "Datetime", "Time", "Blob", "Object", "List", "Set", "Map",
    "Trigger", "System", "Database", "void", "SObject",
}


def strip_apex(source: str) -> tuple[str, list[tuple[int, str]]]:
    """Blank out comments and string-literal contents, preserving offsets.

    Returns ``(code, strings)``: ``code`` has the same length and line breaks as
    ``source`` (so match offsets map to the same line numbers), with comments
    replaced by spaces and string contents blanked between their quotes;
    ``strings`` lists ``(offset, literal)`` for every string literal.
    """
    out: list[str] = []
    strings: list[tuple[int, str]] = []
    i, n = 0, len(source)
    while i < n:
        c = source[i]
        if c == "/" and source.startswith("/", i + 1):
            j = source.find("\n", i)
            j = n if j == -1 else j
            out.append(" " * (j - i))
            i = j
        elif c == "/" and source.startswith("*", i + 1):
            j = source.find("*/", i + 2)
            j = n if j == -1 else j + 2
            out.append(re.sub(r"[^\n]", " ", source[i:j]))
            i = j
        elif c == "'":
            j = i + 1
            while j < n and source[j] not in "'\n":
                j += 2 if source[j] == "\\" else 1
            j = min(j, n)
            literal = source[i + 1:j]
            strings.append((i, literal))
            if j < n and source[j] == "'":
                out.append("'" + " " * len(literal) + "'")
                i = j + 1
            else:
                out.append("'" + " " * len(literal))
                i = j
        else:
            out.append(c)
            i += 1
    return "".join(out), strings


#: Typed declarations (stripped code): ``List<Account> accs``, ``Set<Lead> s``,
#: ``Map<Id, Contact> m``, ``Account[] arr``, ``Account a`` / parameters, and
#: ``for (Opportunity o : ...)``. Captures (type, variable).
_FIELD_DECL_RES = (
    re.compile(r"\b(?:List|Set)\s*<\s*(\w+)\s*>\s+(\w+)\s*[=;,):]", re.IGNORECASE),
    re.compile(r"\bMap\s*<\s*\w+\s*,\s*(\w+)\s*>\s+(\w+)\s*[=;,):]", re.IGNORECASE),
    re.compile(r"\b(\w+)\s*\[\s*\]\s+(\w+)\s*[=;,):]"),
    re.compile(r"\bfor\s*\(\s*(\w+)\s+(\w+)\s*:", re.IGNORECASE),
    re.compile(r"\b([A-Za-z]\w*)\s+(\w+)\s*[=;,):]"),
)

#: ``var.Field`` / ``var.Rel.Field`` with an optional call / assignment after.
_MEMBER_ACCESS_RE = re.compile(r"(?<![\w.])(\w+)\s*\.\s*(\w+)(?:\s*\.\s*(\w+))?(\s*\()?")

#: ``new Account(Name = 'x', Tier__c = t)`` — constructor field writes.
_SOBJECT_CTOR_RE = re.compile(r"\bnew\s+(\w+)\s*\(([^()]*)\)")

#: Members that look like ``var.x`` but are not fields.
_NON_FIELD_MEMBERS = frozenset({
    "sobjecttype", "getsobjecttype", "fields", "getdescribe", "class", "fieldsets",
    "size", "isempty", "keyset", "values", "add", "addall", "put", "get", "clear",
    "contains", "containskey", "remove", "clone", "length", "tostring",
})


def _field_access_refs(code: str, class_id: str, path: Path) -> list[dict]:
    """Field reads / writes through typed variables and SObject constructors.

    The declared type is only a *candidate* SObject here; ``require_object``
    lets the graph-wide resolver drop types that turn out to be Apex classes.
    """
    var_types: dict[str, str] = {}
    for regex in _FIELD_DECL_RES:
        for match in regex.finditer(code):
            type_name, var = match.group(1), match.group(2)
            if type_name not in _NON_SOBJECT_TYPES and type_name.lower() not in (
                    "return", "new", "else", "throw"):
                var_types.setdefault(var.lower(), type_name)

    refs: list[dict] = []

    def add(obj: str, field_path: str, relation: str, offset: int) -> None:
        refs.append(field_ref(
            class_id, obj, field_path, relation, path, confidence="INFERRED",
            confidence_value=0.8, require_object=True,
            source_location=f"L{code.count(chr(10), 0, offset) + 1}",
        ))

    for match in _MEMBER_ACCESS_RE.finditer(code):
        var, first, second, call = match.groups()
        obj = var_types.get(var.lower())
        if obj is None or first.lower() in _NON_FIELD_MEMBERS:
            continue
        if call and not second:
            continue  # var.method(...)
        if second and call:
            add(obj, first, "reads_field", match.start())  # var.Rel.method()
            continue
        field_path = f"{first}.{second}" if second else first
        is_write = bool(re.match(r"\s*[+\-*/]?=(?!=)", code[match.end():match.end() + 4]))
        add(obj, field_path, "writes_field" if is_write else "reads_field", match.start())

    for match in _SOBJECT_CTOR_RE.finditer(code):
        for assignment in re.finditer(r"(\w+)\s*=(?!=)", match.group(2)):
            add(match.group(1), assignment.group(1), "writes_field", match.start())
    return refs


def _soql_field_refs(site: dict, class_id: str, path: Path) -> list[dict]:
    """``reads_field`` references for a SOQL site's SELECT / WHERE fields and
    one child reference per relationship subquery."""
    soql = site["soql"]
    attrs = {"source_location": f"L{site['line']}"}
    if site["dynamic"]:
        attrs.update(confidence="INFERRED", confidence_value=0.7, sf_dynamic=True)
    else:
        attrs["confidence"] = "EXTRACTED"
    refs = [field_ref(class_id, soql["object"], field, "reads_field", path, **attrs)
            for field in (*soql["select"], *soql["where"])]
    for relationship, fields in soql["children"]:
        refs.append({"source": class_id, "object": soql["object"], "child": relationship,
                     "paths": fields, "source_file": str(path),
                     "sf_in_loop": site["in_loop"], **attrs})
    return refs


def _find_loop_ranges(source: str) -> list[tuple[int, int]]:
    """Return ``(start_line, end_line)`` ranges for each for/while loop body.

    Uses simple brace matching from the loop header's opening ``{`` to its
    matching ``}``. Nested loops yield nested (overlapping) ranges, which is
    fine — a line is "in a loop" if it falls inside any range.
    """
    ranges: list[tuple[int, int]] = []
    for match in _LOOP_RE.finditer(source):
        start_line = source[: match.start()].count("\n") + 1
        depth = 1
        pos = match.end()
        while depth > 0 and pos < len(source):
            ch = source[pos]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            pos += 1
        end_line = source[:pos].count("\n") + 1
        ranges.append((start_line, end_line))
    return ranges


def _in_loop(line_no: int, loop_ranges: list[tuple[int, int]]) -> bool:
    return any(start <= line_no <= end for start, end in loop_ranges)


def _build_var_types(source: str) -> dict[str, str]:
    """Map local/param variable names to their (capitalized) declared type.

    Light, regex-only type tracking to resolve DML targets like ``update opps``
    to a concrete SObject. Collections (``List<Opportunity> opps``) resolve to
    the element type. Best-effort: unresolved variables fall back to ``unknown``.
    """
    var_types: dict[str, str] = {}
    for m in _COLLECTION_DECL_RE.finditer(source):
        var_types[m.group(2)] = m.group(1)
    for m in _SIMPLE_DECL_RE.finditer(source):
        type_name, var_name = m.group(1), m.group(2)
        if type_name in _NON_SOBJECT_TYPES:
            continue
        var_types.setdefault(var_name, type_name)
    return var_types


def _is_sobject_name(name: str) -> bool:
    """Reject tokens that a ``FROM`` clause can name but are not SObject roots.

    A child-relationship subquery (``SELECT Id, (SELECT Id FROM Contacts__r) ...``)
    puts a ``__r`` relationship name after ``FROM`` — that is a traversal, never a
    queryable SObject, so it must not become an ``sobject`` node (real-org label
    mis-extraction; ADR-019). Non-SObject keywords are filtered too.
    """
    return not name.lower().endswith("__r") and name not in _NON_SOBJECT_TYPES


def parse_soql(query: str) -> dict | None:
    """Split one SOQL statement into its object, field paths and subqueries.

    Returns ``{"object", "select", "where", "children", "semi_joins"}`` where
    ``select`` / ``where`` are field paths as written (``Name``,
    ``Account.Owner.Name``), ``children`` is ``[(relationship_name, [field
    paths])]`` for each ``(SELECT ... FROM <relationship>)`` subquery and
    ``semi_joins`` holds the parsed ``IN (SELECT ...)`` queries. ``None`` if no
    ``FROM``.
    """
    children: list[tuple[str, list[str]]] = []
    semi_joins: list[dict] = []

    def take_semi_join(match):
        inner = parse_soql(match.group(1))
        if inner:
            semi_joins.append(inner)
        return "IN ( )"

    def take(match):
        children.append((match.group(2), _soql_select_fields(match.group(1))))
        return " "

    flat = _SUBQUERY_RE.sub(take, _SEMI_JOIN_RE.sub(take_semi_join, query))
    main = _MAIN_SOQL_RE.search(flat)
    if not main:
        return None
    select, sobject, rest = main.groups()
    where = re.split(
        r"\b(?:ORDER\s+BY|LIMIT|GROUP\s+BY|OFFSET|FOR\s+(?:UPDATE|VIEW|REFERENCE)|WITH)\b",
        rest, flags=re.IGNORECASE,
    )[0]
    where_fields = [
        m.group(1) for m in re.finditer(
            r"([A-Za-z]\w*(?:\.\w+)*)\s*(?:!=|<>|<=|>=|=|<|>|\bLIKE\b|\bNOT\s+IN\b|\bIN\b|"
            r"\bINCLUDES\b|\bEXCLUDES\b)",
            where, re.IGNORECASE,
        )
        if m.group(1).upper() not in ("WHERE", "AND", "OR", "NOT")
    ]
    return {
        "object": sobject,
        "select": _soql_select_fields(select),
        "where": where_fields,
        "children": children,
        "semi_joins": semi_joins,
    }


def _soql_select_fields(select: str) -> list[str]:
    """Field paths of a SELECT list (``COUNT(Id)`` -> ``Id``; TYPEOF/FIELDS dropped)."""
    fields: list[str] = []
    for item in select.split(","):
        item = item.strip()
        func = re.match(r"^\w+\s*\((.*)\)", item)
        if func:
            item = func.group(1).strip()
        token = re.match(r"^([A-Za-z]\w*(?:\.\w+)*)", item)
        if token and token.group(1).upper() not in ("TYPEOF", "FIELDS"):
            fields.append(token.group(1))
    return fields


def _detect_soql(code: str, strings: list[tuple[int, str]]) -> list[dict]:
    """SOQL sites in stripped *code* plus query-shaped string literals.

    Each site: ``{"soql", "offset", "line", "in_loop", "dynamic"}`` where
    ``soql`` is ``parse_soql``'s result. Inline ``[SELECT ...]`` sites are
    static; a string literal that reads as a query is ``dynamic`` (it is passed
    to ``Database.query`` or similar, so the call site is inferred, not seen).
    """
    loop_ranges = _find_loop_ranges(code)
    sites: list[dict] = []
    candidates = [(m.start(1), m.group(1), False) for m in _INLINE_SOQL_RE.finditer(code)]
    candidates += [(pos, lit, True) for pos, lit in strings if _STRING_SOQL_RE.search(lit)]
    # Dynamic SOQL split across concatenated literals: when the file builds a
    # SELECT in some literal, a literal carrying only the ``FROM <Object>`` part
    # names the queried object.
    if any(re.search(r"\bSELECT\b", lit, re.IGNORECASE) for _pos, lit in strings):
        for pos, lit in strings:
            split_from = _SPLIT_FROM_RE.search(lit)
            if split_from and not _STRING_SOQL_RE.search(lit):
                candidates.append((pos, "SELECT Id " + lit[split_from.start():], True))
    for offset, text, dynamic in sorted(candidates):
        soql = parse_soql(text)
        if soql is None:
            continue
        line_no = code.count("\n", 0, offset) + 1
        for query in (soql, *soql["semi_joins"]):
            if not _is_sobject_name(query["object"]):
                continue
            sites.append({
                "soql": query, "offset": offset, "line": line_no,
                "in_loop": _in_loop(line_no, loop_ranges), "dynamic": dynamic,
            })
    return sites


def _detect_dml_operations(
    code: str, var_types: dict[str, str]
) -> list[tuple[str, str, int, bool]]:
    """Detect DML statements in stripped *code*.

    Returns ``(dml_type, sobject_name, line_no, in_loop, var_typed)``.
    ``sobject_name`` is read from ``new <Type>(...)`` or an inline query's
    ``FROM``, or resolved from
    variable-type tracking (``var_typed`` — only a candidate until
    ``extract_sf`` confirms it is an SObject), or ``"unknown"``.
    """
    loop_ranges = _find_loop_ranges(code)
    found: list[tuple[int, str, str, bool]] = []
    for regex in (_DML_RE, _DATABASE_DML_RE):
        for match in regex.finditer(code):
            sobject = var_types.get(match.group(2), "unknown")
            found.append((match.start(), match.group(1).upper(), sobject,
                          sobject != "unknown"))
    for regex in (_DML_NEW_RE, _DML_QUERY_RE):
        for match in regex.finditer(code):
            found.append((match.start(), match.group(1).upper(), match.group(2), False))
    results: list[tuple[str, str, int, bool, bool]] = []
    for offset, dml_type, sobject, var_typed in sorted(found):
        line_no = code.count("\n", 0, offset) + 1
        results.append((dml_type, sobject, line_no,
                        _in_loop(line_no, loop_ranges), var_typed))
    return results


def _ensure_sobject_node(
    nodes: list[dict], sobject_id: str, api_name: str, path: Path
) -> None:
    """Append a stub ``sobject`` node for *sobject_id* if not already present.

    Keeps cross-file edges (queries / dml_operates_on) non-dangling within this
    result; ``extract_sf`` replaces the stub with the object's own definition via
    the shared ``sobject_nid`` (ADR-002, ADR-012).
    """
    if any(n["id"] == sobject_id for n in nodes):
        return
    node = sobject_stub(api_name, path)
    if api_name == "unknown":
        node["sf_ambiguous"] = True
    nodes.append(node)


def extract_apex_enhanced(path: Path) -> dict:
    """Parse an Apex class / trigger file into graph nodes and edges.

    Returns:
        ``{"nodes": [...], "edges": [...]}``. If no class/trigger declaration is
        found, returns empty lists plus an ``"error"`` key (ADR-009 lenient: the
        caller skips the file and keeps analyzing).
    """
    path = Path(path)
    with open(path, "r", encoding="utf-8") as f:
        source = f.read()
    code, _strings = strip_apex(source)

    nodes: list[dict] = []
    edges: list[dict] = []

    # 1. Class / trigger definition --------------------------------------
    name = path.name.split(".")[0]
    is_trigger = path.suffix == ".trigger"
    trigger_decl = _TRIGGER_DECL_RE.search(code) if is_trigger else None
    type_decl = None if is_trigger else _TYPE_DECL_RE.search(code)
    # Managed-package classes ship with the body "(hidden)": real classes
    # (profiles grant access to them) whose contents cannot be analyzed.
    hidden = source.strip() == "(hidden)"
    if not (trigger_decl or type_decl or hidden):
        return {"nodes": [], "edges": [], "error": "No class/trigger found"}

    class_id = apex_nid(name)
    nodes.append(
        {
            "id": class_id,
            "label": name,
            "file_type": "code",
            "source_file": str(path),
            "sf_qualified_name": name,
            "sf_code_type": (
                "trigger" if is_trigger
                else type_decl.group(1).lower() if type_decl else "class"
            ),
            "sf_loc": source.count("\n") + 1,
            "sf_source_hash": hashlib.sha256(source.encode("utf-8")).hexdigest()[:16],
            "_source": source,
        }
    )

    if hidden:
        nodes[0]["sf_managed_hidden"] = True
        return {"nodes": nodes, "edges": edges}

    if trigger_decl:
        sobject_name = trigger_decl.group(2)
        target_id = sobject_nid(sobject_name)
        _ensure_sobject_node(nodes, target_id, sobject_name, path)
        events = [" ".join(e.split()).lower() for e in trigger_decl.group(3).split(",")]
        edges.append(
            {
                "source": class_id,
                "target": target_id,
                "relation": "triggers_on",
                "confidence": "EXTRACTED",
                "source_file": str(path),
                "sf_trigger_events": [e for e in events if e],
            }
        )

    # 2. Method signatures ------------------------------------------------
    methods: dict[str, dict] = {}
    for method in _METHOD_RE.finditer(code):
        return_type, method_name, params = (
            method.group(2),
            method.group(3),
            method.group(4),
        )
        signature = f"{method_name}({' '.join(params.split())})"
        method_id = apex_method_nid(name, method_name)
        existing = methods.get(method_id)
        if existing is not None:
            existing["sf_signatures"].append(signature)
            continue
        methods[method_id] = {
            "id": method_id,
            "label": f"{name}.{method_name}",
            "file_type": "code",
            "source_file": str(path),
            "sf_qualified_name": f"{name}.{method_name}",
            "sf_return_type": return_type,
            "sf_method_type": "method",
            "sf_signatures": [signature],
            "source_location": f"L{source.count(chr(10), 0, method.start()) + 1}",
        }
        edges.append(
            {
                "source": method_id,
                "target": class_id,
                "relation": "member_of",
                "confidence": "EXTRACTED",
                "source_file": str(path),
            }
        )
    nodes.extend(methods.values())

    # 3. SOQL queries (cross-file resolution) -----------------------------
    field_refs: list[dict] = []
    for site in _detect_soql(code, _strings):
        field_refs.extend(_soql_field_refs(site, class_id, path))
        sobject_name = site["soql"]["object"]
        target_id = sobject_nid(sobject_name)
        _ensure_sobject_node(nodes, target_id, sobject_name, path)
        edge = {
            "source": class_id,
            "target": target_id,
            "relation": "queries",
            "confidence": "EXTRACTED",
            "sf_in_loop": site["in_loop"],
            "source_location": f"L{site['line']}",
            "source_file": str(path),
        }
        if site["dynamic"]:
            edge.update(confidence="INFERRED", confidence_value=0.7, sf_dynamic=True)
        edges.append(edge)
    if _DYNAMIC_QUERY_CALL_RE.search(code):
        nodes[0]["sf_dynamic_soql"] = True

    # 4. DML operations ---------------------------------------------------
    var_types = _build_var_types(code)
    for dml_type, sobject_name, line_no, in_loop, var_typed in _detect_dml_operations(
        code, var_types
    ):
        target_id = sobject_nid(sobject_name)
        _ensure_sobject_node(nodes, target_id, sobject_name, path)
        edge: dict = {
            "source": class_id,
            "target": target_id,
            "relation": "dml_operates_on",
            "sf_dml_type": dml_type,
            "confidence": "INFERRED",
            "sf_in_loop": in_loop,
            "confidence_value": 0.85 if in_loop else 0.9,
            "source_location": f"L{line_no}",
            "source_file": str(path),
        }
        if sobject_name == "unknown":
            edge["sf_ambiguous"] = True
        elif var_typed:
            edge["sf_var_typed"] = True
        edges.append(edge)

    # 5. Implements (QCP / Batchable hint) --------------------------------
    if (
        f"implements {CPQ_QCP_INTERFACE}" in code
        or "implements QuoteCalculatorPlugin" in code
    ):
        qcp_id = "sbqq_quotecalculatorplugin"
        if not any(n["id"] == qcp_id for n in nodes):
            nodes.append(
                {
                    "id": qcp_id,
                    "label": CPQ_QCP_INTERFACE,
                    "file_type": "code",
                    "source_file": str(path),
                    "sf_qualified_name": CPQ_QCP_INTERFACE,
                    "sf_code_type": "interface",
                    "sf_stub": True,
                }
            )
        edges.append(
            {
                "source": class_id,
                "target": qcp_id,
                "relation": "implements",
                "confidence": "EXTRACTED",
                "source_file": str(path),
            }
        )

    if "implements Database.Batchable" in code:
        nodes[0]["sf_async_pattern"] = "batchable"

    field_refs.extend(_field_access_refs(code, class_id, path))

    # 6. Custom Setting reads (``Cfg__c.getInstance()`` and friends) ------------
    for setting, line_no in _detect_setting_access(code):
        target_id = sobject_nid(setting)
        _ensure_sobject_node(nodes, target_id, setting, path)
        edges.append({
            "source": class_id, "target": target_id, "relation": "reads_setting",
            "confidence": "EXTRACTED", "source_location": f"L{line_no}",
            "source_file": str(path),
        })
    for match in _SETTING_FIELD_RE.finditer(code):
        field_refs.append(field_ref(
            class_id, match.group(1), match.group(2), "reads_field", path,
            confidence="EXTRACTED",
            source_location=f"L{code.count(chr(10), 0, match.start()) + 1}"))

    # 7. Custom Labels (``System.Label.X``; strict — ``label`` may be a variable)
    label_nodes, label_edges = named_refs(
        class_id, "label", (m.group(1) for m in APEX_LABEL_RE.finditer(code)), path,
        strict=True)
    nodes.extend(label_nodes)
    edges.extend(label_edges)
    return {"nodes": nodes, "edges": edges, "field_refs": field_refs}


#: ``Cfg__c.getInstance(...)`` / ``getOrgDefaults()`` / ``getValues(...)`` /
#: ``getAll()`` — the Custom Setting accessor methods.
_SETTING_ACCESS_RE = re.compile(
    r"(?<![\w.])(\w+__c)\s*\.\s*(?:getInstance|getOrgDefaults|getValues|getAll)\s*\(",
    re.IGNORECASE)

#: ``Cfg__c.getOrgDefaults().Field__c`` — a field read straight off the accessor.
_SETTING_FIELD_RE = re.compile(
    r"(?<![\w.])(\w+__c)\s*\.\s*(?:getInstance|getOrgDefaults|getValues)\s*"
    r"\((?:[^()]|\([^()]*\))*\)\s*\.\s*(\w+__c)\b",
    re.IGNORECASE)


def _detect_setting_access(code: str) -> list[tuple[str, int]]:
    """``(setting API name, first line)`` per Custom Setting read in *code*."""
    first: dict[str, tuple[str, int]] = {}
    for match in _SETTING_ACCESS_RE.finditer(code):
        name = match.group(1)
        if name.lower() not in first:
            first[name.lower()] = (name, code.count("\n", 0, match.start()) + 1)
    return list(first.values())
