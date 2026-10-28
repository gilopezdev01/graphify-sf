"""
graphify-sf: Salesforce-specific knowledge graph extraction.

Main API:
- register(): Register SF parsers with graphify's core _DISPATCH table.
- extract_sf(): Extract a Salesforce repository and run the SF analysis passes.

``extract_sf`` is the pipeline wrapper described in ARCHITECTURE.md ("서브패키지
구조" / "분석 패스 실행 순서"): it dispatches each Salesforce file to its parser,
merges the per-file results into one node/edge list (cross-file resolution via
``sobject_nid`` — ADR-002), then runs the graph-wide analysis passes in the fixed
order CPQ -> LWC merge -> OoE -> Governor (ADR-011). Errors degrade gracefully
(ADR-009 lenient): an unreadable / unparseable file is skipped, never aborting
the whole analysis.
"""

from __future__ import annotations

import os
from pathlib import Path

from .constants import sobject_nid, sobject_stub


def register():
    """Register Salesforce parsers with the main graphify pipeline.

    Patches ``extract._DISPATCH`` so the core pipeline routes Salesforce
    metadata suffixes to the SF parsers. ``extract_sf`` does NOT depend on this
    (it dispatches internally), but ``import graphify.salesforce; register()``
    enables SF parsing through the plain ``graphify`` entry points (ADR-014).
    """
    from graphify.extract import _DISPATCH

    from .apex_enhanced import extract_apex_enhanced
    from .flow import extract_flow
    from .lwc import extract_lwc_html, extract_lwc_js
    from .metadata import (
        extract_auth_provider,
        extract_custom_labels,
        extract_custom_metadata_record,
        extract_duplicate_rule,
        extract_email_template,
        extract_layout,
        extract_matching_rules,
        extract_permission_set_group,
        extract_quick_action,
        extract_record_type,
        extract_rule_entries,
        extract_sharing_rules,
        extract_static_resource,
        extract_workflow,
    )
    from .objects import (
        extract_custom_field,
        extract_custom_object,
        extract_validation_rule,
    )
    from .pages import extract_flexipage
    from .profiles import extract_permission_set, extract_profile

    _DISPATCH[".cls"] = extract_apex_enhanced
    _DISPATCH[".trigger"] = extract_apex_enhanced
    _DISPATCH[".flow-meta.xml"] = extract_flow
    _DISPATCH[".object-meta.xml"] = extract_custom_object
    _DISPATCH[".field-meta.xml"] = extract_custom_field
    _DISPATCH[".validationRule-meta.xml"] = extract_validation_rule
    _DISPATCH[".recordType-meta.xml"] = extract_record_type
    _DISPATCH[".workflow-meta.xml"] = extract_workflow
    _DISPATCH[".permissionsetgroup-meta.xml"] = extract_permission_set_group
    _DISPATCH[".md-meta.xml"] = extract_custom_metadata_record
    _DISPATCH[".sharingRules-meta.xml"] = extract_sharing_rules
    _DISPATCH[".labels-meta.xml"] = extract_custom_labels
    _DISPATCH[".profile-meta.xml"] = extract_profile
    _DISPATCH[".permissionset-meta.xml"] = extract_permission_set
    _DISPATCH[".html"] = extract_lwc_html
    _DISPATCH[".js"] = extract_lwc_js
    _DISPATCH[".flexipage-meta.xml"] = extract_flexipage
    _DISPATCH[".assignmentRules-meta.xml"] = extract_rule_entries
    _DISPATCH[".escalationRules-meta.xml"] = extract_rule_entries
    _DISPATCH[".autoResponseRules-meta.xml"] = extract_rule_entries
    _DISPATCH[".duplicateRule-meta.xml"] = extract_duplicate_rule
    _DISPATCH[".matchingRule-meta.xml"] = extract_matching_rules
    _DISPATCH[".authprovider-meta.xml"] = extract_auth_provider
    _DISPATCH[".layout-meta.xml"] = extract_layout
    _DISPATCH[".quickAction-meta.xml"] = extract_quick_action
    _DISPATCH[".email-meta.xml"] = extract_email_template
    _DISPATCH[".resource-meta.xml"] = extract_static_resource


def _parser_for(path: Path):
    """Return the SF parser callable for a file, or ``None`` if unsupported.

    Suffix matching mirrors ``extract._get_extractor`` (ADR-003): multi-part
    ``*.meta.xml`` names are matched on ``name``, while ``.cls`` / ``.trigger``
    match on the plain suffix. ``.html`` / ``.js`` are LWC-only — limited to
    files living under an ``lwc/`` directory so ordinary web assets are ignored.
    """
    from .apex_enhanced import extract_apex_enhanced
    from .flow import extract_flow
    from .lwc import extract_lwc_html, extract_lwc_js
    from .metadata import (
        extract_auth_provider,
        extract_custom_labels,
        extract_custom_metadata_record,
        extract_duplicate_rule,
        extract_email_template,
        extract_layout,
        extract_matching_rules,
        extract_permission_set_group,
        extract_quick_action,
        extract_record_type,
        extract_rule_entries,
        extract_sharing_rules,
        extract_static_resource,
        extract_workflow,
    )
    from .objects import (
        extract_custom_field,
        extract_custom_object,
        extract_validation_rule,
    )
    from .pages import (
        extract_aura_bundle,
        extract_experience_site,
        extract_experience_view,
        extract_flexipage,
    )
    from .profiles import extract_permission_set, extract_profile

    name = path.name
    if name.endswith(".object-meta.xml"):
        return extract_custom_object
    if name.endswith(".validationRule-meta.xml"):
        return extract_validation_rule
    if name.endswith(".recordType-meta.xml"):
        return extract_record_type
    if name.endswith(".workflow-meta.xml"):
        return extract_workflow
    if name.endswith(".permissionsetgroup-meta.xml"):
        return extract_permission_set_group
    if name.endswith(".md-meta.xml"):
        return extract_custom_metadata_record
    if name.endswith(".sharingRules-meta.xml"):
        return extract_sharing_rules
    if name.endswith(".labels-meta.xml"):
        return extract_custom_labels
    if name.endswith(".field-meta.xml"):
        return extract_custom_field
    if name.endswith(".flow-meta.xml"):
        return extract_flow
    if name.endswith(".profile-meta.xml"):
        return extract_profile
    if name.endswith(".permissionset-meta.xml"):
        return extract_permission_set
    if name.endswith(".flexipage-meta.xml"):
        return extract_flexipage
    for suffix, parser in {
        ".assignmentRules-meta.xml": extract_rule_entries,
        ".escalationRules-meta.xml": extract_rule_entries,
        ".autoResponseRules-meta.xml": extract_rule_entries,
        ".duplicateRule-meta.xml": extract_duplicate_rule,
        ".matchingRule-meta.xml": extract_matching_rules,
        ".authprovider-meta.xml": extract_auth_provider,
        ".layout-meta.xml": extract_layout,
        ".quickAction-meta.xml": extract_quick_action,
        ".email-meta.xml": extract_email_template,
        ".resource-meta.xml": extract_static_resource,
    }.items():
        if name.endswith(suffix):
            return parser

    suffix = path.suffix
    if suffix in (".cls", ".trigger"):
        return extract_apex_enhanced
    # experiences/<site>/views/<view>.json — Experience Cloud page definitions.
    if (suffix == ".json" and path.parent.name == "views"
            and path.parent.parent.parent.name == "experiences"):
        return extract_experience_view
    if name.endswith(".site-meta.xml") and path.parent.name == "experiences":
        return extract_experience_site
    # aura/<Bundle>/<Bundle>.cmp|.app — the bundle's markup file.
    if (suffix in (".cmp", ".app") and path.parent.parent.name == "aura"
            and path.stem == path.parent.name):
        return extract_aura_bundle

    # LWC HTML/JS only — guard on an lwc/ directory in the path; Jest specs
    # under __tests__ are not component code.
    parts = {p.lower() for p in path.parts[:-1]}
    is_lwc = "lwc" in parts and "__tests__" not in parts
    if is_lwc and suffix == ".html":
        return extract_lwc_html
    if is_lwc and suffix == ".js":
        return extract_lwc_js

    return None


#: Profile / Permission Set / PSG metadata. Off by default: on a real org their
#: grants_access_to edges are ~80% of all edges (160k of 195k) and drown the
#: code/data structure; opt in with ``include_permissions=True``.
_PERMISSION_SUFFIXES = (
    ".profile-meta.xml",
    ".permissionset-meta.xml",
    ".permissionsetgroup-meta.xml",
)


def _merge_into(all_nodes, node_by_id, node):
    """Merge ``node`` into the accumulated node list, deduping by ``id``.

    A definition (no ``sf_stub``) beats a stub: whichever parser defines the
    entity supplies its label / ``source_file`` / attributes, even when a stub
    emitted by a referencing file (an Apex ``FROM Account``) was seen first.
    Otherwise the first occurrence wins (ADR-012) and later nodes only fill in
    attributes the existing node is missing.
    """
    existing = node_by_id.get(node["id"])
    if existing is None:
        node_by_id[node["id"]] = node
        all_nodes.append(node)
        return
    if existing.get("sf_stub") and not node.get("sf_stub"):
        stub_attrs = dict(existing)
        existing.clear()
        existing.update(node)
        for key, value in stub_attrs.items():
            if key not in existing and key != "sf_stub":
                existing[key] = value
        return
    for key, value in node.items():
        if key in ("id", "label") or (key == "sf_stub" and not existing.get("sf_stub")):
            continue
        if existing.get(key) in (None, "", []) and value not in (None, "", []):
            existing[key] = value


def _resolve_unqualified_fields(all_nodes, all_edges):
    """Rewire object-less field stubs (``field_?.<name>``) to a defined field.

    CPQ conditions and ``__mdt`` mappings sometimes name a field without its
    object. When exactly one defined field in the repo carries that API name the
    stub is replaced by it; otherwise the stub stays, flagged ``sf_unresolved``
    with ``sf_candidate_count`` so the ambiguity is visible, never guessed.
    """
    defined: dict[str, list[str]] = {}
    for node in all_nodes:
        if node.get("file_type") == "field" and node.get("sf_object") and not node.get("sf_stub"):
            defined.setdefault(node["sf_api_name"].lower(), []).append(node["id"])

    rewired: dict[str, str] = {}
    for node in all_nodes:
        if node.get("file_type") != "field" or node.get("sf_object"):
            continue
        candidates = defined.get(str(node.get("sf_api_name", "")).lower(), [])
        if len(candidates) == 1:
            rewired[node["id"]] = candidates[0]
        else:
            node["sf_candidate_count"] = len(candidates)

    if not rewired:
        return
    for edge in all_edges:
        edge["source"] = rewired.get(edge["source"], edge["source"])
        edge["target"] = rewired.get(edge["target"], edge["target"])
    all_nodes[:] = [n for n in all_nodes if n["id"] not in rewired]


def _relativize_paths(all_nodes, all_edges, base: Path):
    """Rewrite ``source_file`` values under *base* as repo-relative POSIX paths.

    The graph is shared and committed; an absolute path leaks the extracting
    machine's layout and makes two checkouts of the same repo diff everywhere.
    Values outside *base* (e.g. the ``cpq_data`` marker) are left as they are.
    """
    base = base.resolve()
    cache: dict[str, str] = {}

    def rel(value):
        if not isinstance(value, str) or not value:
            return value
        if value not in cache:
            try:
                cache[value] = Path(value).resolve().relative_to(base).as_posix()
            except ValueError:
                cache[value] = value
        return cache[value]

    for item in (*all_nodes, *all_edges):
        if "source_file" in item:
            item["source_file"] = rel(item["source_file"])


def _confirm_var_typed_dml(all_nodes, all_edges):
    """Re-target DML edges whose object came only from a variable's declared type.

    ``update rows;`` with ``List<RowWrapper> rows`` would otherwise invent an
    SObject named after an Apex class (or ``Id`` / ``HttpResponse``). The type
    is kept only when other evidence says it is an SObject — it is defined,
    queried, triggered on, looked up or written by a Flow — and it is not an
    Apex type; otherwise the edge points at the ``unknown`` SObject
    (``sf_ambiguous``) and stubs left without edges are removed.
    """
    apex_types = {
        str(n.get("label", "")).lower() for n in all_nodes
        if n.get("sf_code_type") in ("class", "interface", "enum")
    }
    evidence = {n["id"] for n in all_nodes
                if n.get("file_type") == "sobject" and not n.get("sf_stub")}
    evidence |= {e["target"] for e in all_edges if not e.get("sf_var_typed")}
    by_id = {n["id"]: n for n in all_nodes}

    unknown = sobject_nid("unknown")
    changed = False
    for edge in all_edges:
        if not edge.get("sf_var_typed"):
            continue
        label = str(by_id.get(edge["target"], {}).get("label", "")).lower()
        if edge["target"] in evidence and label not in apex_types:
            continue
        edge["target"] = unknown
        edge["sf_ambiguous"] = True
        edge.pop("sf_var_typed")
        changed = True
    if not changed:
        return
    if unknown not in by_id:
        stub = sobject_stub("unknown", "")
        stub["sf_ambiguous"] = True
        all_nodes.append(stub)
    referenced = {e["source"] for e in all_edges} | {e["target"] for e in all_edges}
    all_nodes[:] = [
        n for n in all_nodes
        if not (n.get("file_type") == "sobject" and n.get("sf_stub")
                and n["id"] not in referenced)
    ]


def _drop_transient_attrs(all_nodes):
    """Remove ``_``-prefixed working attributes (e.g. Apex ``_source``).

    They exist only so analysis passes can read parser state; the graph carries
    structure, never source code.
    """
    for node in all_nodes:
        for key in [k for k in node if k.startswith("_")]:
            del node[key]


def _merge_lwc_components(all_nodes, all_edges):
    """LWC merge pass (Pass SF-2 / ADR-008): fold each ``*.html`` template node
    into its sibling ``*.js`` controller node so one ``lwc_component`` node
    remains per component.

    The HTML parser emits ``lwc_<stem>_html``; the JS parser emits ``lwc_<stem>``.
    When both exist we keep the JS node (it carries the ``@wire`` / ``@api``
    signal) and drop the HTML node, tagging the survivor ``sf_has_template``.
    A template-only component is promoted to the base ID so it is still a single
    ``lwc_component`` node.
    """
    node_by_id = {n["id"]: n for n in all_nodes}
    html_nodes = [n for n in all_nodes if n.get("sf_lwc_file_type") == "html"]
    renamed: dict[str, str] = {}
    for html in html_nodes:
        html_id = html["id"]
        base_id = html_id[: -len("_html")] if html_id.endswith("_html") else html_id
        renamed[html_id] = base_id
        base = node_by_id.get(base_id)
        if base is None or base is html:
            # Template-only component: promote to the base ID.
            all_nodes.remove(html)
            html["id"] = base_id
            html.pop("sf_lwc_file_type", None)
            html["sf_has_template"] = True
            node_by_id[base_id] = html
            all_nodes.append(html)
            continue
        base["sf_has_template"] = True
        all_nodes.remove(html)
        node_by_id.pop(html_id, None)
    for edge in all_edges:
        edge["source"] = renamed.get(edge["source"], edge["source"])


#: Tooling / output directories that are never Salesforce metadata. ``.sfdx/tools``
#: alone holds thousands of StandardApexLibrary stubs that would flood the graph.
_SKIP_DIRS = frozenset({
    ".sfdx", ".sf", ".git", ".github", ".vscode", ".idea", ".claude", ".husky",
    "node_modules", "graphify-out", ".localdevserver", "__pycache__",
})


def _repo_files(root: Path) -> list[Path]:
    """Every file under *root*, pruning ``_SKIP_DIRS`` before descending into them."""
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        files.extend(Path(dirpath) / f for f in filenames)
    return sorted(files)


def extract_sf(path, *, cpq_data_dir=None, include_permissions=False, **kwargs):
    """Extract a Salesforce repository into a knowledge graph.

    Dispatches every supported Salesforce file under ``path`` to its parser,
    merges the results (deduping nodes by ID for cross-file resolution), then
    merges any CPQ configuration data (``cpq_data_dir``) before running the SF
    analysis passes in the fixed ADR-011 order:

        1. ``cpq_analysis_pass``       — reclassify SBQQ__ nodes, detect QCP.
        2. ``_merge_lwc_components``   — fold LWC HTML + JS into one node.
        2a. ``resolve_hosted_components`` / ``resolve_named_refs`` — point
           component placements / compositions at their LWC or Aura node; drop
           strict label references the repo does not define.
        2b. ``mdt_mapping_pass``       — turn field-mapping ``__mdt`` records into
           traversable ``maps_to`` field->field edges (e.g. Opp->Quote).
        2c. ``resolve_field_refs``     — parsers' field references (formulas,
           SOQL, Flow elements, Apex field access) become ``reads_field`` /
           ``writes_field`` edges once every object's metadata is known.
        2d. ``apex_calls_pass``        — INFERRED ``calls`` edges from Apex
           classes / triggers to the Apex classes they invoke, plus
           ``extends`` / ``implements`` between the repo's own types.
        3. ``ooe_analysis_pass``       — Order of Execution chains.
        4. ``governor_limit_analysis_pass`` — diagnostic ``governor_violation``
           edges (appended to the edge list).
        5. ``detect_recursive_triggers`` — recursive ``calls`` cycles, including
           re-entry through DML on a triggered object, as ``governor_violation``
           edges, guarded recursion downgraded (ADR-027).
        6. ``permission_analysis_pass`` — Profile/FLS constraints on CPQ
           (``gov_permission_violation`` edges, ADR-028). Runs after CPQ so
           ``file_type == "cpq_rule"`` / ``sf_cpq_object`` are already set.
           Only yields edges with ``include_permissions=True``.
        7. ``detect_flow_cpq_loops``   — Flow ↔ CPQ Type A loops
           (``infinite_loop_risk`` self-edges, ADR-029).
        8. ``validation_cpq_analysis_pass`` — CPQ Rule ↔ Validation Rule field
           overlap (``cpq_validation_risk`` edges, ADR-030).

    Passes 4–8 are pure functions returning diagnostic edges that the caller
    appends; passes 1–3 mutate the node/edge lists in place.

    Args:
        path: Path to a Salesforce repository / metadata directory (or a single
            metadata file).
        cpq_data_dir: Optional directory of SFDX JSON exports of SBQQ CPQ records
            (Price/Product Rules, Conditions, Actions). When given, the real CPQ
            rule logic is merged in before the analysis passes so ``validation_cpq``
            / impact see the fields rules actually read/write (Phase 2).
        include_permissions: Also parse Profiles / Permission Sets / Permission
            Set Groups (``grants_access_to`` / ``contains_permission_set`` edges
            and the FLS input of ``permission_analysis_pass``). Off by default.
        **kwargs: Reserved for future options (neo4j-uri, …); currently ignored.

    Returns:
        ``{"nodes": [...], "edges": [...]}`` — the merged, analyzed graph, with
        ``source_file`` values relative to *path* (its parent for a single file).
    """
    from .apex_calls import apex_calls_pass
    from .cpq import cpq_analysis_pass
    from .field_refs import resolve_field_refs
    from .pages import resolve_hosted_components
    from .references import resolve_named_refs
    from .flow_cpq_loops import detect_flow_cpq_loops
    from .mdt_mapping import mdt_mapping_pass
    from .governor_limits import (
        detect_recursive_triggers,
        governor_limit_analysis_pass,
    )
    from .order_of_execution import ooe_analysis_pass
    from .permission_analysis import permission_analysis_pass
    from .validation_cpq import validation_cpq_analysis_pass

    root = Path(path)
    if root.is_file():
        files = [root]
    else:
        files = _repo_files(root)

    all_nodes: list[dict] = []
    all_edges: list[dict] = []
    field_refs: list[dict] = []
    node_by_id: dict[str, dict] = {}

    for file_path in files:
        if not include_permissions and file_path.name.endswith(_PERMISSION_SUFFIXES):
            continue
        parser = _parser_for(file_path)
        if parser is None:
            continue
        try:
            result = parser(file_path)
        except Exception:
            # Lenient mode (ADR-009): skip a file the parser could not handle.
            continue
        for node in result.get("nodes", []):
            _merge_into(all_nodes, node_by_id, node)
        all_edges.extend(result.get("edges", []))
        field_refs.extend(result.get("field_refs", []))

    # CPQ configuration data (SFDX JSON exports) — the rule LOGIC that lives as
    # SBQQ data records, not metadata files. Merged before the analysis passes so
    # validation_cpq / impact see the real fields the rules read/write (Phase 2).
    if cpq_data_dir is not None:
        from .cpq_data import extract_cpq_data

        cpq_result = extract_cpq_data(cpq_data_dir)
        for node in cpq_result.get("nodes", []):
            _merge_into(all_nodes, node_by_id, node)
        all_edges.extend(cpq_result.get("edges", []))

    # Analysis passes — fixed order (ADR-011). Passes 1-3 mutate in place;
    # passes 4-7 are pure functions whose diagnostic edges are appended here.
    cpq_analysis_pass(all_nodes, all_edges)
    _merge_lwc_components(all_nodes, all_edges)
    resolve_hosted_components(all_nodes, all_edges)
    resolve_named_refs(all_nodes, all_edges)
    mdt_mapping_pass(all_nodes, all_edges)
    _resolve_unqualified_fields(all_nodes, all_edges)
    _confirm_var_typed_dml(all_nodes, all_edges)
    resolve_field_refs(all_nodes, all_edges, field_refs)
    apex_calls_pass(all_nodes, all_edges)
    ooe_analysis_pass(all_nodes, all_edges)
    all_edges.extend(governor_limit_analysis_pass(all_nodes, all_edges))
    all_edges.extend(detect_recursive_triggers(all_nodes, all_edges))
    all_edges.extend(permission_analysis_pass(all_nodes, all_edges))
    all_edges.extend(detect_flow_cpq_loops(all_nodes, all_edges))
    all_edges.extend(validation_cpq_analysis_pass(all_nodes, all_edges))

    _drop_transient_attrs(all_nodes)
    _relativize_paths(all_nodes, all_edges, root.parent if root.is_file() else root)
    return {"nodes": all_nodes, "edges": all_edges}
