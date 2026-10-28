"""Salesforce-specific parser / analysis-pass tests (graphify-sf)."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import networkx as nx

from graphify.salesforce import extract_sf
from graphify.salesforce.apex_enhanced import extract_apex_enhanced
from graphify.salesforce.constants import (
    apex_method_nid,
    apex_nid,
    field_nid,
    metadata_nid,
    sobject_nid,
    validation_rule_nid,
)
from graphify.salesforce.validate_sf import validate_sf_graph
from graphify.salesforce.cpq import cpq_analysis_pass
from graphify.salesforce.cpq_data import extract_cpq_data
from graphify.salesforce.flow import extract_flow
from graphify.salesforce.flow_cpq_loops import detect_flow_cpq_loops
from graphify.salesforce.governor_limits import (
    detect_recursive_triggers,
    governor_limit_analysis_pass,
)
from graphify.salesforce.lwc import extract_lwc_html, extract_lwc_js
from graphify.salesforce.neo4j_sf import (
    SF_NODE_TYPE_TO_NEO4J_LABEL,
    SF_RELATION_TO_NEO4J_TYPE,
    push_to_neo4j_sf,
    to_cypher_sf,
)
from graphify.salesforce.metadata import (
    extract_auth_provider,
    extract_duplicate_rule,
    extract_layout,
    extract_matching_rules,
    extract_rule_entries,
    extract_custom_labels,
    extract_custom_metadata_record,
    extract_permission_set_group,
    extract_record_type,
    extract_sharing_rules,
    extract_workflow,
)
from graphify.salesforce.objects import (
    extract_custom_object,
    extract_validation_rule,
)
from graphify.salesforce.order_of_execution import ooe_analysis_pass
from graphify.salesforce.pipeline import build_sf_graph, write_sf_graph
from graphify.salesforce.query import (
    sf_cpq_chain,
    sf_impact,
    sf_ooe,
    sf_violations,
)
from graphify.salesforce.permission_analysis import permission_analysis_pass
from graphify.salesforce.profiles import extract_permission_set, extract_profile
from graphify.salesforce.release_sync import check_staleness, sync_release_notes
from graphify.salesforce.validation_cpq import validation_cpq_analysis_pass

FIXTURES = Path(__file__).parent / "fixtures"


def _assert_no_dangling_edges(result: dict) -> None:
    """Every edge source/target must reference a node present in the result."""
    node_ids = {n["id"] for n in result["nodes"]}
    for edge in result["edges"]:
        assert edge["source"] in node_ids, f"dangling source: {edge}"
        assert edge["target"] in node_ids, f"dangling target: {edge}"


def _sfdx_object_file(tmp_path: Path, api_name: str, source: Path) -> Path:
    """Copy an object fixture into the SFDX layout objects/<Api>/<Api>.object-meta.xml."""
    target = tmp_path / "objects" / api_name / f"{api_name}.object-meta.xml"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    return target


def test_objects_parser(tmp_path: Path) -> None:
    fixture = _sfdx_object_file(
        tmp_path, "Account", FIXTURES / "sf_Account.object-meta.xml")
    result = extract_custom_object(fixture)

    # 1. No error
    assert "error" not in result

    # 2. No dangling edges
    _assert_no_dangling_edges(result)

    # 3. SObject node ID uses sobject_nid()
    account_id = sobject_nid("Account")
    sobjects = [n for n in result["nodes"] if n["file_type"] == "sobject"]
    sobject_ids = {n["id"] for n in sobjects}
    assert account_id in sobject_ids
    account_node = next(n for n in sobjects if n["id"] == account_id)
    assert account_node["label"] == "Account"
    assert account_node["sf_plural_label"] == "Accounts"
    assert account_node["sf_object_type"] == "standard"

    # 4. field_of edges created (one per field), pointing at the Account node
    field_of = [e for e in result["edges"] if e["relation"] == "field_of"]
    assert len(field_of) == 2
    assert all(e["target"] == account_id for e in field_of)
    assert all(e["confidence"] == "EXTRACTED" for e in field_of)

    field_nodes = [n for n in result["nodes"] if n["file_type"] == "field"]
    assert {n["sf_api_name"] for n in field_nodes} == {
        "BillingCity__c",
        "RelatedOpportunity__c",
    }
    # Field IDs are qualified by their object and keep the __c suffix.
    assert {n["id"] for n in field_nodes} == {
        "field_account.billingcity__c",
        "field_account.relatedopportunity__c",
    }
    billing = next(n for n in field_nodes if n["sf_api_name"] == "BillingCity__c")
    assert billing["label"] == billing["sf_qualified_name"] == "Account.BillingCity__c"
    assert billing["sf_label"] == "Billing City"
    assert billing["sf_object"] == "Account"

    # 5. Lookup relationship detected -> references edge to Opportunity
    references = [e for e in result["edges"] if e["relation"] == "references"]
    assert len(references) == 1
    ref = references[0]
    assert ref["source"] == account_id
    assert ref["target"] == sobject_nid("Opportunity")
    assert ref["sf_relationship_type"] == "Lookup"
    assert ref["sf_field_api_name"] == "RelatedOpportunity__c"


def test_object_id_comes_from_api_name_not_display_label(tmp_path: Path) -> None:
    """<label> is a display label ("Quote Line"); the node must key on the API name.

    Real org: 836 of 1,232 objects had label != API name, so every one of them
    was split from the Apex / Flow references to it.
    """
    obj = tmp_path / "objects" / "SBQQ__QuoteLine__c" / "SBQQ__QuoteLine__c.object-meta.xml"
    obj.parent.mkdir(parents=True)
    obj.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<CustomObject xmlns="http://soap.sforce.com/2006/04/metadata">\n'
        "  <label>Quote Line</label>\n"
        "</CustomObject>\n", encoding="utf-8")
    node = extract_custom_object(obj)["nodes"][0]
    assert node["id"] == sobject_nid("SBQQ__QuoteLine__c")
    assert node["label"] == "SBQQ__QuoteLine__c"
    assert node["sf_label"] == "Quote Line"


def test_same_field_name_on_two_objects_stays_two_nodes(tmp_path: Path) -> None:
    """``Status__c`` on Account and on Contact are different fields.

    Real org: 19,443 field files collapsed into 12,106 nodes; ``field_name`` was
    attached to 164 objects at once.
    """
    for obj in ("Account", "Contact"):
        f = tmp_path / "objects" / obj / "fields" / "Status__c.field-meta.xml"
        f.parent.mkdir(parents=True)
        f.write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<CustomField xmlns="http://soap.sforce.com/2006/04/metadata">\n'
            "  <fullName>Status__c</fullName><type>Text</type>\n"
            "</CustomField>\n", encoding="utf-8")
    result = extract_sf(tmp_path)
    fields = {n["id"]: n for n in result["nodes"] if n["file_type"] == "field"}
    assert set(fields) == {field_nid("Account", "Status__c"), field_nid("Contact", "Status__c")}
    field_of = {(e["source"], e["target"]) for e in result["edges"] if e["relation"] == "field_of"}
    assert field_of == {
        (field_nid("Account", "Status__c"), sobject_nid("Account")),
        (field_nid("Contact", "Status__c"), sobject_nid("Contact")),
    }


def _write_field(root: Path, obj: str, name: str, body: str) -> None:
    f = root / "objects" / obj / "fields" / f"{name}.field-meta.xml"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<CustomField xmlns="http://soap.sforce.com/2006/04/metadata">\n'
        f"  <fullName>{name}</fullName>\n{body}\n</CustomField>\n", encoding="utf-8")


def _field_edges(result: dict, relation: str) -> set[tuple[str, str]]:
    return {(e["source"], e["target"]) for e in result["edges"] if e["relation"] == relation}


def test_field_metadata_lookup_and_formula_reads(tmp_path: Path) -> None:
    """Lookups become lookup_to; formulas read fields across __r paths; literals
    and function names never become fields."""
    _write_field(tmp_path, "Account", "Tier__c", "<type>Text</type>")
    _write_field(tmp_path, "Account", "Region__c", "<type>Text</type>")
    _write_field(tmp_path, "Site__c", "Account__c",
                 "<type>Lookup</type><referenceTo>Account</referenceTo>"
                 "<relationshipName>Sites</relationshipName>")
    _write_field(tmp_path, "Site__c", "Label__c",
                 "<type>Text</type><formula>IF(ISBLANK(Account__r.Tier__c), \"Tier__c\", "
                 "Account__r.Tier__c &amp; Name &amp; $User.Id)</formula>")
    vr = tmp_path / "objects" / "Account" / "validationRules" / "Need_Region.validationRule-meta.xml"
    vr.parent.mkdir(parents=True)
    vr.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<ValidationRule xmlns="http://soap.sforce.com/2006/04/metadata">\n'
        "  <fullName>Need_Region</fullName>\n"
        "  <errorConditionFormula>AND(ISPICKVAL(Tier__c, 'Gold'), ISBLANK(Region__c))"
        "</errorConditionFormula>\n</ValidationRule>\n", encoding="utf-8")

    result = extract_sf(tmp_path)
    _assert_no_dangling_edges(result)
    lookup = field_nid("Site__c", "Account__c")
    assert (lookup, sobject_nid("Account")) in _field_edges(result, "lookup_to")
    node = next(n for n in result["nodes"] if n["id"] == lookup)
    assert node["sf_reference_to"] == ["Account"]
    assert node["sf_relationship_name"] == "Sites"

    reads = _field_edges(result, "reads_field")
    label = field_nid("Site__c", "Label__c")
    # Account__r.Tier__c walks the lookup to Account; the quoted "Tier__c",
    # ISBLANK / IF and $User.Id are not fields; Name is not defined in the repo.
    assert {t for s, t in reads if s == label} == {field_nid("Account", "Tier__c")}
    rule = validation_rule_nid("Account", "Need_Region")
    assert {t for s, t in reads if s == rule} == {
        field_nid("Account", "Tier__c"), field_nid("Account", "Region__c")}


def test_rollup_summary_reads_child_field(tmp_path: Path) -> None:
    _write_field(tmp_path, "Opportunity", "Total_Lines__c",
                 "<type>Summary</type><summarizedField>OpportunityLineItem.TotalPrice"
                 "</summarizedField><summaryOperation>sum</summaryOperation>")
    result = extract_sf(tmp_path)
    assert (field_nid("Opportunity", "Total_Lines__c"),
            field_nid("OpportunityLineItem", "TotalPrice")) in _field_edges(result, "reads_field")
    _assert_no_dangling_edges(result)


def test_definition_replaces_stub_regardless_of_file_order(tmp_path: Path) -> None:
    """An Apex FROM-clause stub seen first must not own the SObject node."""
    (tmp_path / "classes").mkdir()
    (tmp_path / "classes" / "AService.cls").write_text(
        "public class AService { public void f() { List<Widget__c> w = [SELECT Id FROM Widget__c]; } }",
        encoding="utf-8")
    obj = tmp_path / "objects" / "Widget__c" / "Widget__c.object-meta.xml"
    obj.parent.mkdir(parents=True)
    obj.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<CustomObject xmlns="http://soap.sforce.com/2006/04/metadata">\n'
        "  <label>Widget</label>\n</CustomObject>\n", encoding="utf-8")
    result = extract_sf(tmp_path)
    widget = next(n for n in result["nodes"] if n["id"] == sobject_nid("Widget__c"))
    assert widget["source_file"].endswith("Widget__c.object-meta.xml")
    assert widget["sf_label"] == "Widget"
    assert "sf_stub" not in widget
    assert any(e["relation"] == "queries" and e["target"] == widget["id"]
               for e in result["edges"])

    # Definition first, stub later: the stub must not mark the definition.
    (tmp_path / "zz").mkdir()
    (tmp_path / "zz" / "ZService.cls").write_text(
        "public class ZService { public void f() { List<Widget__c> w = [SELECT Id FROM Widget__c]; } }",
        encoding="utf-8")
    result = extract_sf(tmp_path)
    by_id = {n["id"]: n for n in result["nodes"]}
    assert "sf_stub" not in by_id[sobject_nid("Widget__c")]
    assert "sf_stub" not in by_id[apex_nid("AService")]


def test_apex_identity_ignores_keywords_in_comments(tmp_path: Path) -> None:
    """A ``class``/``trigger`` word in a comment must not rename or re-type a class.

    Real org: 212 Apex nodes were labelled ``for`` / ``Name`` / ``Handler`` and 53
    classes were typed as triggers because the declaration regex read comments.
    """
    cls = tmp_path / "AgentService.cls"
    cls.write_text(
        "/**\n * Helper class for agents. Handles the trigger Name mapping.\n */\n"
        "public with sharing class AgentService {\n"
        "    // returns 'class Foo' style strings\n"
        "    public static String describe() { return 'trigger X on Y'; }\n"
        "}\n", encoding="utf-8")
    result = extract_apex_enhanced(cls)
    node = result["nodes"][0]
    assert node["id"] == apex_nid("AgentService")
    assert node["label"] == "AgentService"
    assert node["sf_code_type"] == "class"
    assert not any(e["relation"] == "triggers_on" for e in result["edges"])


def test_apex_node_carries_no_source_text() -> None:
    """The extracted graph keeps structure only — never the Apex source text."""
    result = extract_sf(SAMPLE_ORG)
    code = [n for n in result["nodes"] if n.get("sf_code_type") in ("class", "trigger")]
    assert code
    for node in code:
        assert "source" not in node and "_source" not in node
        assert node["sf_loc"] > 0
        assert len(node["sf_source_hash"]) == 16


def test_managed_hidden_class_is_kept_as_node(tmp_path: Path) -> None:
    cls = tmp_path / "pkg__CleanUpHelper.cls"
    cls.write_text("(hidden)", encoding="utf-8")
    result = extract_apex_enhanced(cls)
    assert "error" not in result
    node = result["nodes"][0]
    assert node["id"] == apex_nid("pkg__CleanUpHelper")
    assert node["sf_managed_hidden"] is True
    assert result["edges"] == []


def test_trigger_emits_triggers_on_with_events(tmp_path: Path) -> None:
    trig = tmp_path / "OppTrigger.trigger"
    trig.write_text(
        "trigger OppTrigger on Opportunity (before insert, after   update) {\n}\n",
        encoding="utf-8")
    result = extract_apex_enhanced(trig)
    edge = next(e for e in result["edges"] if e["relation"] == "triggers_on")
    assert edge["source"] == apex_nid("OppTrigger")
    assert edge["target"] == sobject_nid("Opportunity")
    assert edge["sf_trigger_events"] == ["before insert", "after update"]
    _assert_no_dangling_edges(result)


def test_apex_overloads_share_one_method_node(tmp_path: Path) -> None:
    cls = tmp_path / "Calc.cls"
    cls.write_text(
        "public class Calc {\n"
        "  public Integer add(Integer a) { return a; }\n"
        "  public Integer add(Integer a, Integer b) { return a + b; }\n"
        "}\n", encoding="utf-8")
    result = extract_apex_enhanced(cls)
    methods = [n for n in result["nodes"] if n.get("sf_method_type") == "method"]
    assert [m["id"] for m in methods] == [apex_method_nid("Calc", "add")]
    assert methods[0]["sf_signatures"] == ["add(Integer a)", "add(Integer a, Integer b)"]
    member = [e for e in result["edges"] if e["relation"] == "member_of"]
    assert len(member) == 1


def test_apex_parser() -> None:
    # --- Apex class: methods, SOQL (not in loop), DML --------------------
    cls_result = extract_apex_enhanced(FIXTURES / "sf_AccountService.cls")

    # 1. No error
    assert "error" not in cls_result

    # 2. No dangling edges
    _assert_no_dangling_edges(cls_result)

    # class node + sf_code_type
    classes = [n for n in cls_result["nodes"] if n.get("sf_code_type") == "class"]
    assert len(classes) == 1
    assert classes[0]["label"] == "sf_AccountService"  # file name is the API name

    # method signatures parsed (getAccounts, updateAccount)
    methods = [n for n in cls_result["nodes"] if n.get("sf_method_type") == "method"]
    method_ids = {n["id"] for n in methods}
    assert classes[0]["id"] == apex_nid("sf_AccountService")
    assert apex_method_nid("sf_AccountService", "getAccounts") in method_ids
    assert apex_method_nid("sf_AccountService", "updateAccount") in method_ids
    # each method -> class via member_of (ownership, not a call)
    member_of = [e for e in cls_result["edges"] if e["relation"] == "member_of"]
    assert all(e["target"] == classes[0]["id"] for e in member_of)
    assert len(member_of) == len(methods)
    assert not any(e["relation"] == "calls" for e in cls_result["edges"])

    # 3. SOQL detected (FROM Account), CRITICAL: target uses sobject_nid()
    cls_queries = [e for e in cls_result["edges"] if e["relation"] == "queries"]
    account_q = [e for e in cls_queries if e["target"] == sobject_nid("Account")]
    assert len(account_q) == 1
    # SOQL here sits *before* the loop -> not in loop
    assert account_q[0]["sf_in_loop"] is False
    assert account_q[0]["confidence"] == "EXTRACTED"

    # 4. DML detected (update acc) and resolved to Account
    cls_dml = [e for e in cls_result["edges"] if e["relation"] == "dml_operates_on"]
    assert any(
        e["target"] == sobject_nid("Account") and e["sf_dml_type"] == "UPDATE"
        for e in cls_dml
    )


def test_apex_soql_relationship_subquery_not_sobject(tmp_path: Path) -> None:
    """A ``__r`` child-relationship subquery target must NOT become an sobject.

    Real-org label mis-extraction (ADR-019): the inner ``FROM Contacts__r`` is a
    relationship traversal, not a queryable SObject. Only the root Account is.
    """
    cls = tmp_path / "RelQuery.cls"
    cls.write_text(
        "public class RelQuery {\n"
        "  public void run() {\n"
        "    List<Account> a = [SELECT Id FROM Account];\n"
        "    List<Account> b = [SELECT Id, (SELECT Id FROM Contacts__r) FROM Account];\n"
        "  }\n"
        "}\n", encoding="utf-8")
    result = extract_apex_enhanced(cls)
    _assert_no_dangling_edges(result)
    sobjects = {n["id"] for n in result["nodes"] if n.get("file_type") == "sobject"}
    assert sobject_nid("Account") in sobjects        # root object kept
    assert not any(s.endswith("__r") for s in sobjects)  # relationship dropped

    # --- Apex trigger: SOQL/DML inside a loop ----------------------------
    trig_result = extract_apex_enhanced(FIXTURES / "sf_AccountTrigger.trigger")

    assert "error" not in trig_result
    _assert_no_dangling_edges(trig_result)

    triggers = [n for n in trig_result["nodes"] if n.get("sf_code_type") == "trigger"]
    assert len(triggers) == 1
    assert triggers[0]["label"] == "sf_AccountTrigger"

    # 5. SOQL inside the loop is tagged sf_in_loop: true
    trig_queries = [e for e in trig_result["edges"] if e["relation"] == "queries"]
    opp_q = [e for e in trig_queries if e["target"] == sobject_nid("Opportunity")]
    assert len(opp_q) == 1
    assert opp_q[0]["sf_in_loop"] is True

    # DML inside the loop (update opps) also tagged in loop, resolved to Opportunity
    trig_dml = [e for e in trig_result["edges"] if e["relation"] == "dml_operates_on"]
    opp_dml = [e for e in trig_dml if e["target"] == sobject_nid("Opportunity")]
    assert len(opp_dml) == 1
    assert opp_dml[0]["sf_in_loop"] is True
    assert opp_dml[0]["sf_dml_type"] == "UPDATE"


def _apex_edges(tmp_path: Path, body: str, relation: str) -> list[dict]:
    cls = tmp_path / "C.cls"
    cls.write_text(f"public class C {{\n{body}\n}}\n", encoding="utf-8")
    return [e for e in extract_apex_enhanced(cls)["edges"] if e["relation"] == relation]


def test_soql_multiline_field_list(tmp_path: Path) -> None:
    """Multi-line SELECT lists are extracted (real org: 628 SOQL sites, 11%, were lost)."""
    edges = _apex_edges(tmp_path, """
    public static Account f(Id x) {
        return [
            SELECT
                Name,
                Annual_Revenue_Band__c
            FROM Account
            WHERE Id = :x LIMIT 1
        ];
    }""", "queries")
    assert [e["target"] for e in edges] == [sobject_nid("Account")]
    assert edges[0]["confidence"] == "EXTRACTED"
    assert edges[0]["source_location"] == "L5"  # the SELECT line


def test_soql_ignores_comments_and_never_crosses_statements(tmp_path: Path) -> None:
    edges = _apex_edges(tmp_path, """
    // List<Lead> l = [SELECT Id FROM Lead];
    /* [SELECT Id FROM Task] */
    String s = 'SELECT';
    List<Case> c = [SELECT Id FROM Case];""", "queries")
    assert [e["target"] for e in edges] == [sobject_nid("Case")]


def test_dynamic_soql_string_is_inferred(tmp_path: Path) -> None:
    cls = tmp_path / "Dyn.cls"
    cls.write_text(
        "public class Dyn {\n"
        "  public List<SObject> f() { return Database.query('SELECT Id, Name FROM Account LIMIT 5'); }\n"
        "  public List<SObject> g(String o) { return Database.query('SELECT Id FROM ' + o); }\n"
        "}\n", encoding="utf-8")
    result = extract_apex_enhanced(cls)
    q = [e for e in result["edges"] if e["relation"] == "queries"]
    assert [e["target"] for e in q] == [sobject_nid("Account")]
    assert q[0]["confidence"] == "INFERRED" and q[0]["sf_dynamic"] is True
    assert result["nodes"][0]["sf_dynamic_soql"] is True


def test_soql_subquery_does_not_hide_main_object(tmp_path: Path) -> None:
    edges = _apex_edges(tmp_path, """
    List<Account> a = [SELECT Id, (SELECT Id FROM Contacts) FROM Account];""", "queries")
    assert [e["target"] for e in edges] == [sobject_nid("Account")]


def test_soql_semi_join_queries_second_object(tmp_path: Path) -> None:
    edges = _apex_edges(tmp_path, """
    List<Contact> c = [SELECT Id FROM Contact
        WHERE Id NOT IN (SELECT ContactId FROM User WHERE IsActive = true)];""", "queries")
    assert sorted(e["target"] for e in edges) == [sobject_nid("Contact"), sobject_nid("User")]


def test_var_typed_dml_needs_sobject_evidence(tmp_path: Path) -> None:
    """``update rows`` on a wrapper-class list must not invent a RowWrapper SObject."""
    (tmp_path / "classes").mkdir()
    (tmp_path / "classes" / "RowWrapper.cls").write_text(
        "public class RowWrapper { }", encoding="utf-8")
    (tmp_path / "classes" / "Svc.cls").write_text(
        "public class Svc {\n"
        "  public void f(List<RowWrapper> rows, List<Lead> leads) {\n"
        "    update rows;\n"
        "    update leads;\n"
        "    List<Lead> more = [SELECT Id FROM Lead];\n"
        "  }\n"
        "}\n", encoding="utf-8")
    result = extract_sf(tmp_path)
    _assert_no_dangling_edges(result)
    dml = {e["target"] for e in result["edges"] if e["relation"] == "dml_operates_on"}
    assert dml == {sobject_nid("Lead"), sobject_nid("unknown")}
    assert not any(n["id"] == sobject_nid("RowWrapper") for n in result["nodes"])


def test_dml_variants(tmp_path: Path) -> None:
    edges = _apex_edges(tmp_path, """
    public void f(List<Opportunity> opps) {
        // update opps;
        upsert opps;
        Database.update(opps, false);
        insert new Task(Subject = 'x');
        delete [SELECT Id FROM Case_Part__c
                WHERE Case__c IN :ids];
        Database.delete([select id from Contact], false);
    }""", "dml_operates_on")
    got = [(e["sf_dml_type"], e["target"]) for e in edges]
    assert got == [
        ("UPSERT", sobject_nid("Opportunity")),
        ("UPDATE", sobject_nid("Opportunity")),
        ("INSERT", sobject_nid("Task")),
        ("DELETE", sobject_nid("Case_Part__c")),
        ("DELETE", sobject_nid("Contact")),
    ]


def test_flow_parser_process_builder() -> None:
    """A Process Builder (processType Workflow) names its object in root-level
    processMetadataValues, not in <start>; it still triggers on that object."""
    result = extract_flow(FIXTURES / "sf_LeadProcess.flow-meta.xml")
    assert "error" not in result
    _assert_no_dangling_edges(result)

    flow_node = next(n for n in result["nodes"] if n["file_type"] == "flow")
    assert flow_node["sf_process_type"] == "Workflow"
    assert flow_node["sf_trigger_object"] == "Lead"
    assert flow_node["sf_trigger_type"] == "CreateAndUpdate"
    assert flow_node["sf_flow_trigger_type"] is None
    assert flow_node["sf_status"] == "Active"

    triggers = [e for e in result["edges"] if e["relation"] == "triggers_on"]
    assert [e["target"] for e in triggers] == [sobject_nid("Lead")]


def test_flow_parser() -> None:
    fixture = FIXTURES / "sf_AccountFlow.flow-meta.xml"
    result = extract_flow(fixture)

    # 1. No error
    assert "error" not in result

    # 2. No dangling edges
    _assert_no_dangling_edges(result)

    # Flow node carries trigger metadata from <start>
    flows = [n for n in result["nodes"] if n["file_type"] == "flow"]
    assert len(flows) == 1
    flow_node = flows[0]
    assert flow_node["label"] == "sf_AccountFlow"
    assert flow_node["sf_trigger_object"] == "Account"
    assert flow_node["sf_trigger_type"] == "CreateAndUpdate"
    assert flow_node["sf_flow_trigger_type"] == "RecordAfterSave"
    assert flow_node["sf_status"] == "Active"
    assert flow_node["sf_process_type"] == "AutoLaunchedFlow"
    flow_id = flow_node["id"]

    # 3. <recordLookups> -> queries edge, target resolved via sobject_nid()
    queries = [e for e in result["edges"] if e["relation"] == "queries"]
    assert len(queries) == 1
    q = queries[0]
    assert q["source"] == flow_id
    assert q["target"] == sobject_nid("Account")
    assert q["confidence"] == "EXTRACTED"
    assert q["sf_flow_element"] == "Get_Accounts"

    # 4. <recordCreates>/<recordUpdates> -> dml_operates_on edges.
    dml = [e for e in result["edges"] if e["relation"] == "dml_operates_on"]
    by_elem = {e["sf_flow_element"]: e for e in dml}

    # 4a. Direct <object> create -> INSERT Opportunity.
    create_opp = by_elem["Create_Opportunity"]
    assert create_opp["target"] == sobject_nid("Opportunity")
    assert create_opp["sf_dml_type"] == "INSERT"

    # 4b. <inputReference> create -> object resolved via the variable's
    #     objectType (NewQuote -> SBQQ__Quote__c). This is the real-org pattern
    #     the previous parser missed entirely.
    create_quote = by_elem["Create_Quote"]
    assert create_quote["target"] == sobject_nid("SBQQ__Quote__c")
    assert create_quote["sf_dml_type"] == "INSERT"

    # 4c. <recordUpdates> -> UPDATE Account.
    update_acc = by_elem["Update_Account"]
    assert update_acc["target"] == sobject_nid("Account")
    assert update_acc["sf_dml_type"] == "UPDATE"

    # 5. <actionCalls actionType=apex> -> flow_invokes (INFERRED).
    invokes = [e for e in result["edges"] if e["relation"] == "flow_invokes"]
    assert len(invokes) == 1
    assert invokes[0]["target"] == "apex_accountservice"
    assert invokes[0]["confidence"] == "INFERRED"

    # 5. apexAction -> flow_invokes edge to the Apex class
    invokes = [e for e in result["edges"] if e["relation"] == "flow_invokes"]
    assert len(invokes) == 1
    inv = invokes[0]
    assert inv["source"] == flow_id
    assert inv["target"] == "apex_accountservice"
    assert inv["sf_flow_element"] == "Call_Apex"


def test_apex_field_reads_and_writes(tmp_path: Path) -> None:
    """SOQL fields, relationship paths, child subqueries, variable access and
    constructors become field edges; a wrapper class is never taken for an SObject."""
    _write_field(tmp_path, "Contact", "Account__c",
                 "<type>Lookup</type><referenceTo>Account</referenceTo>"
                 "<relationshipName>Members</relationshipName>")
    _write_field(tmp_path, "Account", "Tier__c", "<type>Text</type>")
    (tmp_path / "classes").mkdir()
    (tmp_path / "classes" / "Row.cls").write_text(
        "public class Row { public String Tier__c; }", encoding="utf-8")
    (tmp_path / "classes" / "TierService.cls").write_text(
        "public class TierService {\n"
        "  public void run(Id x) {\n"
        "    List<Account> accs = [SELECT Name, Owner.Email, (SELECT Email FROM Members__r)\n"
        "                          FROM Account WHERE Tier__c = 'Gold'];\n"
        "    for (Account a : accs) {\n"
        "      a.Tier__c = 'Silver';\n"
        "      String n = a.Name;\n"
        "    }\n"
        "    Row r = new Row();\n"
        "    r.Tier__c = 'x';\n"
        "    insert new Contact(LastName = 'Doe');\n"
        "  }\n"
        "}\n", encoding="utf-8")

    result = extract_sf(tmp_path)
    _assert_no_dangling_edges(result)
    cls = apex_nid("TierService")
    reads = {t for s, t in _field_edges(result, "reads_field") if s == cls}
    writes = {t for s, t in _field_edges(result, "writes_field") if s == cls}
    assert {field_nid("Account", "Name"), field_nid("User", "Email"),
            field_nid("Account", "Tier__c"), field_nid("Contact", "Email")} <= reads
    assert writes == {field_nid("Account", "Tier__c"), field_nid("Contact", "LastName")}
    # Child subquery Members__r resolves through Contact.Account__c's relationshipName.
    assert (cls, sobject_nid("Contact")) in _field_edges(result, "queries")
    # Stub fields hang off their object too.
    assert (field_nid("User", "Email"), sobject_nid("User")) in _field_edges(result, "field_of")
    # Row is an Apex class: its member access never becomes a field.
    assert not any(n["id"] == sobject_nid("Row") for n in result["nodes"])


def test_flow_field_reads_and_writes(tmp_path: Path) -> None:
    """Record-triggered Flow: Get Records / Update / Assignment / $Record mentions."""
    flow = tmp_path / "flows" / "Tier_Sync.flow-meta.xml"
    flow.parent.mkdir(parents=True)
    flow.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<Flow xmlns="http://soap.sforce.com/2006/04/metadata">\n'
        "  <start><object>Contact</object><recordTriggerType>Update</recordTriggerType>"
        "<triggerType>RecordAfterSave</triggerType></start>\n"
        "  <recordLookups><name>Get_Account</name><object>Account</object>"
        "<filters><field>Id</field><operator>EqualTo</operator>"
        "<value><elementReference>$Record.AccountId</elementReference></value></filters>"
        "<queriedFields>Tier__c</queriedFields></recordLookups>\n"
        "  <decisions><name>Gold</name><rules><conditions>"
        "<leftValueReference>Get_Account.Tier__c</leftValueReference>"
        "</conditions></rules></decisions>\n"
        "  <assignments><name>Set_Flag</name><assignmentItems>"
        "<assignToReference>$Record.Is_Gold__c</assignToReference>"
        "<operator>Assign</operator></assignmentItems></assignments>\n"
        "  <recordUpdates><name>Update_Account</name><inputReference>Get_Account</inputReference>"
        "<inputAssignments><field>Last_Sync__c</field></inputAssignments></recordUpdates>\n"
        "</Flow>\n", encoding="utf-8")
    result = extract_sf(tmp_path)
    _assert_no_dangling_edges(result)
    flow_id = "flow_tier_sync"
    reads = {t for s, t in _field_edges(result, "reads_field") if s == flow_id}
    writes = {t for s, t in _field_edges(result, "writes_field") if s == flow_id}
    assert reads == {field_nid("Account", "Tier__c"), field_nid("Contact", "AccountId")}
    assert writes == {field_nid("Contact", "Is_Gold__c"), field_nid("Account", "Last_Sync__c")}
    assert (flow_id, sobject_nid("Contact")) in _field_edges(result, "triggers_on")


def test_lwc_parser() -> None:
    # --- HTML template ---------------------------------------------------
    html_result = extract_lwc_html(FIXTURES / "sf_MyComponent.html")

    # 1. No error + no dangling edges
    assert "error" not in html_result
    _assert_no_dangling_edges(html_result)

    html_nodes = [n for n in html_result["nodes"] if n["file_type"] == "lwc_component"]
    assert len(html_nodes) == 1
    assert html_nodes[0]["sf_lwc_file_type"] == "html"

    # --- JavaScript ------------------------------------------------------
    js_result = extract_lwc_js(FIXTURES / "sf_MyComponent.js")

    # 1. No error + no dangling edges
    assert "error" not in js_result
    _assert_no_dangling_edges(js_result)

    lwc_nodes = [n for n in js_result["nodes"] if n["file_type"] == "lwc_component"]
    assert len(lwc_nodes) == 1
    lwc_node = lwc_nodes[0]
    assert lwc_node["label"] == "sf_MyComponent"  # bundle name, not the JS class
    assert lwc_node["sf_js_class"] == "MyComponent"
    assert lwc_node["sf_lwc_file_type"] == "js"

    # 4. @api properties detected
    assert lwc_node["sf_api_property_recordId"] is True
    assert lwc_node["sf_api_property_label"] is True

    # 2. @wire to an Apex method -> wire_to edge. @wire to getRecord (UI-API)
    #    must NOT produce an edge.
    wire_edges = [e for e in js_result["edges"] if e["relation"] == "wire_to"]
    assert len(wire_edges) == 1
    w = wire_edges[0]
    assert w["source"] == lwc_node["id"]
    # Resolves to the same Apex method node ID the Apex parser produces.
    assert w["target"] == apex_method_nid("AccountService", "getAccounts")
    assert w["sf_wire_method"] == "getAccounts"
    assert w["confidence"] == "INFERRED"

    # 3. Imperative Apex import (saveAccount, not @wire'd) -> lwc_calls edge.
    #    This is the real-org pattern (Opportunity LWCs call Apex imperatively)
    #    the parser previously dropped.
    calls = [e for e in js_result["edges"] if e["relation"] == "lwc_calls"]
    assert len(calls) == 1
    assert calls[0]["source"] == lwc_node["id"]
    assert calls[0]["target"] == apex_method_nid("AccountService", "saveAccount")
    assert calls[0]["sf_apex_method"] == "saveAccount"


def test_pages_host_components_and_answer_where_is_it_shown(tmp_path: Path) -> None:
    """FlexiPage + Experience view -> hosts edges to LWC / Aura bundles (review item 0).

    Real org: 1,252 Experience files and 304 FlexiPages produced no nodes, so
    "which page is this component on?" was answered with "none".
    """
    lwc = tmp_path / "lwc" / "tierGauge"
    lwc.mkdir(parents=True)
    (lwc / "tierGauge.js").write_text(
        "import { LightningElement } from 'lwc';\nexport default class TierGauge extends LightningElement {}\n",
        encoding="utf-8")
    aura = tmp_path / "aura" / "LegacyBanner"
    aura.mkdir(parents=True)
    (aura / "LegacyBanner.cmp").write_text(
        '<aura:component controller="BannerController" implements="flexipage:availableForAllPageTypes">'
        "</aura:component>", encoding="utf-8")
    page = tmp_path / "flexipages" / "Account_Record_Page.flexipage-meta.xml"
    page.parent.mkdir()
    page.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<FlexiPage xmlns="http://soap.sforce.com/2006/04/metadata">\n'
        "  <flexiPageRegions><itemInstances><componentInstance>"
        "<componentName>tierGauge</componentName></componentInstance></itemInstances>"
        "<itemInstances><componentInstance><componentName>LegacyBanner</componentName>"
        "</componentInstance></itemInstances><itemInstances><componentInstance>"
        "<componentName>force:highlightsPanel</componentName></componentInstance>"
        "</itemInstances><itemInstances><fieldInstance><fieldItem>Record.Tier__c</fieldItem>"
        "</fieldInstance></itemInstances></flexiPageRegions>\n"
        "  <masterLabel>Account Record Page</masterLabel>\n"
        "  <sobjectType>Account</sobjectType>\n  <type>RecordPage</type>\n"
        "</FlexiPage>\n", encoding="utf-8")
    view = tmp_path / "experiences" / "Partner_Portal1" / "views" / "home.json"
    view.parent.mkdir(parents=True)
    view.write_text(json.dumps({
        "componentName": "siteforce:dynamicLayout", "label": "Home",
        "regions": [{"components": [
            {"componentName": "c:tierGauge"},
            {"componentName": "forceCommunity:richText"}]}]}), encoding="utf-8")
    _write_field(tmp_path, "Account", "Tier__c", "<type>Text</type>")
    (tmp_path / "experiences" / "Partner_Portal1.site-meta.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<ExperienceBundle xmlns="http://soap.sforce.com/2006/04/metadata">\n'
        "  <label>Partner Portal</label><type>ChatterNetworkPicasso</type>\n"
        "  <urlPathPrefix>partners/s</urlPathPrefix>\n"
        "</ExperienceBundle>\n", encoding="utf-8")

    result = extract_sf(tmp_path)
    _assert_no_dangling_edges(result)
    site_id = "experience_site_partner_portal1"
    assert _field_edges(result, "contains") == {(site_id, "experience_partner_portal1.home")}
    site = next(n for n in result["nodes"] if n["id"] == site_id)
    assert site["file_type"] == "experience_site" and not site.get("sf_stub")
    assert site["label"] == "Partner Portal"
    assert site["sf_qualified_name"] == "Partner_Portal1"
    assert site["sf_url_path_prefix"] == "partners/s"
    hosts = _field_edges(result, "hosts")
    page_id = "flexipage_account_record_page"
    view_id = "experience_partner_portal1.home"
    assert hosts == {(page_id, "lwc_tiergauge"), (page_id, "aura_legacybanner"),
                     (view_id, "lwc_tiergauge")}
    assert (page_id, sobject_nid("Account")) in _field_edges(result, "page_for")
    assert (page_id, field_nid("Account", "Tier__c")) in _field_edges(result, "reads_field")
    assert ("aura_legacybanner", apex_nid("BannerController")) in _field_edges(
        result, "aura_controller")
    by_id = {n["id"]: n for n in result["nodes"]}
    assert by_id[view_id]["label"] == "Partner_Portal1/home"
    assert by_id[page_id]["sf_standard_component_count"] == 1

    # Upstream impact from the component now reaches both pages.
    G = build_sf_graph(result)
    up = sf_impact(G, "tierGauge", direction="upstream", depth=1)
    assert {page_id, view_id} <= set(up["nodes"])


def test_profile_parser() -> None:
    fixture = FIXTURES / "sf_Admin.profile-meta.xml"
    result = extract_profile(fixture)

    # 1. No error
    assert "error" not in result

    # 2. No dangling edges
    _assert_no_dangling_edges(result)

    # Profile node
    profiles = [n for n in result["nodes"] if n["file_type"] == "profile"]
    assert len(profiles) == 1
    profile_node = profiles[0]
    assert profile_node["id"] == "profile_sf_admin"
    assert profile_node["label"] == "sf_Admin"
    profile_id = profile_node["id"]

    grants = [e for e in result["edges"] if e["relation"] == "grants_access_to"]
    assert all(e["source"] == profile_id for e in grants)
    assert all(e["confidence"] == "EXTRACTED" for e in grants)

    # 3. Object permission -> grants_access_to edge, target via sobject_nid()
    obj_grants = [e for e in grants if e["target"] == sobject_nid("Account")]
    assert len(obj_grants) == 1
    og = obj_grants[0]
    assert og["sf_object"] == "Account"
    assert og["sf_permissions"] == ["CREATE", "READ", "EDIT", "DELETE"]

    # 4. FLS permissions stored as a node attribute (not a separate node)
    fls = profile_node["sf_fls_permissions"]
    assert fls["Account.BillingCity"] == {"readable": True, "editable": True}
    assert fls["SBQQ__Quote__c.SBQQ__NetPrice__c"] == {
        "readable": True,
        "editable": False,
    }

    # 5. Apex class access detected -> grants_access_to edge to apex_<class>
    apex_grants = [e for e in grants if e["target"] == "apex_accountservice"]
    assert len(apex_grants) == 1
    assert apex_grants[0]["sf_access_type"] == "apex_class"


def test_permission_set_parser(tmp_path: Path) -> None:
    """PermissionSet files yield a permission_set node (prefix differs)."""
    permset = tmp_path / "Sales.permissionset-meta.xml"
    permset.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<PermissionSet xmlns="http://soap.sforce.com/2006/04/metadata">\n'
        "    <objectPermissions>\n"
        "        <object>Account</object>\n"
        "        <allowRead>true</allowRead>\n"
        "    </objectPermissions>\n"
        "</PermissionSet>\n"
    )

    result = extract_permission_set(permset)

    assert "error" not in result
    _assert_no_dangling_edges(result)

    nodes = [n for n in result["nodes"] if n["file_type"] == "permission_set"]
    assert len(nodes) == 1
    assert nodes[0]["id"] == "permission_set_sales"

    grants = [e for e in result["edges"] if e["relation"] == "grants_access_to"]
    assert len(grants) == 1
    assert grants[0]["target"] == sobject_nid("Account")
    assert grants[0]["sf_permissions"] == ["READ"]


def test_profile_parser_xml_parse_error(tmp_path: Path) -> None:
    """Malformed Profile XML degrades gracefully to a single concept error node."""
    bad = tmp_path / "Broken.profile-meta.xml"
    bad.write_text("<Profile><objectPermissions></Profile>")  # mismatched tag

    result = extract_profile(bad)

    assert result["edges"] == []
    assert len(result["nodes"]) == 1
    err = result["nodes"][0]
    assert err["file_type"] == "concept"
    assert err["sf_error_type"] == "xml_parse_error"


def test_lwc_parser_encoding_error(tmp_path: Path) -> None:
    """Undecodable JS bytes degrade gracefully to a single concept error node."""
    bad = tmp_path / "Broken.js"
    bad.write_bytes(b"\xff\xfe invalid \x80 bytes")

    result = extract_lwc_js(bad)

    assert result["edges"] == []
    assert len(result["nodes"]) == 1
    err = result["nodes"][0]
    assert err["file_type"] == "concept"
    assert err["sf_error_type"] == "js_parse_error"


def test_flow_parser_xml_parse_error(tmp_path: Path) -> None:
    """Malformed Flow XML degrades gracefully to a single concept error node."""
    bad = tmp_path / "Broken.flow-meta.xml"
    bad.write_text("<Flow><start></Flow>")  # mismatched tag

    result = extract_flow(bad)

    assert result["edges"] == []
    assert len(result["nodes"]) == 1
    err = result["nodes"][0]
    assert err["file_type"] == "concept"
    assert err["sf_error_type"] == "xml_parse_error"


def test_cpq_analysis() -> None:
    """CPQ analysis pass: tag SBQQ__ metadata, detect QCP, order applies-to edges."""
    # Parse the QCP plugin -> a "code" node carrying its transient _source.
    qcp_result = extract_apex_enhanced(FIXTURES / "sf_QCPPlugin.cls")
    assert "error" not in qcp_result

    all_nodes: list[dict] = list(qcp_result["nodes"])
    all_edges: list[dict] = list(qcp_result["edges"])
    qcp_class_id = apex_nid("sf_QCPPlugin")

    # Real CPQ rules (as the CPQ data ingester emits them) + SBQQ__ metadata.
    all_nodes.append({"id": "cpq_price_rule", "label": "Discount",
                      "file_type": "cpq_rule", "sf_cpq_rule_type": "Price",
                      "source_file": "cpq_data"})
    all_nodes.append({"id": "cpq_product_rule", "label": "Bundle",
                      "file_type": "cpq_rule", "sf_cpq_rule_type": "Product",
                      "source_file": "cpq_data"})
    quote_id = sobject_nid("SBQQ__Quote__c")
    all_nodes.append({"id": quote_id, "label": "SBQQ__Quote__c", "file_type": "sobject",
                      "sf_api_name": "SBQQ__Quote__c",
                      "source_file": "objects/SBQQ__Quote__c.object-meta.xml"})
    all_nodes.append({"id": field_nid("Account", "SBQQ__Renewal__c"),
                      "label": "Account.SBQQ__Renewal__c", "file_type": "field",
                      "sf_api_name": "SBQQ__Renewal__c", "sf_object": "Account"})
    account_id = sobject_nid("Account")
    all_nodes.append({"id": account_id, "label": "Account", "file_type": "sobject",
                      "sf_api_name": "Account",
                      "source_file": "objects/Account.object-meta.xml"})
    # An Apex method whose *signature* mentions SBQQ__Quote__c is still code.
    all_nodes.append({"id": "apex_x.clone", "label": "X.clone", "file_type": "code",
                      "sf_signatures": ["clone(SBQQ__Quote__c q)"]})

    for rule in ("cpq_price_rule", "cpq_product_rule"):
        all_edges.append({"source": rule, "target": quote_id,
                          "relation": "cpq_applies_to", "confidence": "INFERRED",
                          "source_file": "x"})

    nodes_before = len(all_nodes)
    edges_before = len(all_edges)
    input_nodes_obj = all_nodes
    input_edges_obj = all_edges

    result = cpq_analysis_pass(all_nodes, all_edges)

    # In-place contract: returns None, mutates the same list objects.
    assert result is None
    assert all_nodes is input_nodes_obj
    assert all_edges is input_edges_obj
    assert len(all_edges) == edges_before  # pass adds no edges

    by_id = {n["id"]: n for n in all_nodes}

    # 1. SBQQ__ metadata is tagged but keeps its type; nothing becomes a rule.
    assert by_id[quote_id]["file_type"] == "sobject"
    assert by_id[quote_id]["sf_cpq_managed"] is True
    assert by_id[field_nid("Account", "SBQQ__Renewal__c")]["sf_cpq_managed"] is True
    assert by_id["apex_x.clone"]["file_type"] == "code"
    assert "sf_cpq_managed" not in by_id[account_id]
    assert {n["id"] for n in all_nodes if n["file_type"] == "cpq_rule"} == {
        "cpq_price_rule", "cpq_product_rule"}

    # 2. QCP interface implementation detected
    assert by_id[qcp_class_id]["sf_qcp_implementation"] is True

    # 4. QCP method nodes created (one per QCP method present in the source)
    qcp_methods = [n for n in all_nodes if n.get("file_type") == "cpq_qcp_method"]
    assert len(all_nodes) > nodes_before
    qcp_method_names = {n["sf_qcp_method"] for n in qcp_methods}
    assert {
        "onBeforePriceRules",
        "calculate",
        "onAfterPriceRules",
        "onAfterCalculate",
    } <= qcp_method_names
    # onBeforeCalculate is not implemented in the fixture -> no node
    assert "onBeforeCalculate" not in qcp_method_names
    for m in qcp_methods:
        assert m["sf_qcp_class"] == qcp_class_id
        assert m["source_file"] == by_id[qcp_class_id]["source_file"]

    # 3. execution_order added to cpq_applies_to edges, existing attrs preserved
    applies = [e for e in all_edges if e["relation"] == "cpq_applies_to"]
    price_edge = next(e for e in applies if e["source"] == "cpq_price_rule")
    product_edge = next(e for e in applies if e["source"] == "cpq_product_rule")
    assert price_edge["execution_order"] == 2  # Price Rules
    assert product_edge["execution_order"] == 1  # Product Rules
    assert price_edge["confidence"] == "INFERRED"  # not overwritten


def test_ooe_analysis() -> None:
    """OoE pass: 18-step chain per triggered SObject, forming a DAG.

    SObjects with an Apex trigger or a Validation Rule qualify; an SObject
    referenced only by SOQL must NOT get an OoE chain (ADR-005 / ADR-017).
    """
    account_id = sobject_nid("Account")
    contact_id = sobject_nid("Contact")
    opp_id = sobject_nid("Opportunity")

    all_nodes: list[dict] = [
        {"id": account_id, "label": "Account", "file_type": "sobject",
         "source_file": "objects/Account.object-meta.xml"},
        {"id": contact_id, "label": "Contact", "file_type": "sobject",
         "source_file": "objects/Contact.object-meta.xml"},
        {"id": opp_id, "label": "Opportunity", "file_type": "sobject",
         "source_file": "objects/Opportunity.object-meta.xml"},
        {"id": "apex_accounttrigger", "label": "AccountTrigger",
         "file_type": "code", "source_file": "triggers/AccountTrigger.trigger",
         "sf_code_type": "trigger"},
        {"id": "validation_contact_amount", "label": "ContactAmount",
         "file_type": "validation_rule",
         "source_file": "objects/Contact/ContactAmount.validationRule-meta.xml"},
    ]
    all_edges: list[dict] = [
        # Account has a trigger -> qualifies for OoE
        {"source": "apex_accounttrigger", "target": account_id,
         "relation": "triggers_on", "confidence": "EXTRACTED", "source_file": "x"},
        # Contact has a Validation Rule -> qualifies for OoE
        {"source": "validation_contact_amount", "target": contact_id,
         "relation": "validates", "confidence": "EXTRACTED", "source_file": "x"},
        # Opportunity is referenced only by SOQL -> must NOT get OoE
        {"source": "apex_accounttrigger", "target": opp_id, "relation": "queries",
         "confidence": "EXTRACTED", "sf_in_loop": False, "source_file": "x"},
    ]

    nodes_before = len(all_nodes)
    input_nodes_obj = all_nodes
    input_edges_obj = all_edges

    result = ooe_analysis_pass(all_nodes, all_edges)

    # In-place contract: returns None, mutates the same list objects.
    assert result is None
    assert all_nodes is input_nodes_obj
    assert all_edges is input_edges_obj

    # 1. 18 OoE nodes per qualifying SObject (Account + Contact); none for Opportunity.
    ooe_nodes = [n for n in all_nodes
                 if n.get("file_type") == "concept" and "sf_ooe_step" in n]
    assert len(ooe_nodes) == 36
    assert len(all_nodes) == nodes_before + 36
    account_ooe = [n for n in ooe_nodes if n["sf_ooe_sobject"] == account_id]
    contact_ooe = [n for n in ooe_nodes if n["sf_ooe_sobject"] == contact_id]
    assert len(account_ooe) == 18
    assert len(contact_ooe) == 18
    # SOQL-only Opportunity excluded.
    assert not any(n["sf_ooe_sobject"] == opp_id for n in ooe_nodes)
    # Steps numbered 1..18.
    assert {n["sf_ooe_step"] for n in account_ooe} == set(range(1, 19))

    # 2. order_of_execution edges chain the steps sequentially.
    ooe_edges = [e for e in all_edges if e["relation"] == "order_of_execution"]
    assert all(e["confidence"] == "EXTRACTED" for e in ooe_edges)
    dag = nx.DiGraph((e["source"], e["target"]) for e in ooe_edges)
    for i in range(1, 18):
        assert dag.has_edge(f"ooe_{account_id}_{i}", f"ooe_{account_id}_{i + 1}")
        assert dag.has_edge(f"ooe_{contact_id}_{i}", f"ooe_{contact_id}_{i + 1}")

    # 3. The order_of_execution subgraph is a DAG (no cycle).
    assert nx.is_directed_acyclic_graph(dag)

    # No dangling edges introduced.
    node_ids = {n["id"] for n in all_nodes}
    for e in all_edges:
        assert e["source"] in node_ids, f"dangling source: {e}"
        assert e["target"] in node_ids, f"dangling target: {e}"

    # Re-run safety: a second pass does not duplicate the chains.
    ooe_analysis_pass(all_nodes, all_edges)
    ooe_nodes_2 = [n for n in all_nodes
                   if n.get("file_type") == "concept" and "sf_ooe_step" in n]
    assert len(ooe_nodes_2) == 36


def test_governor_analysis() -> None:
    """Governor pass: SOQL/DML-in-loop violations + one sentinel node per type.

    The pass aggregates ``sf_in_loop`` ``queries`` / ``dml_operates_on`` edges
    per offending method into ``governor_violation`` edges, and materializes one
    sentinel ``concept`` node per violation type (ADR-004, no node explosion).
    """
    account_id = sobject_nid("Account")
    contact_id = sobject_nid("Contact")

    all_nodes: list[dict] = [
        {"id": account_id, "label": "Account", "file_type": "sobject",
         "source_file": "objects/Account.object-meta.xml"},
        {"id": contact_id, "label": "Contact", "file_type": "sobject",
         "source_file": "objects/Contact.object-meta.xml"},
        {"id": "apex_loopservice", "label": "LoopService", "file_type": "code",
         "source_file": "classes/LoopService.cls"},
        {"id": "apex_dmlservice", "label": "DmlService", "file_type": "code",
         "source_file": "classes/DmlService.cls"},
        {"id": "apex_cleanservice", "label": "CleanService", "file_type": "code",
         "source_file": "classes/CleanService.cls"},
    ]
    all_edges: list[dict] = [
        # LoopService: two SOQL queries inside a loop -> one aggregated violation.
        {"source": "apex_loopservice", "target": account_id, "relation": "queries",
         "confidence": "EXTRACTED", "sf_in_loop": True, "source_location": "L42",
         "source_file": "classes/LoopService.cls"},
        {"source": "apex_loopservice", "target": contact_id, "relation": "queries",
         "confidence": "EXTRACTED", "sf_in_loop": True, "source_location": "L45",
         "source_file": "classes/LoopService.cls"},
        # CleanService: a query NOT in a loop -> no violation.
        {"source": "apex_cleanservice", "target": account_id, "relation": "queries",
         "confidence": "EXTRACTED", "sf_in_loop": False, "source_location": "L10",
         "source_file": "classes/CleanService.cls"},
        # DmlService: a DML in a loop -> one DML violation.
        {"source": "apex_dmlservice", "target": account_id,
         "relation": "dml_operates_on", "confidence": "INFERRED", "sf_in_loop": True,
         "source_location": "L87", "source_file": "classes/DmlService.cls"},
    ]

    nodes_before = len(all_nodes)
    edges_before = len(all_edges)
    input_nodes_obj = all_nodes
    input_edges_obj = all_edges

    violations = governor_limit_analysis_pass(all_nodes, all_edges)

    # Contract: returns the diagnostic edges, mutates only all_nodes (sentinels).
    assert isinstance(violations, list)
    assert all_nodes is input_nodes_obj
    assert all_edges is input_edges_obj
    assert len(all_edges) == edges_before  # pass does not append edges itself

    by_id = {n["id"]: n for n in all_nodes}

    # 1. SOQL-in-loop detected for LoopService, aggregated (count == 2).
    soql_v = [v for v in violations if v["sf_violation_type"] == "soql_in_loop"]
    assert len(soql_v) == 1
    soql_edge = soql_v[0]
    assert soql_edge["source"] == "apex_loopservice"
    assert soql_edge["target"] == "gov_limit_soql_in_loop"
    assert soql_edge["relation"] == "governor_violation"
    assert soql_edge["confidence"] == "EXTRACTED"
    assert soql_edge["sf_violation_count"] == 2
    assert soql_edge["sf_severity"] == "HIGH"
    assert soql_edge["sf_limit"] == 100  # GOVERNOR_LIMITS soql_queries_per_transaction

    # 2. DML-in-loop detected for DmlService.
    dml_v = [v for v in violations if v["sf_violation_type"] == "dml_in_loop"]
    assert len(dml_v) == 1
    assert dml_v[0]["source"] == "apex_dmlservice"
    assert dml_v[0]["target"] == "gov_limit_dml_in_loop"
    assert dml_v[0]["sf_limit"] == 150

    # CleanService's non-loop query produced no violation.
    assert not any(v["source"] == "apex_cleanservice" for v in violations)

    # 3. Exactly one sentinel node per violation type (no node explosion).
    sentinels = [n for n in all_nodes if str(n["id"]).startswith("gov_limit_")]
    assert {n["id"] for n in sentinels} == {
        "gov_limit_soql_in_loop", "gov_limit_dml_in_loop"
    }
    assert len(sentinels) == 2
    assert len(all_nodes) == nodes_before + 2
    for s in sentinels:
        assert s["file_type"] == "concept"

    # 4. Violation edges reference existing nodes (no dangling once extended).
    node_ids = {n["id"] for n in all_nodes}
    for v in violations:
        assert v["source"] in node_ids, f"dangling source: {v}"
        assert v["target"] in node_ids, f"dangling target: {v}"

    # Re-run safety: sentinels are not duplicated on a second pass.
    governor_limit_analysis_pass(all_nodes, all_edges)
    sentinels_2 = [n for n in all_nodes if str(n["id"]).startswith("gov_limit_")]
    assert len(sentinels_2) == 2


def test_permission_analysis() -> None:
    """Permission pass: FLS-restricted SBQQ__ fields on CPQ objects -> risk edges.

    Cross-analyzes Profile/PermSet Field-Level Security (``sf_fls_permissions``)
    against ``cpq_rule`` nodes: a non-readable ``SBQQ__`` field whose object is a
    CPQ rule yields a ``gov_permission_violation`` risk edge (ADR-028). Only CPQ
    (SBQQ__) fields are analyzed; readable fields and non-CPQ fields are ignored.
    """
    quote_id = "cpq_quote"
    price_rule_id = "cpq_price_rule"

    all_nodes: list[dict] = [
        # CPQ rule nodes (post cpq_analysis_pass reclassification).
        {"id": quote_id, "label": "SBQQ__Quote__c", "file_type": "cpq_rule",
         "sf_cpq_object": "SBQQ__Quote__c",
         "source_file": "objects/SBQQ__Quote__c.object-meta.xml"},
        {"id": price_rule_id, "label": "SBQQ__PriceRule__c Discount",
         "file_type": "cpq_rule", "sf_cpq_object": "SBQQ__PriceRule__c Discount",
         "source_file": "objects/SBQQ__PriceRule__c.object-meta.xml"},
        # An Admin profile restricting a CPQ field, plus an unrelated profile.
        {"id": "profile_admin", "label": "Admin", "file_type": "profile",
         "source_file": "profiles/Admin.profile-meta.xml",
         "sf_fls_permissions": {
             # Restricted CPQ field on a CPQ object -> risk.
             "SBQQ__Quote__c.SBQQ__NetPrice__c": {"readable": False, "editable": False},
             # Readable CPQ field -> no risk.
             "SBQQ__Quote__c.SBQQ__ListPrice__c": {"readable": True, "editable": True},
             # Non-CPQ field (no SBQQ__) -> ignored even if restricted.
             "Account.BillingCity": {"readable": False, "editable": False},
         }},
        {"id": "permission_set_sales", "label": "Sales",
         "file_type": "permission_set",
         "source_file": "permissionsets/Sales.permissionset-meta.xml"},
    ]
    all_edges: list[dict] = []

    input_nodes_obj = all_nodes
    input_edges_obj = all_edges
    nodes_before = len(all_nodes)

    risks = permission_analysis_pass(all_nodes, all_edges)

    # Contract: pure function — returns risk edges, mutates neither list.
    assert isinstance(risks, list)
    assert all_nodes is input_nodes_obj
    assert all_edges is input_edges_obj
    assert all_edges == []
    assert len(all_nodes) == nodes_before

    # 1. Exactly one risk edge: the restricted CPQ field on the Quote CPQ object.
    assert len(risks) == 1
    risk = risks[0]
    assert risk["source"] == quote_id  # CPQ rule -> Profile (ADR-028)
    assert risk["target"] == "profile_admin"
    assert risk["relation"] == "gov_permission_violation"
    assert risk["sf_risk_type"] == "fls_restricted"
    assert risk["sf_field"] == "SBQQ__Quote__c.SBQQ__NetPrice__c"
    assert risk["sf_severity"] == "HIGH"
    assert risk["confidence"] == "INFERRED"
    assert risk["confidence_value"] == 0.75

    # 2. Readable CPQ field produced no risk; non-CPQ field ignored.
    assert all(r["sf_field"] != "SBQQ__Quote__c.SBQQ__ListPrice__c" for r in risks)
    assert all("Account" not in r["sf_field"] for r in risks)

    # 3. The PriceRule CPQ object has no restricted field -> not a risk source.
    assert all(r["source"] != price_rule_id for r in risks)

    # 4. Risk edges reference existing nodes (no dangling once extended).
    node_ids = {n["id"] for n in all_nodes}
    for r in risks:
        assert r["source"] in node_ids, f"dangling source: {r}"
        assert r["target"] in node_ids, f"dangling target: {r}"

    # Re-run safety: a pure pass yields identical edges (idempotent).
    risks_2 = permission_analysis_pass(all_nodes, all_edges)
    assert len(risks_2) == 1


def test_flow_cpq_loops() -> None:
    """Flow-CPQ loop pass: Type A (Direct) detection + safe-pattern downgrade.

    A Record-Triggered Flow that performs DML on a Quote object re-triggers
    itself once CPQ saves the recalculated Quote (ADR-029 Type A, CRITICAL). A
    flow carrying a recursion-prevention marker is still reported but tagged
    ``sf_loop_prevention`` and downgraded to INFO. Only Record-Triggered flows
    that update a Quote object qualify; Screen flows and non-Quote DML are out.
    """
    quote_id = sobject_nid("SBQQ__Quote__c")
    account_id = sobject_nid("Account")

    all_nodes: list[dict] = [
        {"id": quote_id, "label": "SBQQ__Quote__c", "file_type": "sobject",
         "source_file": "objects/SBQQ__Quote__c.object-meta.xml"},
        {"id": account_id, "label": "Account", "file_type": "sobject",
         "source_file": "objects/Account.object-meta.xml"},
        # Record-Triggered Flow updating Quote -> Type A direct loop (CRITICAL).
        {"id": "flow_quotesync", "label": "QuoteSync", "file_type": "flow",
         "source_file": "flows/QuoteSync.flow-meta.xml",
         "sf_trigger_object": "SBQQ__Quote__c", "sf_trigger_type": "CreateAndUpdate"},
        # Record-Triggered Flow updating Quote BUT guarded (isFirstRun) -> INFO.
        {"id": "flow_quoteguard", "label": "QuoteGuard", "file_type": "flow",
         "source_file": "flows/QuoteGuard.flow-meta.xml",
         "sf_trigger_object": "SBQQ__Quote__c", "sf_trigger_type": "Update",
         "sf_entry_conditions": "isFirstRun == true"},
        # Record-Triggered Flow updating Account (not Quote) -> no loop.
        {"id": "flow_accountnotify", "label": "AccountNotify", "file_type": "flow",
         "source_file": "flows/AccountNotify.flow-meta.xml",
         "sf_trigger_object": "Account", "sf_trigger_type": "Create"},
        # Screen Flow (NOT record-triggered) updating Quote -> no Type A loop.
        {"id": "flow_screenquote", "label": "ScreenQuote", "file_type": "flow",
         "source_file": "flows/ScreenQuote.flow-meta.xml",
         "sf_trigger_object": None, "sf_trigger_type": None},
    ]
    all_edges: list[dict] = [
        {"source": "flow_quotesync", "target": quote_id,
         "relation": "dml_operates_on", "sf_dml_type": "UPDATE",
         "confidence": "EXTRACTED", "source_file": "flows/QuoteSync.flow-meta.xml"},
        # Second Quote DML on the same flow -> must NOT create a second loop edge.
        {"source": "flow_quotesync", "target": sobject_nid("SBQQ__QuoteLine__c"),
         "relation": "dml_operates_on", "sf_dml_type": "UPDATE",
         "confidence": "EXTRACTED", "source_file": "flows/QuoteSync.flow-meta.xml"},
        {"source": "flow_quoteguard", "target": quote_id,
         "relation": "dml_operates_on", "sf_dml_type": "UPDATE",
         "confidence": "EXTRACTED", "source_file": "flows/QuoteGuard.flow-meta.xml"},
        {"source": "flow_accountnotify", "target": account_id,
         "relation": "dml_operates_on", "sf_dml_type": "UPDATE",
         "confidence": "EXTRACTED", "source_file": "flows/AccountNotify.flow-meta.xml"},
        {"source": "flow_screenquote", "target": quote_id,
         "relation": "dml_operates_on", "sf_dml_type": "UPDATE",
         "confidence": "EXTRACTED", "source_file": "flows/ScreenQuote.flow-meta.xml"},
    ]

    input_nodes_obj = all_nodes
    input_edges_obj = all_edges
    nodes_before = len(all_nodes)
    edges_before = len(all_edges)

    loops = detect_flow_cpq_loops(all_nodes, all_edges)

    # Contract: pure function — returns loop edges, mutates neither list.
    assert isinstance(loops, list)
    assert all_nodes is input_nodes_obj
    assert all_edges is input_edges_obj
    assert len(all_nodes) == nodes_before
    assert len(all_edges) == edges_before

    by_source = {e["source"]: e for e in loops}

    # 1. Flow -> Quote update detected; exactly two loops (sync + guard).
    assert set(by_source) == {"flow_quotesync", "flow_quoteguard"}
    assert len(loops) == 2  # quotesync deduped despite two Quote DML edges

    # 2. Type A (Direct) loop for the unguarded flow -> CRITICAL self-edge.
    sync = by_source["flow_quotesync"]
    assert sync["source"] == sync["target"] == "flow_quotesync"  # self-loop
    assert sync["relation"] == "infinite_loop_risk"
    assert sync["confidence"] == "INFERRED"
    assert sync["confidence_value"] == 0.85
    assert sync["sf_loop_type"] == "A_DIRECT"
    assert sync["sf_severity"] == "CRITICAL"
    assert sync["sf_loop_prevention"] is False

    # 3. Safe-pattern detected on the guarded flow -> downgraded to INFO.
    guard = by_source["flow_quoteguard"]
    assert guard["sf_loop_type"] == "A_DIRECT"
    assert guard["sf_loop_prevention"] is True
    assert guard["sf_severity"] == "INFO"

    # 4. Non-Quote DML and Screen (non record-triggered) flows produce no loop.
    assert "flow_accountnotify" not in by_source
    assert "flow_screenquote" not in by_source

    # 5. Self-edges reference existing nodes (no dangling once extended).
    node_ids = {n["id"] for n in all_nodes}
    for loop in loops:
        assert loop["source"] in node_ids, f"dangling source: {loop}"
        assert loop["target"] in node_ids, f"dangling target: {loop}"

    # Re-run safety: a pure pass yields identical results (idempotent).
    loops_2 = detect_flow_cpq_loops(all_nodes, all_edges)
    assert len(loops_2) == 2


def test_apex_calls_pass(tmp_path: Path) -> None:
    """Class names invoked from other Apex (static call, ``new``, ``.class``)
    become INFERRED ``calls`` edges; mentions in comments / strings, type-only
    declarations and self-references do not."""
    classes = tmp_path / "classes"
    triggers = tmp_path / "triggers"
    classes.mkdir()
    triggers.mkdir()
    (triggers / "AccountTrigger.trigger").write_text(
        "trigger AccountTrigger on Account (before update, after update) {\n"
        "    new AccountTriggerHandler().run();\n"
        "}\n", encoding="utf-8")
    (classes / "AccountTriggerHandler.cls").write_text(
        "public class AccountTriggerHandler {\n"
        "    // AccountAudit.log() is commented out\n"
        "    String note = 'AccountAudit.log()';\n"
        "    public void run() {\n"
        "        accountservice.touch(Trigger.new);\n"
        "        Dispatcher.register(AccountRules.class);\n"
        "        AccountTriggerHandler.helper();\n"
        "    }\n"
        "    static void helper() {}\n"
        "}\n", encoding="utf-8")
    (classes / "AccountService.cls").write_text(
        "public class AccountService {\n"
        "    public static void touch(List<Account> rows) {\n"
        "        AccountRules typed;\n"
        "        update rows;\n"
        "    }\n"
        "}\n", encoding="utf-8")
    for name in ("AccountAudit", "AccountRules", "Dispatcher"):
        (classes / f"{name}.cls").write_text(
            f"public class {name} {{ public static void register(Type t) {{}} }}\n",
            encoding="utf-8")

    result = extract_sf(tmp_path)
    calls = {(e["source"], e["target"]) for e in result["edges"]
             if e["relation"] == "calls" and not e.get("sf_method_level")}
    assert calls == {
        (apex_nid("AccountTrigger"), apex_nid("AccountTriggerHandler")),
        (apex_nid("AccountTriggerHandler"), apex_nid("AccountService")),
        (apex_nid("AccountTriggerHandler"), apex_nid("Dispatcher")),
        (apex_nid("AccountTriggerHandler"), apex_nid("AccountRules")),
    }
    # Method level: from the enclosing method to each parsed callee method.
    method_calls = {(e["source"], e["target"]) for e in result["edges"]
                    if e.get("sf_method_level")}
    assert method_calls == {
        (apex_method_nid("AccountTriggerHandler", "run"), apex_method_nid("AccountService", "touch")),
        (apex_method_nid("AccountTriggerHandler", "run"), apex_method_nid("Dispatcher", "register")),
    }
    call = next(e for e in result["edges"] if e["relation"] == "calls"
                and e["source"] == apex_nid("AccountTrigger"))
    assert call["confidence"] == "INFERRED"
    assert call["source_location"] == "L2"
    assert call["source_file"] == "triggers/AccountTrigger.trigger"

    # The handler's service updates Account, re-firing the Account trigger:
    # the trigger -> handler -> service -> trigger re-entry is a recursion risk.
    recursive = [e for e in result["edges"]
                 if e.get("sf_violation_type") == "recursive_trigger"]
    assert len(recursive) == 1
    assert recursive[0]["sf_cycle"] == sorted([
        apex_nid("AccountService"), apex_nid("AccountTrigger"),
        apex_nid("AccountTriggerHandler")])


def test_apex_real_org_shapes(tmp_path: Path) -> None:
    """Multi-line signatures keep ``member_of``; platform interfaces become stub
    nodes; a query split across concatenated literals still names its object;
    tooling folders (``.sfdx``) are not parsed."""
    classes = tmp_path / "force-app" / "classes"
    classes.mkdir(parents=True)
    (classes / "NightlyBatch.cls").write_text(
        "public with sharing class NightlyBatch implements Database.Batchable<SObject>,\n"
        "        Database.Stateful, Schedulable {\n"
        "    @AuraEnabled(cacheable=false)\n"
        "    public static Map<Id, List<Database.SaveResult>> listRows(\n"
        "        String a,\n"
        "        Integer b\n"
        "    ) {\n"
        "        String q = 'SELECT Id, Status ' +\n"
        "            'FROM ServiceAppointment WHERE ' + a;\n"
        "        return null;\n"
        "    }\n"
        "}\n", encoding="utf-8")
    sfdx = tmp_path / ".sfdx" / "tools" / "StandardApexLibrary" / "System"
    sfdx.mkdir(parents=True)
    (sfdx / "Http.cls").write_text("global class Http { global Http() {} }\n", encoding="utf-8")

    result = extract_sf(tmp_path)
    ids = {n["id"] for n in result["nodes"]}
    assert apex_nid("Http") not in ids
    member = {(e["source"], e["target"]) for e in result["edges"] if e["relation"] == "member_of"}
    assert (apex_method_nid("NightlyBatch", "listRows"), apex_nid("NightlyBatch")) in member
    implements = {e["target"] for e in result["edges"] if e["relation"] == "implements"}
    assert implements == {apex_nid("Database.Batchable"), apex_nid("Database.Stateful"),
                          apex_nid("Schedulable")}
    stub = next(n for n in result["nodes"] if n["id"] == apex_nid("Database.Batchable"))
    assert stub["sf_stub"] and stub["sf_platform"]
    queries = [e for e in result["edges"] if e["relation"] == "queries"]
    assert [(e["target"], e.get("sf_dynamic")) for e in queries] == [
        (sobject_nid("ServiceAppointment"), True)]


def _flow_xml(trigger_type: str, status: str) -> str:
    return f"""
<Flow xmlns="http://soap.sforce.com/2006/04/metadata">
    <processType>AutoLaunchedFlow</processType>
    <start>
        <object>Account</object>
        <recordTriggerType>CreateAndUpdate</recordTriggerType>
        <triggerType>{trigger_type}</triggerType>
    </start>
    <status>{status}</status>
</Flow>
"""


def test_ooe_runs_in(tmp_path: Path) -> None:
    """Each automation that runs in a save is attached to its OoE step with a
    ``runs_in`` edge; inactive components are not."""
    _md_file(tmp_path, "triggers/AccountTrigger.trigger",
             "trigger AccountTrigger on Account (before insert, after update) {}\n")
    _md_file(tmp_path, "flows/Acc_Before.flow-meta.xml", _flow_xml("RecordBeforeSave", "Active"))
    _md_file(tmp_path, "flows/Acc_After.flow-meta.xml", _flow_xml("RecordAfterSave", "Active"))
    _md_file(tmp_path, "flows/Acc_Draft.flow-meta.xml", _flow_xml("RecordAfterSave", "Draft"))
    _md_file(tmp_path, "objects/Account/validationRules/Need_Name.validationRule-meta.xml", """
<ValidationRule xmlns="http://soap.sforce.com/2006/04/metadata">
    <fullName>Need_Name</fullName><active>true</active>
    <errorConditionFormula>ISBLANK(Name)</errorConditionFormula>
</ValidationRule>
""")
    _md_file(tmp_path, "duplicateRules/Account.Dup.duplicateRule-meta.xml", """
<DuplicateRule xmlns="http://soap.sforce.com/2006/04/metadata">
    <isActive>true</isActive><masterLabel>Dup</masterLabel>
</DuplicateRule>
""")
    _md_file(tmp_path, "workflows/Account.workflow-meta.xml", """
<Workflow xmlns="http://soap.sforce.com/2006/04/metadata">
    <rules><fullName>Notify</fullName><active>true</active></rules>
    <rules><fullName>Retired</fullName><active>false</active></rules>
</Workflow>
""")
    _md_file(tmp_path, "sharingRules/Account.sharingRules-meta.xml", """
<SharingRules xmlns="http://soap.sforce.com/2006/04/metadata">
    <sharingCriteriaRules>
        <fullName>Big</fullName><accessLevel>Read</accessLevel>
    </sharingCriteriaRules>
    <sharingOwnerRules>
        <fullName>Team</fullName><accessLevel>Read</accessLevel>
    </sharingOwnerRules>
</SharingRules>
""")
    _md_file(tmp_path, "assignmentRules/Lead.assignmentRules-meta.xml", """
<AssignmentRules xmlns="http://soap.sforce.com/2006/04/metadata">
    <assignmentRule><fullName>Std</fullName><active>true</active></assignmentRule>
</AssignmentRules>
""")

    result = extract_sf(tmp_path)
    _assert_no_dangling_edges(result)
    labels = {n["id"]: n["label"] for n in result["nodes"]}
    runs_in = sorted((labels[e["source"]], labels[e["target"]])
                     for e in result["edges"] if e["relation"] == "runs_in")
    assert runs_in == [
        ("Acc_After", "Account: After-Save Flow"),
        ("Acc_Before", "Account: Before-Save Flow"),
        ("Account", "Account: Workflow Rules"),
        ("AccountTrigger", "Account: After Trigger"),
        ("AccountTrigger", "Account: Before Trigger"),
        ("Big", "Account: Criteria-Based Sharing"),
        ("Dup", "Account: Duplicate Rules"),
        ("Need_Name", "Account: Custom Validation"),
        ("Std", "Lead: Assignment Rules"),
    ]
    # Steps follow the documented order: before-save flows precede before triggers.
    steps = {n["label"]: n["sf_ooe_step"] for n in result["nodes"] if "sf_ooe_step" in n}
    assert steps["Account: Before-Save Flow"] < steps["Account: Before Trigger"]
    assert steps["Account: Escalation Rules"] < steps["Account: After-Save Flow"]

    G = build_sf_graph(result)
    text = sf_ooe(G, "Account")["text"]
    assert "Acc_Before" in text and "AccountTrigger" in text


def test_detect_recursive_triggers() -> None:
    """``calls`` cycles -> governor_violation; guarded recursion downgraded."""
    all_nodes: list[dict] = [
        # Unguarded 2-cycle: A <-> B.
        {"id": "code_a", "label": "AccountTriggerHandlerA", "file_type": "code",
         "sf_code_type": "class", "_source": "void run() { B.go(); }"},
        {"id": "code_b", "label": "ServiceB", "file_type": "code",
         "sf_code_type": "class", "_source": "void go() { A.run(); }"},
        # Guarded 2-cycle: C <-> D, where C uses a static Boolean flag.
        {"id": "code_c", "label": "ContactHandler", "file_type": "code",
         "sf_code_type": "class",
         "_source": "private static Boolean isRunning = false;"},
        {"id": "code_d", "label": "ContactService", "file_type": "code",
         "sf_code_type": "class", "_source": "void touch() { C.run(); }"},
        # Acyclic edge -> never reported.
        {"id": "code_e", "label": "Leaf", "file_type": "code",
         "sf_code_type": "class", "_source": ""},
    ]
    all_edges: list[dict] = [
        {"source": "code_a", "target": "code_b", "relation": "calls",
         "confidence": "EXTRACTED", "source_file": "A.cls"},
        {"source": "code_b", "target": "code_a", "relation": "calls",
         "confidence": "EXTRACTED", "source_file": "B.cls"},
        {"source": "code_c", "target": "code_d", "relation": "calls",
         "confidence": "EXTRACTED", "source_file": "C.cls"},
        {"source": "code_d", "target": "code_c", "relation": "calls",
         "confidence": "EXTRACTED", "source_file": "D.cls"},
        {"source": "code_a", "target": "code_e", "relation": "calls",
         "confidence": "EXTRACTED", "source_file": "A.cls"},
    ]

    edges_before = len(all_edges)
    violations = detect_recursive_triggers(all_nodes, all_edges)

    # Contract: pure w.r.t. edges; sentinel node appended once.
    assert len(all_edges) == edges_before
    assert sum(1 for n in all_nodes if n["id"] == "gov_recursive_trigger") == 1

    by_source = {e["source"]: e for e in violations}
    # Two distinct cycles (A/B and C/D), deduped across rotations.
    assert len(violations) == 2
    assert all(v["relation"] == "governor_violation" for v in violations)
    assert all(v["sf_violation_type"] == "recursive_trigger" for v in violations)
    assert all(v["target"] == "gov_recursive_trigger" for v in violations)

    # Unguarded A/B cycle -> HIGH; guarded C/D cycle -> LOW.
    ab = by_source["code_a"]
    assert ab["sf_safe_recursion"] is False
    assert ab["sf_severity"] == "HIGH"
    assert ab["sf_cycle"] == ["code_a", "code_b"]

    cd = by_source["code_c"]
    assert cd["sf_safe_recursion"] is True
    assert cd["sf_severity"] == "LOW"

    # No dangling endpoints; idempotent re-run.
    node_ids = {n["id"] for n in all_nodes}
    for v in violations:
        assert v["source"] in node_ids and v["target"] in node_ids
    assert len(detect_recursive_triggers(all_nodes, all_edges)) == 2


def test_validation_cpq_field_overlap() -> None:
    """CPQ rule writing a field a same-object Validation Rule checks -> risk edge."""
    quote_id = sobject_nid("SBQQ__Quote__c")
    opp_id = sobject_nid("Opportunity")

    all_nodes: list[dict] = [
        # CPQ rule on Quote that writes Discount__c + NetTotal__c.
        {"id": "cpq_discount", "label": "SBQQ__PriceRule__c Discount",
         "file_type": "cpq_rule", "sf_cpq_object": "SBQQ__Quote__c",
         "sf_target_fields": ["SBQQ__Quote__c.Discount__c", "NetTotal__c"],
         "source_file": "objects/SBQQ__PriceRule__c/Discount.xml"},
        # Validation Rule on Quote that checks Discount__c (object via sf_object).
        {"id": "val_maxdiscount", "label": "MaxDiscount",
         "file_type": "validation_rule", "sf_object": "SBQQ__Quote__c",
         "sf_referenced_fields": ["Discount__c", "Approved__c"],
         "source_file": "objects/SBQQ__Quote__c/MaxDiscount.validationRule-meta.xml"},
        # Validation Rule on Quote, object inferred from a ``validates`` edge.
        {"id": "val_nettotal", "label": "NetTotalPositive",
         "file_type": "validation_rule",
         "sf_referenced_fields": ["NetTotal__c"],
         "source_file": "objects/SBQQ__Quote__c/NetTotalPositive.validationRule-meta.xml"},
        # Validation Rule on a DIFFERENT object sharing a field name -> no risk.
        {"id": "val_oppdiscount", "label": "OppDiscount",
         "file_type": "validation_rule", "sf_object": "Opportunity",
         "sf_referenced_fields": ["Discount__c"],
         "source_file": "objects/Opportunity/OppDiscount.validationRule-meta.xml"},
        quote_node := {"id": quote_id, "label": "SBQQ__Quote__c",
                       "file_type": "sobject"},
        {"id": opp_id, "label": "Opportunity", "file_type": "sobject"},
    ]
    all_edges: list[dict] = [
        {"source": "val_nettotal", "target": quote_id, "relation": "validates",
         "confidence": "EXTRACTED", "source_file": quote_node["label"]},
        {"source": "val_oppdiscount", "target": opp_id, "relation": "validates",
         "confidence": "EXTRACTED", "source_file": "Opportunity"},
    ]

    input_nodes_obj = all_nodes
    input_edges_obj = all_edges
    nodes_before = len(all_nodes)
    edges_before = len(all_edges)

    risks = validation_cpq_analysis_pass(all_nodes, all_edges)

    # Contract: pure function — returns risk edges, mutates neither list.
    assert isinstance(risks, list)
    assert all_nodes is input_nodes_obj
    assert all_edges is input_edges_obj
    assert len(all_nodes) == nodes_before
    assert len(all_edges) == edges_before

    by_target = {e["target"]: e for e in risks}

    # 1. Two risks: Discount__c overlap (sf_object) + NetTotal__c (validates edge).
    #    The cross-object Discount__c clash is NOT reported.
    assert set(by_target) == {"val_maxdiscount", "val_nettotal"}

    # 2. Discount__c overlap on Quote -> well-formed cpq_validation_risk edge.
    discount = by_target["val_maxdiscount"]
    assert discount["source"] == "cpq_discount"
    assert discount["relation"] == "cpq_validation_risk"
    assert discount["confidence"] == "INFERRED"
    assert discount["confidence_value"] == 0.7
    assert discount["sf_risk_level"] == "MEDIUM"
    assert discount["sf_overlapping_fields"] == ["discount__c"]  # bare, normalized

    # 3. Object inferred from the ``validates`` edge still matches (NetTotal__c).
    nettotal = by_target["val_nettotal"]
    assert nettotal["sf_overlapping_fields"] == ["nettotal__c"]

    # 4. No dangling edges; both endpoints reference existing nodes.
    node_ids = {n["id"] for n in all_nodes}
    for risk in risks:
        assert risk["source"] in node_ids, f"dangling source: {risk}"
        assert risk["target"] in node_ids, f"dangling target: {risk}"

    # Re-run safety: a pure pass yields identical results (idempotent).
    assert len(validation_cpq_analysis_pass(all_nodes, all_edges)) == len(risks)


def test_validation_cpq_no_field_data_yields_nothing() -> None:
    """Without field data on either side, the pass emits no false positives."""
    quote_id = sobject_nid("SBQQ__Quote__c")
    nodes = [
        {"id": "cpq_x", "label": "SBQQ__PriceRule__c X", "file_type": "cpq_rule",
         "sf_cpq_object": "SBQQ__Quote__c"},  # no sf_target_fields
        {"id": "val_x", "label": "ValX", "file_type": "validation_rule",
         "sf_object": "SBQQ__Quote__c"},  # no sf_referenced_fields
        {"id": quote_id, "label": "SBQQ__Quote__c", "file_type": "sobject"},
    ]
    assert validation_cpq_analysis_pass(nodes, []) == []


def test_validation_rule_parser_standalone(tmp_path: Path) -> None:
    """A standalone *.validationRule-meta.xml -> validation_rule node + validates edge."""
    vr = (
        tmp_path / "objects" / "SBQQ__Quote__c" / "validationRules"
        / "MaxDiscount.validationRule-meta.xml"
    )
    vr.parent.mkdir(parents=True)
    vr.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<ValidationRule xmlns="http://soap.sforce.com/2006/04/metadata">\n'
        "  <fullName>MaxDiscount</fullName>\n"
        "  <active>true</active>\n"
        "  <errorConditionFormula>AND(ISCHANGED(SBQQ__Discount__c), "
        "SBQQ__Discount__c &gt; 50)</errorConditionFormula>\n"
        "</ValidationRule>\n",
        encoding="utf-8",
    )
    result = extract_validation_rule(vr)
    assert "error" not in result
    _assert_no_dangling_edges(result)

    rule = next(n for n in result["nodes"] if n["file_type"] == "validation_rule")
    assert rule["sf_object"] == "SBQQ__Quote__c"
    assert rule["sf_active"] is True
    # Function tokens (AND/ISCHANGED) filtered; the field is kept (deduped).
    assert rule["sf_referenced_fields"] == ["SBQQ__Discount__c"]

    validates = [e for e in result["edges"] if e["relation"] == "validates"]
    assert len(validates) == 1
    assert validates[0]["source"] == rule["id"]
    assert validates[0]["target"] == sobject_nid("SBQQ__Quote__c")


def test_validation_rule_parser_embedded(tmp_path: Path) -> None:
    """<validationRules> embedded in an object-meta.xml are extracted too."""
    obj = tmp_path / "SBQQ__Quote__c.object-meta.xml"
    obj.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<CustomObject xmlns="http://soap.sforce.com/2006/04/metadata">\n'
        "  <label>SBQQ__Quote__c</label>\n"
        "  <validationRules>\n"
        "    <fullName>NetTotalPositive</fullName>\n"
        "    <active>true</active>\n"
        "    <errorConditionFormula>NetTotal__c &lt; 0</errorConditionFormula>\n"
        "  </validationRules>\n"
        "</CustomObject>\n",
        encoding="utf-8",
    )
    result = extract_custom_object(obj)
    _assert_no_dangling_edges(result)

    rule = next(n for n in result["nodes"] if n["file_type"] == "validation_rule")
    assert rule["label"] == "NetTotalPositive"
    assert rule["sf_referenced_fields"] == ["NetTotal__c"]
    assert any(
        e["relation"] == "validates" and e["target"] == sobject_nid("SBQQ__Quote__c")
        for e in result["edges"]
    )


def test_cpq_qcp_field_writes_populate_target_fields() -> None:
    """cpq_analysis_pass records the fields a QCP plugin writes (sf_target_fields)."""
    qcp_source = (
        "global class QuoteCalculator implements SBQQ.QuoteCalculatorPlugin {\n"
        "  global void calculate(SBQQ.QuoteModel quote, "
        "List<SBQQ.QuoteLineModel> lines) {\n"
        "    quote.SBQQ__Discount__c = 10;\n"
        "    line.put('NetTotal__c', 5);\n"
        "    Boolean ok = a == b;\n"  # '==' must NOT be read as a field write
        "  }\n"
        "}\n"
    )
    nodes = [
        {"id": "apex_quotecalculator", "label": "QuoteCalculator",
         "file_type": "code", "sf_code_type": "class", "_source": qcp_source},
    ]
    cpq_analysis_pass(nodes, [])

    qcp = nodes[0]
    assert qcp["sf_qcp_implementation"] is True
    assert set(qcp["sf_target_fields"]) == {"SBQQ__Discount__c", "NetTotal__c"}
    assert qcp["sf_cpq_object"] == "SBQQ__Quote__c"


def test_validation_cpq_fires_end_to_end(tmp_path: Path) -> None:
    """extract_sf wires QCP writes + Validation Rule into a cpq_validation_risk edge."""
    default = tmp_path / "force-app" / "main" / "default"
    (default / "classes").mkdir(parents=True)
    (default / "objects" / "SBQQ__Quote__c" / "validationRules").mkdir(parents=True)

    # QCP plugin that writes SBQQ__Discount__c on the Quote.
    (default / "classes" / "QuoteCalculator.cls").write_text(
        "global class QuoteCalculator implements SBQQ.QuoteCalculatorPlugin {\n"
        "  global void calculate(SBQQ.QuoteModel quote, "
        "List<SBQQ.QuoteLineModel> lines) {\n"
        "    quote.SBQQ__Discount__c = 10;\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    # Validation Rule on the same Quote object that checks SBQQ__Discount__c.
    (
        default / "objects" / "SBQQ__Quote__c" / "validationRules"
        / "MaxDiscount.validationRule-meta.xml"
    ).write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<ValidationRule xmlns="http://soap.sforce.com/2006/04/metadata">\n'
        "  <fullName>MaxDiscount</fullName>\n"
        "  <errorConditionFormula>SBQQ__Discount__c &gt; 50</errorConditionFormula>\n"
        "</ValidationRule>\n",
        encoding="utf-8",
    )

    result = extract_sf(tmp_path)
    _assert_no_dangling_edges(result)

    risks = [e for e in result["edges"] if e["relation"] == "cpq_validation_risk"]
    assert risks, "expected a CPQ ↔ Validation overlap edge"
    risk = risks[0]
    assert risk["sf_overlapping_fields"] == ["sbqq__discount__c"]
    assert risk["confidence"] == "INFERRED"

    # The Validation Rule parser also feeds the OoE pass with a ``validates`` edge.
    assert any(e["relation"] == "validates" for e in result["edges"])


def test_pipeline_build_sf_graph_enriches(tmp_path: Path) -> None:
    """build_sf_graph -> directed graph with community labels; round-trips to JSON."""
    extraction = extract_sf(SAMPLE_ORG)
    G = build_sf_graph(extraction)

    assert isinstance(G, nx.DiGraph)
    # Every node lands in a community (serve._communities_from_graph reads this).
    assert G.number_of_nodes() > 0
    assert all("community" in d for _, d in G.nodes(data=True))

    out = write_sf_graph(G, tmp_path / "graph.json")
    assert out.exists()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["directed"] is True
    assert "links" in data  # serve._load_graph reads this key


def _two_relation_extraction() -> dict:
    acc = sobject_nid("Account")
    cls = apex_nid("AccService")
    return {
        "nodes": [
            {"id": acc, "label": "Account", "file_type": "sobject", "source_file": "a"},
            {"id": cls, "label": "AccService", "file_type": "code", "source_file": "c"},
        ],
        "edges": [
            {"source": cls, "target": acc, "relation": "queries", "confidence": "EXTRACTED",
             "sf_in_loop": False, "source_location": "L10", "source_file": "c"},
            {"source": cls, "target": acc, "relation": "queries", "confidence": "EXTRACTED",
             "sf_in_loop": True, "source_location": "L42", "source_file": "c"},
            {"source": cls, "target": acc, "relation": "dml_operates_on",
             "confidence": "INFERRED", "confidence_value": 0.9, "sf_dml_type": "UPDATE",
             "source_location": "L50", "source_file": "c"},
            {"source": cls, "target": "sobject_missing", "relation": "queries",
             "confidence": "EXTRACTED", "source_file": "c"},
        ],
    }


def test_build_keeps_every_relation_and_aggregates_sites() -> None:
    """Reads AND writes between one pair both survive; repeated sites fold.

    Real org: a DiGraph kept one edge per pair, dropping 6,292 edges — 902 of
    them a write hidden behind a read (or vice versa) on the same object.
    """
    G = build_sf_graph(_two_relation_extraction())
    assert G.is_multigraph()
    cls, acc = apex_nid("AccService"), sobject_nid("Account")
    assert set(G[cls][acc]) == {"queries", "dml_operates_on"}
    q = G[cls][acc]["queries"]
    assert q["sf_occurrences"] == 2
    assert q["source_locations"] == ["L10", "L42"]
    assert q["sf_in_loop"] is True  # any site in a loop
    assert "sf_occurrences" not in G[cls][acc]["dml_operates_on"]
    assert G.number_of_edges() == 2  # dangling edge dropped

    # An EXTRACTED site (no explicit value) outranks an INFERRED 0.8 site.
    extraction = _two_relation_extraction()
    extraction["edges"][0].update(confidence="INFERRED", confidence_value=0.8)
    q = build_sf_graph(extraction)[cls][acc]["queries"]
    assert q["confidence"] == "EXTRACTED" and "confidence_value" not in q


def test_written_graph_is_byte_identical_for_shuffled_input(tmp_path: Path) -> None:
    import random

    extraction = extract_sf(SAMPLE_ORG, include_permissions=True)
    first = write_sf_graph(build_sf_graph(extraction), tmp_path / "a.json").read_bytes()
    shuffled = {"nodes": list(extraction["nodes"]), "edges": list(extraction["edges"])}
    random.Random(7).shuffle(shuffled["nodes"])
    random.Random(7).shuffle(shuffled["edges"])
    second = write_sf_graph(build_sf_graph(shuffled), tmp_path / "b.json").read_bytes()
    assert first == second


def test_cli_loads_multigraph_and_impact_lists_both_relations(tmp_path: Path) -> None:
    from graphify.salesforce.cli import _load_graph

    path = write_sf_graph(build_sf_graph(_two_relation_extraction()), tmp_path / "g.json")
    G = _load_graph(path)
    assert G.is_multigraph()
    text = sf_impact(G, "AccService")["text"]
    assert "--queries" in text and "--dml_operates_on" in text
    # min_confidence filters per relation, not per node pair.
    filtered = sf_impact(G, "AccService", min_confidence=0.95)["text"]
    assert "--queries" in filtered and "--dml_operates_on" not in filtered


def test_resolve_node_matches_qualified_and_bare_field_names() -> None:
    from graphify.salesforce.query import resolve_node

    G = nx.MultiDiGraph()
    fid = field_nid("Account", "Revenue_Band__c")
    G.add_node(fid, label="Account.Revenue_Band__c", file_type="field",
               sf_qualified_name="Account.Revenue_Band__c", sf_api_name="Revenue_Band__c")
    assert resolve_node(G, "account.revenue_band__c") == fid
    assert resolve_node(G, "Revenue_Band__c") == fid


def _sf_query_graph() -> nx.DiGraph:
    """Small enriched SF graph for query-core tests."""
    quote = sobject_nid("SBQQ__Quote__c")
    G = nx.DiGraph()
    G.add_node("apex_accounttrigger", label="AccountTrigger", file_type="code")
    G.add_node("sobject_opportunity", label="Opportunity", file_type="sobject")
    G.add_node("gov_limit_soql_in_loop", label="⚠ SOQL-in-loop", file_type="concept")
    G.add_node("apex_weak", label="WeakLink", file_type="code")
    G.add_node(quote, label="SBQQ__Quote__c", file_type="sobject")
    G.add_node("cpq_rule_disc", label="SBQQ__PriceRule__c Discount", file_type="cpq_rule")
    G.add_node(f"ooe_{quote}_1", label="SBQQ__Quote__c: System Validation",
               file_type="concept", sf_ooe_step=1, sf_ooe_sobject=quote)
    G.add_node(f"ooe_{quote}_2", label="SBQQ__Quote__c: Before-Save Flow",
               file_type="concept", sf_ooe_step=2, sf_ooe_sobject=quote)

    G.add_edge("apex_accounttrigger", "sobject_opportunity",
               relation="queries", confidence="EXTRACTED", confidence_value=1.0)
    G.add_edge("apex_accounttrigger", "gov_limit_soql_in_loop",
               relation="governor_violation", confidence="EXTRACTED",
               sf_violation_type="soql_in_loop", sf_severity="HIGH")
    G.add_edge("apex_accounttrigger", "apex_weak",
               relation="calls", confidence="AMBIGUOUS", confidence_value=0.4)
    G.add_edge("cpq_rule_disc", quote,
               relation="cpq_applies_to", confidence="INFERRED", execution_order=2)
    G.add_edge(f"ooe_{quote}_1", f"ooe_{quote}_2",
               relation="order_of_execution", confidence="EXTRACTED")
    return G


def test_sf_impact_traversal_and_confidence_filter() -> None:
    G = _sf_query_graph()

    imp = sf_impact(G, "AccountTrigger", depth=2)
    assert imp["node"] == "apex_accounttrigger"
    assert {"sobject_opportunity", "gov_limit_soql_in_loop", "apex_weak"} <= set(imp["nodes"])
    assert "IMPACT" in imp["text"]

    # min_confidence drops the AMBIGUOUS (0.4) calls edge to WeakLink.
    filtered = sf_impact(G, "AccountTrigger", depth=2, min_confidence=0.8)
    assert "apex_weak" not in filtered["nodes"]
    assert "sobject_opportunity" in filtered["nodes"]

    # Unresolvable node -> node None, explanatory text, no crash.
    assert sf_impact(G, "NoSuchSymbol")["node"] is None


def test_sf_violations_and_severity_filter() -> None:
    G = _sf_query_graph()
    allv = sf_violations(G)
    assert any(v["violation_type"] == "soql_in_loop" for v in allv["violations"])

    high = sf_violations(G, severity="HIGH")
    assert len(high["violations"]) == 1
    assert high["violations"][0]["severity"] == "HIGH"

    assert sf_violations(G, severity="CRITICAL")["violations"] == []


def test_sf_impact_hints_other_direction() -> None:
    """An entry point has nothing upstream; an empty result says which way to look."""
    G = nx.MultiDiGraph()
    G.add_node("lwc_tiergauge", label="tierGauge", file_type="lwc_component")
    G.add_node("apex_ctl.get", label="Ctl.get", file_type="code")
    G.add_edge("lwc_tiergauge", "apex_ctl.get", relation="wire_to", confidence="INFERRED")

    up = sf_impact(G, "tierGauge", direction="upstream")
    assert up["hint"] == "downstream"
    assert "direction=downstream" in up["text"]
    down = sf_impact(G, "tierGauge", direction="downstream")
    assert down.get("hint") is None and "hint" not in down["text"]


def test_sf_cpq_chain_and_ooe() -> None:
    G = _sf_query_graph()
    chain = sf_cpq_chain(G, "SBQQ__Quote__c")
    assert chain["target"] == sobject_nid("SBQQ__Quote__c")
    assert any(s.get("execution_order") == 2 for s in chain["steps"])

    quote = sobject_nid("SBQQ__Quote__c")
    ooe = sf_ooe(G, "SBQQ__Quote__c")
    assert (f"ooe_{quote}_1", f"ooe_{quote}_2") in ooe["edges"]
    assert " 2. Before-Save Flow" in ooe["text"]


def test_cpq_data_parser() -> None:
    """SFDX JSON SBQQ exports -> cpq_rule/condition/action nodes + edges."""
    result = extract_cpq_data(FIXTURES / "sf_cpq_data")
    nodes = {n["id"]: n for n in result["nodes"]}

    # Price Rule node: applies object + aggregated target fields + eval order.
    rule = nodes["cpq_rule_a0x0000000000001"]
    assert rule["file_type"] == "cpq_rule"
    assert rule["sf_cpq_object"] == "SBQQ__Quote__c"
    assert rule["sf_cpq_rule_type"] == "Price"
    assert rule["sf_target_fields"] == ["SBQQ__Discount__c"]
    assert rule["sf_eval_order"] == 15

    # Condition + action nodes carry their fields.
    assert nodes["cpq_condition_a0y0000000000001"]["sf_field"] == "SBQQ__Quantity__c"
    assert nodes["cpq_action_a0z0000000000001"]["sf_target_field"] == "SBQQ__Discount__c"

    rels = {(e["source"], e["relation"], e["target"]) for e in result["edges"]}
    assert ("cpq_rule_a0x0000000000001", "cpq_has_condition",
            "cpq_condition_a0y0000000000001") in rels
    assert ("cpq_rule_a0x0000000000001", "cpq_has_action",
            "cpq_action_a0z0000000000001") in rels
    assert any(s == "cpq_rule_a0x0000000000001" and r == "cpq_applies_to"
               for s, r, _ in rels)

    # No dangling edges.
    ids = set(nodes)
    for e in result["edges"]:
        assert e["source"] in ids and e["target"] in ids


def test_cpq_data_qualifies_fields_and_rule_objects(tmp_path: Path) -> None:
    """CPQ picklist objects ("Quote Line") qualify field IDs and the rule target.

    Real org: rules "applied to" Always / Save / Load — evaluation-event picklist
    values — because the ingester fell back to SBQQ__EvaluationEvent__c.
    """
    rule_dir = tmp_path / "SBQQ__PriceRule__c"
    cond_dir = tmp_path / "SBQQ__PriceCondition__c"
    act_dir = tmp_path / "SBQQ__PriceAction__c"
    for d in (rule_dir, cond_dir, act_dir):
        d.mkdir()
    ref = [{"Name": "SBQQ__Rule__r", "ReferencedFields": {"GearsetExternalId__c": "R1"}}]
    (rule_dir / "r.gs.json").write_text(json.dumps({
        "Object": "SBQQ__PriceRule__c",
        "Fields": {"GearsetExternalId__c": "R1", "Name": "Line Discount",
                   "SBQQ__EvaluationEvent__c": "Always"}}), encoding="utf-8")
    (cond_dir / "c.gs.json").write_text(json.dumps({
        "Object": "SBQQ__PriceCondition__c",
        "Fields": {"GearsetExternalId__c": "C1", "SBQQ__Object__c": "Quote",
                   "SBQQ__Field__c": "Region__c"}, "References": ref}), encoding="utf-8")
    (act_dir / "a.gs.json").write_text(json.dumps({
        "Object": "SBQQ__PriceAction__c",
        "Fields": {"GearsetExternalId__c": "A1", "SBQQ__TargetObject__c": "Quote Line",
                   "SBQQ__Field__c": "SBQQ__Discount__c"}, "References": ref}), encoding="utf-8")

    result = extract_cpq_data(tmp_path)
    ids = {n["id"] for n in result["nodes"]}
    assert field_nid("SBQQ__Quote__c", "Region__c") in ids
    assert field_nid("SBQQ__QuoteLine__c", "SBQQ__Discount__c") in ids
    applies = next(e for e in result["edges"] if e["relation"] == "cpq_applies_to")
    assert applies["target"] == sobject_nid("SBQQ__QuoteLine__c")  # the action's object
    rule = next(n for n in result["nodes"] if n["id"] == "cpq_rule_r1")
    assert rule["sf_evaluation_event"] == "Always"
    assert not any(n["id"] == sobject_nid("Always") for n in result["nodes"])


def test_unqualified_field_reference_resolves_to_unique_definition(tmp_path: Path) -> None:
    """A field named without its object binds to the one defined field of that name."""
    f = tmp_path / "objects" / "Account" / "fields" / "Region__c.field-meta.xml"
    f.parent.mkdir(parents=True)
    f.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<CustomField xmlns="http://soap.sforce.com/2006/04/metadata">\n'
        "  <fullName>Region__c</fullName><type>Text</type>\n"
        "</CustomField>\n", encoding="utf-8")
    cpq = tmp_path / "cpq" / "SBQQ__PriceCondition__c"
    cpq.mkdir(parents=True)
    (cpq.parent / "SBQQ__PriceRule__c").mkdir()
    (cpq.parent / "SBQQ__PriceRule__c" / "r.gs.json").write_text(json.dumps({
        "Object": "SBQQ__PriceRule__c", "Fields": {"GearsetExternalId__c": "R1"}}),
        encoding="utf-8")
    (cpq / "c.gs.json").write_text(json.dumps({
        "Object": "SBQQ__PriceCondition__c",
        "Fields": {"GearsetExternalId__c": "C1", "SBQQ__Field__c": "Region__c"},
        "References": [{"Name": "SBQQ__Rule__r",
                        "ReferencedFields": {"GearsetExternalId__c": "R1"}}]}),
        encoding="utf-8")

    result = extract_sf(tmp_path / "objects", cpq_data_dir=tmp_path / "cpq")
    _assert_no_dangling_edges(result)
    reads = next(e for e in result["edges"] if e["relation"] == "cpq_reads_field")
    assert reads["target"] == field_nid("Account", "Region__c")
    assert not any(n["id"].startswith("field_?.") for n in result["nodes"])


def test_cpq_data_gearset_format(tmp_path: Path) -> None:
    """Gearset *.gs.json (Object/Fields/References) ingests natively — no adapter."""
    rule_dir = tmp_path / "SBQQ__PriceRule__c"
    act_dir = tmp_path / "SBQQ__PriceAction__c"
    rule_dir.mkdir(); act_dir.mkdir()
    (rule_dir / "r.gs.json").write_text(json.dumps({
        "Object": "SBQQ__PriceRule__c",
        "Fields": {"GearsetExternalId__c": "RULE1", "Name": "Apply Discount",
                   "SBQQ__EvaluationOrder__c": "50.0", "SBQQ__LookupObject__c": "SBQQ__Quote__c"},
    }), encoding="utf-8")
    (act_dir / "a.gs.json").write_text(json.dumps({
        "Object": "SBQQ__PriceAction__c",
        "Fields": {"GearsetExternalId__c": "ACT1", "SBQQ__Field__c": "SBQQ__Discount__c"},
        "References": [{"Name": "SBQQ__Rule__r", "ReferencedObject": "SBQQ__PriceRule__c",
                        "ReferencedFields": {"GearsetExternalId__c": "RULE1"}}],
    }), encoding="utf-8")

    result = extract_cpq_data(tmp_path)
    nodes = {n["id"]: n for n in result["nodes"]}

    rule = nodes["cpq_rule_rule1"]
    assert rule["sf_eval_order"] == 50.0           # "50.0" string coerced
    assert rule["sf_target_fields"] == ["SBQQ__Discount__c"]  # via References parent link
    assert rule["sf_cpq_object"] == "SBQQ__Quote__c"
    rels = {(e["source"], e["relation"], e["target"]) for e in result["edges"]}
    assert ("cpq_rule_rule1", "cpq_has_action", "cpq_action_act1") in rels
    ids = set(nodes)
    for e in result["edges"]:
        assert e["source"] in ids and e["target"] in ids


def test_cpq_data_qcp_custom_script_js(tmp_path: Path) -> None:
    """SBQQ__CustomScript__c (JS QCP) -> qcp_method nodes + declared field signals."""
    sdir = tmp_path / "SBQQ__CustomScript__c"
    sdir.mkdir()
    (sdir / "qcp.gs.json").write_text(json.dumps({
        "Object": "SBQQ__CustomScript__c",
        "Fields": {
            "GearsetExternalId__c": "QCP1", "Name": "Custom_QCP_Script",
            "SBQQ__Code__c": "export function onBeforeCalculate(q){} "
                             "export function onAfterCalculate(q){ q.SBQQ__Discount__c=1; }",
            "SBQQ__QuoteFields__c": ["SBQQ__Discount__c", "RequestedAmount__c"],
            "SBQQ__QuoteLineFields__c": ["RequestedPrice__c"],
        },
    }), encoding="utf-8")

    result = extract_cpq_data(tmp_path)
    nodes = {n["id"]: n for n in result["nodes"]}

    # The script itself is a QCP implementation carrying its declared fields.
    script = nodes["cpq_script_qcp1"]
    assert script["sf_qcp_implementation"] is True
    assert script["sf_qcp_language"] == "javascript"
    assert script["sf_cpq_object"] == "SBQQ__Quote__c"
    assert set(script["sf_target_fields"]) == {
        "SBQQ__Discount__c", "RequestedAmount__c", "RequestedPrice__c"}

    # One cpq_qcp_method node per detected JS hook (so sf_cpq_chain lists them).
    qcp_methods = {n["sf_qcp_method"] for n in result["nodes"]
                   if n.get("file_type") == "cpq_qcp_method"}
    assert qcp_methods == {"onBeforeCalculate", "onAfterCalculate"}


def test_extract_sf_cpq_data_fires_validation_and_order(tmp_path: Path) -> None:
    """CPQ data + a Validation Rule on the same field -> cpq_validation_risk; real order."""
    default = tmp_path / "force-app" / "main" / "default"
    vr_dir = default / "objects" / "SBQQ__Quote__c" / "validationRules"
    vr_dir.mkdir(parents=True)
    (vr_dir / "MaxDiscount.validationRule-meta.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<ValidationRule xmlns="http://soap.sforce.com/2006/04/metadata">\n'
        "  <fullName>MaxDiscount</fullName>\n"
        "  <errorConditionFormula>SBQQ__Discount__c &gt; 50</errorConditionFormula>\n"
        "</ValidationRule>\n",
        encoding="utf-8",
    )

    result = extract_sf(tmp_path, cpq_data_dir=str(FIXTURES / "sf_cpq_data"))
    _assert_no_dangling_edges(result)

    # The real Price Rule (writes Discount) vs the Validation Rule (checks Discount).
    risks = [e for e in result["edges"] if e["relation"] == "cpq_validation_risk"]
    assert risks, "expected cpq_validation_risk from real CPQ rule fields"
    assert risks[0]["sf_overlapping_fields"] == ["sbqq__discount__c"]

    # execution_order reflects the real SBQQ__EvaluationOrder__c (15), not a guess.
    applies = [e for e in result["edges"]
               if e["relation"] == "cpq_applies_to"
               and e["source"] == "cpq_rule_a0x0000000000001"]
    assert applies and applies[0]["execution_order"] == 15


def test_viz_build_self_contained_html(tmp_path: Path) -> None:
    """sf viz builds a focused, self-contained HTML with embedded data (no fetch)."""
    from graphify.salesforce.viz import build_viz, focus_subgraph

    G = _sf_query_graph()  # reuse the small enriched graph
    # focus_subgraph centers on seeds + 1-hop, excludes test nodes.
    seeds = ["apex_accounttrigger"]
    node_ids, edges = focus_subgraph(G, seeds, max_nodes=20)
    assert "apex_accounttrigger" in node_ids
    assert "sobject_opportunity" in node_ids  # 1-hop neighbor

    out = build_viz(G, tmp_path / "v.html", focus=["AccountTrigger"], title="T")
    assert out.exists()
    html = out.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in html
    assert "fetch(" not in html  # data embedded inline, not fetched (no CORS)
    assert "apex_accounttrigger" in html  # graph data is embedded


def test_record_type_parser(tmp_path: Path) -> None:
    """*.recordType-meta.xml -> record_type node + record_type_of edge to SObject."""
    rt = (tmp_path / "objects" / "SBQQ__Quote__c" / "recordTypes"
          / "Builder.recordType-meta.xml")
    rt.parent.mkdir(parents=True)
    rt.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<RecordType xmlns="http://soap.sforce.com/2006/04/metadata">\n'
        "  <fullName>Builder</fullName><active>true</active><label>Builder Quote</label>\n"
        "</RecordType>\n", encoding="utf-8")
    result = extract_record_type(rt)
    _assert_no_dangling_edges(result)
    node = next(n for n in result["nodes"] if n["file_type"] == "record_type")
    assert node["sf_object"] == "SBQQ__Quote__c"
    assert node["label"] == "Builder Quote"
    assert node["sf_qualified_name"] == "SBQQ__Quote__c.Builder"
    edge = next(e for e in result["edges"] if e["relation"] == "record_type_of")
    assert edge["source"] == node["id"]
    assert edge["target"] == sobject_nid("SBQQ__Quote__c")


_MD_XML = '<?xml version="1.0" encoding="UTF-8"?>\n'


def _md_file(root: Path, rel: str, body: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_MD_XML + body, encoding="utf-8")
    return path


def _field_refs_by(result: dict) -> set[tuple[str, str, str]]:
    return {(r["object"], r["path"], r["relation"]) for r in result.get("field_refs", [])}


def test_assignment_rules_parser(tmp_path: Path) -> None:
    """assignmentRules/<Obj>.assignmentRules-meta.xml -> one node per rule,
    rule_of its object, criteria fields as reads; escalation / auto-response
    rule files share the shape."""
    path = _md_file(tmp_path, "assignmentRules/Lead.assignmentRules-meta.xml", """
<AssignmentRules xmlns="http://soap.sforce.com/2006/04/metadata">
    <assignmentRule>
        <fullName>Partner Queue Assignment</fullName>
        <active>true</active>
        <ruleEntry>
            <assignedTo>PartnerQueue</assignedTo>
            <assignedToType>Queue</assignedToType>
            <criteriaItems>
                <field>Lead.Region__c</field>
                <operation>equals</operation>
                <value>East</value>
            </criteriaItems>
        </ruleEntry>
        <ruleEntry>
            <assignedTo>FallbackQueue</assignedTo>
            <assignedToType>Queue</assignedToType>
            <criteriaItems>
                <field>Lead.Region__c</field>
                <operation>notEqual</operation>
                <value>East</value>
            </criteriaItems>
            <criteriaItems>
                <field>Account.Type</field>
                <operation>equals</operation>
                <value>Partner</value>
            </criteriaItems>
        </ruleEntry>
    </assignmentRule>
    <assignmentRule>
        <fullName>Old Assignment</fullName>
        <active>false</active>
    </assignmentRule>
</AssignmentRules>
""")
    result = extract_rule_entries(path)
    _assert_no_dangling_edges(result)
    rules = {n["sf_qualified_name"]: n for n in result["nodes"]
             if n["file_type"] == "assignment_rule"}
    assert set(rules) == {"Lead.Partner Queue Assignment", "Lead.Old Assignment"}
    active = rules["Lead.Partner Queue Assignment"]
    assert active["sf_active"] is True
    assert active["sf_assigned_to"] == ["FallbackQueue", "PartnerQueue"]
    assert rules["Lead.Old Assignment"]["sf_active"] is False
    rule_of = [e for e in result["edges"] if e["relation"] == "rule_of"]
    assert {e["target"] for e in rule_of} == {sobject_nid("Lead")}
    assert len(rule_of) == 2
    assert _field_refs_by(result) == {
        ("Lead", "Region__c", "reads_field"), ("Account", "Type", "reads_field")}

    esc = _md_file(tmp_path, "escalationRules/Case.escalationRules-meta.xml", """
<EscalationRules xmlns="http://soap.sforce.com/2006/04/metadata">
    <escalationRule>
        <fullName>Standard</fullName>
        <active>true</active>
    </escalationRule>
</EscalationRules>
""")
    esc_node = next(n for n in extract_rule_entries(esc)["nodes"]
                    if n["file_type"] == "escalation_rule")
    assert esc_node["sf_qualified_name"] == "Case.Standard"


def test_duplicate_and_matching_rule_parsers(tmp_path: Path) -> None:
    dup = _md_file(tmp_path, "duplicateRules/Account.Name_Duplicate.duplicateRule-meta.xml", """
<DuplicateRule xmlns="http://soap.sforce.com/2006/04/metadata" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <actionOnInsert>Allow</actionOnInsert>
    <actionOnUpdate>Block</actionOnUpdate>
    <duplicateRuleFilter>
        <booleanFilter xsi:nil="true"/>
        <duplicateRuleFilterItems>
            <field>BusinessUnit__c</field>
            <operation>equals</operation>
            <value>Retail</value>
            <sortOrder>1</sortOrder>
            <table>Account</table>
        </duplicateRuleFilterItems>
    </duplicateRuleFilter>
    <duplicateRuleMatchRules>
        <matchRuleSObjectType>Account</matchRuleSObjectType>
        <matchingRule>Name_Match</matchingRule>
        <objectMapping xsi:nil="true"/>
    </duplicateRuleMatchRules>
    <isActive>true</isActive>
    <masterLabel>Account Name Duplicate</masterLabel>
    <sortOrder>1</sortOrder>
</DuplicateRule>
""")
    result = extract_duplicate_rule(dup)
    _assert_no_dangling_edges(result)
    node = next(n for n in result["nodes"] if n["file_type"] == "duplicate_rule")
    assert node["sf_qualified_name"] == "Account.Name_Duplicate"
    assert node["label"] == "Account Name Duplicate"
    assert node["sf_active"] is True
    assert node["sf_action_on_update"] == "Block"
    uses = next(e for e in result["edges"] if e["relation"] == "uses_matching_rule")
    stub = next(n for n in result["nodes"] if n["id"] == uses["target"])
    assert stub["file_type"] == "matching_rule" and stub["sf_stub"] is True
    assert stub["sf_qualified_name"] == "Account.Name_Match"
    assert _field_refs_by(result) == {("Account", "BusinessUnit__c", "reads_field")}

    match = _md_file(tmp_path, "matchingRules/Account.matchingRule-meta.xml", """
<MatchingRules xmlns="http://soap.sforce.com/2006/04/metadata">
    <matchingRules>
        <fullName>Name_Match</fullName>
        <label>Name Match</label>
        <matchingRuleItems>
            <blankValueBehavior>NullNotAllowed</blankValueBehavior>
            <fieldName>Name</fieldName>
            <matchingMethod>CompanyName</matchingMethod>
        </matchingRuleItems>
        <ruleStatus>Active</ruleStatus>
    </matchingRules>
</MatchingRules>
""")
    m_result = extract_matching_rules(match)
    _assert_no_dangling_edges(m_result)
    m_node = next(n for n in m_result["nodes"] if n["file_type"] == "matching_rule")
    assert m_node["id"] == stub["id"]
    assert m_node["sf_active"] is True and not m_node.get("sf_stub")
    assert _field_refs_by(m_result) == {("Account", "Name", "reads_field")}


def test_auth_provider_parser_keeps_no_secrets(tmp_path: Path) -> None:
    path = _md_file(tmp_path, "authproviders/PartnerIdP.authprovider-meta.xml", """
<AuthProvider xmlns="http://soap.sforce.com/2006/04/metadata">
    <consumerKey>key-123</consumerKey>
    <consumerSecret>secret-456</consumerSecret>
    <friendlyName>Partner IdP</friendlyName>
    <providerType>OpenIdConnect</providerType>
    <registrationHandler>PartnerRegHandler</registrationHandler>
    <tokenUrl>https://idp.example.com/token</tokenUrl>
</AuthProvider>
""")
    result = extract_auth_provider(path)
    _assert_no_dangling_edges(result)
    node = next(n for n in result["nodes"] if n["file_type"] == "auth_provider")
    assert node["sf_qualified_name"] == "PartnerIdP"
    assert node["label"] == "Partner IdP"
    assert node["sf_provider_type"] == "OpenIdConnect"
    text = json.dumps(result)
    assert "secret-456" not in text and "key-123" not in text
    handler = next(e for e in result["edges"] if e["relation"] == "apex_handler")
    assert handler["target"] == apex_nid("PartnerRegHandler")


def test_layout_parser(tmp_path: Path) -> None:
    path = _md_file(tmp_path, "layouts/Account-%28X%29 Account Layout.layout-meta.xml", """
<Layout xmlns="http://soap.sforce.com/2006/04/metadata">
    <layoutSections>
        <layoutColumns>
            <layoutItems>
                <behavior>Required</behavior>
                <field>Name</field>
            </layoutItems>
            <layoutItems>
                <behavior>Edit</behavior>
                <field>Region__c</field>
            </layoutItems>
            <layoutItems>
                <emptySpace>true</emptySpace>
            </layoutItems>
        </layoutColumns>
    </layoutSections>
    <relatedLists>
        <fields>CONTACT.EMAIL</fields>
        <relatedList>RelatedContactList</relatedList>
    </relatedLists>
</Layout>
""")
    result = extract_layout(path)
    _assert_no_dangling_edges(result)
    node = next(n for n in result["nodes"] if n["file_type"] == "layout")
    assert node["sf_qualified_name"] == "Account-(X) Account Layout"
    assert node["sf_object"] == "Account"
    layout_for = next(e for e in result["edges"] if e["relation"] == "layout_for")
    assert layout_for["target"] == sobject_nid("Account")
    refs = {(r["path"], r["sf_behavior"]) for r in result["field_refs"]}
    assert refs == {("Name", "Required"), ("Region__c", "Edit")}
    assert {r["relation"] for r in result["field_refs"]} == {"places_field"}


def test_permission_set_group_parser(tmp_path: Path) -> None:
    """*.permissionsetgroup-meta.xml -> PSG node + contains_permission_set edges."""
    psg = tmp_path / "Sales_PSG.permissionsetgroup-meta.xml"
    psg.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<PermissionSetGroup xmlns="http://soap.sforce.com/2006/04/metadata">\n'
        "  <label>Sales PSG</label>\n"
        "  <permissionSets>CPQ_User</permissionSets>\n"
        "  <permissionSets>Quote_Editor</permissionSets>\n"
        "</PermissionSetGroup>\n", encoding="utf-8")
    result = extract_permission_set_group(psg)
    _assert_no_dangling_edges(result)
    psg_node = next(n for n in result["nodes"] if n["file_type"] == "permission_set_group")
    members = {e["target"] for e in result["edges"]
              if e["relation"] == "contains_permission_set"}
    # Resolves to the same permission_set_<name> ID profiles.py emits.
    assert members == {"permission_set_cpq_user", "permission_set_quote_editor"}
    assert all(e["source"] == psg_node["id"] for e in result["edges"])


def test_workflow_parser(tmp_path: Path) -> None:
    """workflows/<Object>.workflow-meta.xml fieldUpdates -> dml_operates_on UPDATE."""
    wf = tmp_path / "workflows" / "Opportunity.workflow-meta.xml"
    wf.parent.mkdir(parents=True)
    wf.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<Workflow xmlns="http://soap.sforce.com/2006/04/metadata">\n'
        "  <fieldUpdates><fullName>Set_Stage</fullName><field>StageName</field></fieldUpdates>\n"
        "</Workflow>\n", encoding="utf-8")
    result = extract_workflow(wf)
    _assert_no_dangling_edges(result)
    dml = next(e for e in result["edges"] if e["relation"] == "dml_operates_on")
    assert dml["target"] == sobject_nid("Opportunity")
    assert dml["sf_dml_type"] == "UPDATE"
    assert dml["sf_automation"] == "workflow"


def test_custom_metadata_record_parser() -> None:
    """customMetadata/<Type>.<Record>.md-meta.xml -> cmt_record node + cmt_record_of edge.

    The <values> field/value pairs are kept as sf_values — this is the config DATA
    that drives, e.g., the Opportunity->Quote field mapping (North Star).
    """
    result = extract_custom_metadata_record(
        FIXTURES / "sf_OppToQuoteMapping.Default.md-meta.xml")
    _assert_no_dangling_edges(result)
    node = next(n for n in result["nodes"] if n["file_type"] == "cmt_record")
    assert node["sf_mdt_type"] == "sf_OppToQuoteMapping__mdt"
    assert node["sf_record_name"] == "Default"
    # Field/value pairs captured as config data.
    assert node["sf_values"]["Source_Field__c"] == "Opportunity.Amount"
    assert node["sf_values"]["Target_Field__c"] == "SBQQ__Quote__c.SBQQ__NetAmount__c"
    edge = next(e for e in result["edges"] if e["relation"] == "cmt_record_of")
    assert edge["source"] == node["id"]
    assert edge["target"] == sobject_nid("sf_OppToQuoteMapping__mdt")


def test_sharing_rules_parser() -> None:
    """<Object>.sharingRules-meta.xml -> sharing_rule node + shares edge per rule."""
    result = extract_sharing_rules(FIXTURES / "sf_Account.sharingRules-meta.xml")
    _assert_no_dangling_edges(result)
    rules = {n["label"]: n for n in result["nodes"] if n["file_type"] == "sharing_rule"}
    # Both owner and criteria rules are captured.
    assert "Account Share to Sales" in rules
    assert "High Value Accounts" in rules
    owner = rules["Account Share to Sales"]
    assert owner["sf_access_level"] == "Edit"
    assert owner["sf_shared_to"] == "Sales_Team"
    assert owner["sf_rule_type"] == "sharingOwnerRules"
    # Every rule shares to the (filename-derived) SObject.
    targets = {e["target"] for e in result["edges"] if e["relation"] == "shares"}
    assert targets == {sobject_nid("sf_Account")}


def test_custom_labels_parser() -> None:
    """*.labels-meta.xml -> one custom_label node per <labels> (no edges)."""
    result = extract_custom_labels(FIXTURES / "sf_CustomLabels.labels-meta.xml")
    assert result["edges"] == []  # reference targets only, until $Label resolution
    labels = {n["id"]: n for n in result["nodes"]}
    assert "label_quote_error_message" in labels
    err = labels["label_quote_error_message"]
    assert err["file_type"] == "custom_label"
    assert err["sf_categories"] == "CPQ"
    assert err["sf_protected"] is True
    assert err["sf_value"].startswith("Quote cannot be created")


def test_mdt_mapping_pass_separated_form() -> None:
    """Real-org Main/Second __mdt record -> directed maps_to field edge (Opp->Quote)."""
    from graphify.salesforce.mdt_mapping import mdt_mapping_pass

    record = {
        "id": "cmt_opportunity_to_quote_mapping_rdd", "label": "RDD",
        "file_type": "cmt_record", "source_file": "customMetadata/x.md-meta.xml",
        "sf_mdt_type": "Opportunity_To_Quote_Mapping__mdt",
        "sf_values": {
            "Main_Object__c": "Opportunity",
            "Main_Object_Api_Field__c": "RequestedDeliveryDate__c",
            "Second_Object__c": "SBQQ__Quote__c",
            "Second_Object_Api_Field__c": "Requested_Delivery_Date__c",
        },
    }
    nodes = [record]
    edges: list[dict] = []
    new = mdt_mapping_pass(nodes, edges)
    assert len(new) == 1
    edge = new[0]
    # Direction: Main (source) -> Second (target).
    assert edge["source"] == field_nid("Opportunity", "RequestedDeliveryDate__c")
    assert edge["target"] == field_nid("SBQQ__Quote__c", "Requested_Delivery_Date__c")
    assert edge["relation"] == "maps_to"
    assert edge["confidence"] == "INFERRED"
    assert edge["sf_source_object"] == "Opportunity"
    assert edge["sf_target_object"] == "SBQQ__Quote__c"
    assert edge["sf_via"] == record["id"]
    # Field stub nodes added for both endpoints -> no dangling edge.
    ids = {n["id"] for n in nodes}
    assert edge["source"] in ids and edge["target"] in ids


def test_mdt_mapping_pass_dotted_form() -> None:
    """Dotted Object.Field values with source/target key hints -> directed edge."""
    from graphify.salesforce.metadata import extract_custom_metadata_record
    from graphify.salesforce.mdt_mapping import mdt_mapping_pass

    parsed = extract_custom_metadata_record(
        FIXTURES / "sf_OppToQuoteMapping.Default.md-meta.xml")
    nodes = list(parsed["nodes"])
    edges = list(parsed["edges"])
    new = mdt_mapping_pass(nodes, edges)
    maps = [e for e in new if e["relation"] == "maps_to"]
    assert len(maps) == 1
    assert maps[0]["source"] == field_nid("Opportunity", "Amount")
    assert maps[0]["target"] == field_nid("SBQQ__Quote__c", "SBQQ__NetAmount__c")
    assert maps[0]["confidence"] == "INFERRED"


def test_custom_setting_enrichment() -> None:
    """A CustomObject with <customSettingsType> is tagged as a Custom Setting."""
    from graphify.salesforce.objects import extract_custom_object

    result = extract_custom_object(FIXTURES / "sf_AppConfig__c.object-meta.xml")
    sobj = next(n for n in result["nodes"] if n["file_type"] == "sobject")
    assert sobj["sf_is_custom_setting"] is True
    assert sobj["sf_setting_type"] == "List"


def test_objects_parser_xml_parse_error(tmp_path: Path) -> None:
    """Malformed XML degrades gracefully to a single concept error node."""
    bad = tmp_path / "Broken.object-meta.xml"
    bad.write_text("<CustomObject><label>Broken</CustomObject>")  # mismatched tag

    result = extract_custom_object(bad)

    assert result["edges"] == []
    assert len(result["nodes"]) == 1
    err = result["nodes"][0]
    assert err["file_type"] == "concept"
    assert err["sf_error_type"] == "xml_parse_error"


# ---------------------------------------------------------------------------
# Neo4j export (Cypher generation + live driver push)
# ---------------------------------------------------------------------------


def _sf_neo4j_graph() -> nx.DiGraph:
    """A small SF graph exercising every node type and relation mapping."""
    account_id = sobject_nid("Account")
    quote_id = sobject_nid("SBQQ__Quote__c")
    G = nx.DiGraph()
    G.add_node(account_id, label="Account", file_type="sobject",
               source_file="objects/Account.object-meta.xml")
    G.add_node(quote_id, label="SBQQ__Quote__c", file_type="cpq_rule",
               source_file="objects/SBQQ__Quote__c.object-meta.xml")
    G.add_node("apex_accountservice", label="AccountService", file_type="code",
               source_file="classes/AccountService.cls")
    G.add_node("flow_accountflow", label="AccountFlow", file_type="flow",
               source_file="flows/AccountFlow.flow-meta.xml")
    G.add_node("lwc_accountcard", label="accountCard", file_type="lwc_component",
               source_file="lwc/accountCard")
    G.add_node("profile_admin", label="Admin", file_type="profile",
               source_file="profiles/Admin.profile-meta.xml")
    G.add_node("gov_limit_soql_in_loop", label="SOQL in loop", file_type="concept")

    G.add_edge("apex_accountservice", account_id, relation="queries",
               confidence="EXTRACTED", sf_in_loop=True, source_location="L42")
    G.add_edge("flow_accountflow", "apex_accountservice", relation="flow_invokes",
               confidence="EXTRACTED")
    G.add_edge("lwc_accountcard", "apex_accountservice", relation="wire_to",
               confidence="EXTRACTED")
    G.add_edge("profile_admin", account_id, relation="grants_access_to",
               confidence="EXTRACTED")
    G.add_edge("apex_accountservice", quote_id, relation="cpq_applies_to",
               confidence="INFERRED", execution_order=4)
    G.add_edge("apex_accountservice", "gov_limit_soql_in_loop",
               relation="governor_violation", confidence="EXTRACTED",
               sf_violation_type="soql_in_loop", sf_severity="HIGH")
    # A second edge between the same pair would collapse in a DiGraph, so the
    # trigger relation is carried by a dedicated SObject-less trigger node.
    G.add_node("trigger_accounttrigger", label="AccountTrigger", file_type="code",
               source_file="triggers/AccountTrigger.trigger")
    G.add_edge("trigger_accounttrigger", account_id, relation="triggers_on",
               confidence="EXTRACTED")
    return G


def test_neo4j_export(tmp_path: Path) -> None:
    """to_cypher_sf writes Neo4j-import-ready MERGE statements for SF graphs."""
    G = _sf_neo4j_graph()
    out = tmp_path / "graph_sf.cypher"

    to_cypher_sf(G, str(out))

    # 1. Cypher file is created and non-empty.
    assert out.exists()
    text = out.read_text(encoding="utf-8")
    assert text.strip()

    statements = [s for s in text.split(";") if s.strip()]
    node_stmts = [s for s in statements if "MERGE (n:" in s]
    rel_stmts = [s for s in statements if "MERGE (a)" in s]

    # 2. Every node yields a MERGE statement with the SF-aware Neo4j label.
    assert len(node_stmts) == G.number_of_nodes()
    assert ":SObject " in text       # sobject -> SObject
    assert ":ApexClass " in text     # code -> ApexClass
    assert ":Flow " in text          # flow -> Flow
    assert ":LWCComponent " in text  # lwc_component -> LWCComponent
    assert ":CPQRule " in text       # cpq_rule -> CPQRule
    assert ":Profile " in text       # profile -> Profile
    assert ":Concept " in text       # concept -> Concept

    # 3. Every edge yields a relationship MERGE with the SF-aware Neo4j type.
    assert len(rel_stmts) == G.number_of_edges()
    for neo_type in ("TRIGGERS_ON", "QUERIES", "FLOW_INVOKES", "WIRE_TO",
                     "GRANTS_ACCESS_TO", "CPQ_APPLIES_TO", "GOVERNOR_VIOLATION"):
        assert f":{neo_type} " in text or f":{neo_type}]" in text, neo_type

    # 4. Mapping tables cover the declared SF vocabulary.
    assert SF_NODE_TYPE_TO_NEO4J_LABEL["sobject"] == "SObject"
    assert SF_RELATION_TO_NEO4J_TYPE["triggers_on"] == "TRIGGERS_ON"

    # 5. Edge attributes are carried into the relationship.
    assert "execution_order" in text
    assert "sf_violation_type" in text


def test_neo4j_push_live(monkeypatch) -> None:
    """push_to_neo4j_sf upserts every node/edge via a (mocked) driver session."""
    import sys
    import types

    runs: list[str] = []

    class _FakeSession:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def run(self, query, **params):
            runs.append(query)

    class _FakeDriver:
        def __init__(self):
            self.closed = False

        def session(self):
            return _FakeSession()

        def close(self):
            self.closed = True

    class _FakeGraphDatabase:
        @staticmethod
        def driver(uri, auth=None):
            return _FakeDriver()

    fake_neo4j = types.ModuleType("neo4j")
    fake_neo4j.GraphDatabase = _FakeGraphDatabase
    monkeypatch.setitem(sys.modules, "neo4j", fake_neo4j)

    G = _sf_neo4j_graph()
    result = push_to_neo4j_sf(G, "bolt://localhost:7687", "neo4j", "pw")

    assert result["success"] is True
    assert result["nodes_created"] == G.number_of_nodes()
    assert result["relationships_created"] == G.number_of_edges()
    # One MERGE per node + one per edge.
    assert len(runs) == G.number_of_nodes() + G.number_of_edges()
    # SF-aware labels reach the driver in node MERGE queries.
    assert any(":SObject" in q for q in runs)
    assert any(":CPQRule" in q for q in runs)
    # SF-aware relation types reach the driver in edge MERGE queries.
    assert any(":TRIGGERS_ON" in q for q in runs)


# ---------------------------------------------------------------------------
# Release sync (Phase 3, Step 1)
# ---------------------------------------------------------------------------


def test_release_sync(tmp_path, monkeypatch) -> None:
    """sync_release_notes writes a version file, detects staleness, dry-runs."""
    import graphify.salesforce.release_sync as rs

    # 1. Normal run writes a well-formed JSON version file.
    result = sync_release_notes(tmp_path)
    version_file = tmp_path / "sf_governor_limits_version.json"
    assert version_file.exists()

    data = json.loads(version_file.read_text(encoding="utf-8"))
    assert data["version"] == result["version"]
    assert isinstance(data["limits"], dict) and data["limits"]
    # last_synced is a valid ISO timestamp.
    datetime.fromisoformat(data["last_synced"])

    # Return contract.
    assert set(result) >= {"changed", "new_limits", "version", "days_stale", "status"}
    # Offline default mirrors hardcoded constants -> no drift.
    assert result["changed"] == 0
    assert result["status"] in {"FRESH", "WARNING", "ERROR"}

    # 2. Staleness is detected from the written file (FRESH right after write).
    staleness = check_staleness(version_file)
    assert staleness["days_stale"] == 0
    assert staleness["status"] == "FRESH"

    # Threshold mapping is correct at the WARNING / ERROR boundaries.
    assert rs._staleness_status(0) == "FRESH"
    assert rs._staleness_status(30) == "FRESH"
    assert rs._staleness_status(31) == "WARNING"
    assert rs._staleness_status(90) == "WARNING"
    assert rs._staleness_status(91) == "ERROR"

    # 3. --dry-run previews without writing a file.
    fresh_dir = tmp_path / "dry"
    dry = sync_release_notes(fresh_dir, dry_run=True)
    assert dry["dry_run"] is True
    assert not (fresh_dir / "sf_governor_limits_version.json").exists()

    # 4. A drift in the fetched limits is counted as a change (mock backend).
    monkeypatch.setattr(
        rs, "_fetch_release_limits", lambda: {"soql_queries_per_transaction": 200}
    )
    changed = sync_release_notes(tmp_path / "changed")
    assert changed["changed"] >= 1


# ---------------------------------------------------------------------------
# Integration: extract_sf() E2E + backwards compatibility (Phase 3, Step 2)
# ---------------------------------------------------------------------------

SAMPLE_ORG = FIXTURES / "sf_full_org_sample" / "force-app" / "main" / "default"


class TestExtractSF:
    """E2E integration tests for the ``extract_sf`` pipeline wrapper."""

    def test_full_org_sample(self) -> None:
        """``extract_sf`` parses a complete sample org and runs every pass.

        Sample org (tests/fixtures/sf_full_org_sample/force-app/main/default):
            - classes/   5 Apex files (incl. a QCP plugin + triggers)
            - flows/     3 Flow files
            - objects/   2 Custom Object files
            - lwc/       1 LWC component pair (html + js)
            - profiles/  1 Profile (parsed with include_permissions=True)
        """
        result = extract_sf(SAMPLE_ORG, include_permissions=True)

        # 1. No top-level error.
        assert "error" not in result

        nodes = result["nodes"]
        edges = result["edges"]

        # 2. All expected node types are present.
        file_types = {n["file_type"] for n in nodes}
        expected_types = {"code", "sobject", "flow", "lwc_component", "profile"}
        assert expected_types.issubset(file_types), file_types

        # 3. Cross-file resolution: every parser that touches Account converges
        #    on the single ``sobject_nid("Account")`` node (ADR-002).
        account_nodes = [n for n in nodes if n.get("label") == "Account"]
        assert len(account_nodes) == 1
        assert account_nodes[0]["id"] == sobject_nid("Account")
        assert account_nodes[0]["file_type"] == "sobject"

        # 4. No dangling edges — every endpoint resolves to a real node.
        node_ids = {n["id"] for n in nodes}
        for edge in edges:
            assert edge["source"] in node_ids, f"dangling source: {edge}"
            assert edge["target"] in node_ids, f"dangling target: {edge}"

        # 5. Analysis passes ran on the merged graph -------------------------

        # 5a. CPQ pass detected the QCP plugin and emitted callback nodes.
        qcp_methods = [n for n in nodes if n.get("file_type") == "cpq_qcp_method"]
        assert qcp_methods, "CPQ pass produced no QCP callback nodes"
        qcp_classes = {n.get("sf_qcp_class") for n in qcp_methods}
        assert any(
            nodes_by_id := [n for n in nodes if n["id"] in qcp_classes]
        )
        assert any(n.get("sf_qcp_implementation") for n in nodes_by_id)

        # 5b. LWC merge pass folded html + js into a single component node.
        lwc_nodes = [n for n in nodes if n.get("file_type") == "lwc_component"]
        assert len(lwc_nodes) == 1
        assert lwc_nodes[0].get("sf_has_template") is True
        # html sidecar node was removed by the merge.
        assert not any(n.get("sf_lwc_file_type") == "html" for n in nodes)

        # 5c. Cross-file LWC -> Apex resolution: @wire targets a real method.
        wire_edges = [e for e in edges if e["relation"] == "wire_to"]
        assert wire_edges
        assert all(e["target"] in node_ids for e in wire_edges)

        # 5d. Governor pass flagged the SOQL-in-loop in the trigger.
        gov_edges = [e for e in edges if e.get("relation") == "governor_violation"]
        assert gov_edges, "Governor pass produced no violation edges"
        assert all(e["target"] in node_ids for e in gov_edges)
        violation_types = {e.get("sf_violation_type") for e in gov_edges}
        assert "soql_in_loop" in violation_types

    def test_single_file_path(self) -> None:
        """``extract_sf`` also accepts a single metadata file (not just a dir)."""
        result = extract_sf(SAMPLE_ORG / "objects" / "Account.object-meta.xml")
        assert "error" not in result
        node_ids = {n["id"] for n in result["nodes"]}
        assert sobject_nid("Account") in node_ids
        for edge in result["edges"]:
            assert edge["source"] in node_ids
            assert edge["target"] in node_ids

    def test_lenient_skips_unparseable_file(self, tmp_path) -> None:
        """A malformed metadata file is skipped, not fatal (ADR-009 lenient)."""
        good = tmp_path / "Account.object-meta.xml"
        good.write_text(
            (SAMPLE_ORG / "objects" / "Account.object-meta.xml").read_text(
                encoding="utf-8"
            ),
            encoding="utf-8",
        )
        # The flow parser will see broken XML; the run must still succeed.
        bad = tmp_path / "Broken.flow-meta.xml"
        bad.write_text("<Flow><unclosed></Flow>", encoding="utf-8")

        result = extract_sf(tmp_path)
        assert "error" not in result
        node_ids = {n["id"] for n in result["nodes"]}
        assert sobject_nid("Account") in node_ids


    def test_permissions_are_opt_in(self) -> None:
        """Profiles / Permission Sets are skipped unless include_permissions=True."""
        default = extract_sf(SAMPLE_ORG)
        assert not any(n["file_type"] == "profile" for n in default["nodes"])
        assert not any(e["relation"] == "grants_access_to" for e in default["edges"])
        opted_in = extract_sf(SAMPLE_ORG, include_permissions=True)
        assert any(e["relation"] == "grants_access_to" for e in opted_in["edges"])

    def test_source_files_are_repo_relative(self) -> None:
        result = extract_sf(SAMPLE_ORG)
        files = {n["source_file"] for n in result["nodes"]} | {
            e["source_file"] for e in result["edges"] if "source_file" in e}
        assert "classes/AccountService.cls" in files
        assert not any(f.startswith("/") for f in files if f)

    def test_written_graph_is_compact_with_clean_summary(self, tmp_path) -> None:
        """graph.json is unindented; summary.json reports zero integrity defects."""
        from graphify.salesforce.pipeline import write_sf_summary
        from graphify.salesforce.quality import integrity_errors

        G = build_sf_graph(extract_sf(SAMPLE_ORG, include_permissions=True))
        text = write_sf_graph(G, tmp_path / "graph.json").read_text(encoding="utf-8")
        assert "\n" not in text and ": " not in text[:200]
        summary = write_sf_summary(G, tmp_path / "summary.json")
        assert json.loads((tmp_path / "summary.json").read_text()) == summary
        assert summary["nodes"] == G.number_of_nodes()
        assert summary["nodes_by_type"]["sobject"] >= 2
        assert integrity_errors(summary) == []


    def test_validate_sf_graph_gate(self) -> None:
        """A clean extraction validates; each ontology-integrity defect is reported."""
        from graphify.salesforce.validate_sf import validate_sf_graph

        G = build_sf_graph(extract_sf(SAMPLE_ORG, include_permissions=True))
        assert validate_sf_graph(G) == []

        G.add_node("apex_leak", label="for", file_type="code", sf_code_type="class",
                   source_file="/Users/x/classes/Leak.cls", source="public class Leak {}")
        G.add_node(field_nid("Account", "Dup__c"), label="Account.Dup__c", file_type="field")
        G.add_edge(field_nid("Account", "Dup__c"), sobject_nid("Account"),
                   key="field_of", relation="field_of")
        G.add_edge(field_nid("Account", "Dup__c"), sobject_nid("Opportunity"),
                   key="field_of", relation="field_of")
        errors = " ".join(validate_sf_graph(G))
        for key in ("absolute_source_files", "nodes_with_source_text",
                    "fields_with_multiple_objects", "apex_label_mismatches",
                    "nodes_missing_qualified_name"):
            assert key in errors, key


class TestBackwardsCompatibility:
    """Existing language support must keep working alongside the SF parsers."""

    def test_existing_apex_dispatch_present(self) -> None:
        """The core ``.cls`` dispatch entry still exists (no regression)."""
        from graphify.extract import _DISPATCH

        assert ".cls" in _DISPATCH
        assert ".trigger" in _DISPATCH

    def test_register_patches_sf_parsers(self) -> None:
        """``register()`` wires the SF metadata suffixes into ``_DISPATCH``."""
        import graphify.salesforce as sf
        from graphify.extract import _DISPATCH

        sf.register()
        for suffix in (".flow-meta.xml", ".object-meta.xml", ".profile-meta.xml"):
            assert suffix in _DISPATCH

    def test_languages_test_suite(self) -> None:
        """Run the existing language test suite to verify no regression."""
        import subprocess
        import sys

        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "tests/test_languages.py", "-q"],
            capture_output=True,
            cwd=str(Path(__file__).parent.parent),
        )
        assert proc.returncode == 0, proc.stdout.decode() + proc.stderr.decode()


# ---------------------------------------------------------------------------
# Named references, inheritance, Quick Actions, email templates, resources
# ---------------------------------------------------------------------------

def _write(root: Path, rel: str, body: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


def _reference_repo(root: Path) -> Path:
    """A small repo exercising every named-reference shape."""
    _md_file(root, "labels/CustomLabels.labels-meta.xml", """
<CustomLabels xmlns="http://soap.sforce.com/2006/04/metadata">
    <labels><fullName>Greeting</fullName><value>Hi</value></labels>
    <labels><fullName>ErrorMsg</fullName><value>Oops</value></labels>
</CustomLabels>
""")
    _md_file(root, "staticresources/Logo.resource-meta.xml", """
<StaticResource xmlns="http://soap.sforce.com/2006/04/metadata">
    <cacheControl>Public</cacheControl><contentType>image/png</contentType>
</StaticResource>
""")
    _md_file(root, "objects/AppConfig__c/AppConfig__c.object-meta.xml", """
<CustomObject xmlns="http://soap.sforce.com/2006/04/metadata">
    <customSettingsType>Hierarchy</customSettingsType>
    <fields><fullName>Limit__c</fullName><type>Number</type></fields>
</CustomObject>
""")
    _md_file(root, "objects/Account/Account.object-meta.xml", """
<CustomObject xmlns="http://soap.sforce.com/2006/04/metadata">
    <fields><fullName>Region__c</fullName><type>Text</type></fields>
    <fields>
        <fullName>Banner__c</fullName><type>Text</type>
        <formula>$Label.Greeting &amp; Region__c &amp; TEXT($Setup.AppConfig__c.Limit__c)</formula>
    </fields>
</CustomObject>
""")
    _write(root, "classes/BaseHandler.cls",
           "public virtual class BaseHandler implements IHandler { public virtual void run() {} }\n")
    _write(root, "classes/IHandler.cls", "public interface IHandler { void run(); }\n")
    _write(root, "classes/AccountHandler.cls",
           "public class AccountHandler extends BaseHandler implements Queueable {\n"
           "    public void execute(QueueableContext ctx) {}\n"
           "    public override void run() {\n"
           "        String a = System.Label.Greeting;\n"
           "        String b = Label.Missing_Label;\n"
           "        Decimal lim = AppConfig__c.getOrgDefaults().Limit__c;\n"
           "        String c = label.Name;\n"
           "    }\n"
           "}\n")
    _md_file(root, "flows/Parent.flow-meta.xml", """
<Flow xmlns="http://soap.sforce.com/2006/04/metadata">
    <processType>AutoLaunchedFlow</processType>
    <subflows><name>Call_Child</name><flowName>Child</flowName></subflows>
    <textTemplates><name>Msg</name><text>{!$Label.ErrorMsg} {!$Setup.AppConfig__c.Limit__c}</text></textTemplates>
</Flow>
""")
    _md_file(root, "flows/Child.flow-meta.xml", """
<Flow xmlns="http://soap.sforce.com/2006/04/metadata">
    <processType>AutoLaunchedFlow</processType>
</Flow>
""")
    _write(root, "lwc/accountCard/accountCard.js",
           "import { LightningElement } from 'lwc';\n"
           "import REGION from '@salesforce/schema/Account.Region__c';\n"
           "import OWNER_NAME from '@salesforce/schema/Account.Owner.Name';\n"
           "import ACCOUNT from '@salesforce/schema/Account';\n"
           "import greeting from '@salesforce/label/c.Greeting';\n"
           "import logo from '@salesforce/resourceUrl/Logo';\n"
           "import { format } from 'c/utils';\n"
           "// import ghost from 'c/ghost';\n"
           "/* import OLD from '@salesforce/apex/Old.run'; */\n"
           "export default class AccountCard extends LightningElement {}\n")
    _write(root, "lwc/accountCard/accountCard.html",
           "<template>\n  <!-- <c-old-widget></c-old-widget> -->\n"
           "  <c-region-badge region={region}></c-region-badge>\n</template>\n")
    _write(root, "lwc/regionBadge/regionBadge.js",
           "import { LightningElement } from 'lwc';\n"
           "export default class RegionBadge extends LightningElement {}\n")
    _write(root, "lwc/utils/utils.js", "export function format(v) { return v; }\n")
    _write(root, "aura/LegacyPanel/LegacyPanel.cmp",
           '<aura:component controller="AccountHandler">\n'
           '  <img src="{!$Resource.Logo}"/> {!$Label.c.Greeting}\n'
           '  <c:accountCard/>\n</aura:component>\n')
    _write(root, "aura/LegacyPanel/LegacyPanelController.js",
           "({ init: function(component) { var a = component.get('c.loadRows'); } })\n")
    _md_file(root, "quickActions/Account.Deactivate.quickAction-meta.xml", """
<QuickAction xmlns="http://soap.sforce.com/2006/04/metadata">
    <fieldOverrides><field>Region__c</field><literalValue>None</literalValue></fieldOverrides>
    <label>Deactivate</label>
    <quickActionLayout><quickActionLayoutColumns><quickActionLayoutItems>
        <emptySpace>false</emptySpace><field>Name</field><uiBehavior>Edit</uiBehavior>
    </quickActionLayoutItems></quickActionLayoutColumns></quickActionLayout>
    <type>Update</type>
</QuickAction>
""")
    _md_file(root, "quickActions/Account.Wizard.quickAction-meta.xml", """
<QuickAction xmlns="http://soap.sforce.com/2006/04/metadata">
    <lightningWebComponent>accountCard</lightningWebComponent>
    <type>LightningWebComponent</type>
</QuickAction>
""")
    _md_file(root, "quickActions/NewTask.quickAction-meta.xml", """
<QuickAction xmlns="http://soap.sforce.com/2006/04/metadata">
    <targetObject>Task</targetObject>
    <type>Create</type>
</QuickAction>
""")
    _md_file(root, "quickActions/Account.RunChild.quickAction-meta.xml", """
<QuickAction xmlns="http://soap.sforce.com/2006/04/metadata">
    <flowDefinition>Child</flowDefinition>
    <type>Flow</type>
</QuickAction>
""")
    _md_file(root, "email/Sales/Welcome.email-meta.xml", """
<EmailTemplate xmlns="http://soap.sforce.com/2006/04/metadata">
    <name>Welcome</name>
    <subject>Hi {!Account.Name}</subject>
    <type>text</type>
</EmailTemplate>
""")
    _write(root, "email/Sales/Welcome.email",
           "Region: {!Account.Region__c} {!Receiving_User.Name} {!$Label.Greeting}\n")
    _md_file(root, "email/Sales/Vf.email-meta.xml", """
<EmailTemplate xmlns="http://soap.sforce.com/2006/04/metadata">
    <name>Vf</name><type>visualforce</type>
</EmailTemplate>
""")
    _write(root, "email/Sales/Vf.email",
           '<messaging:emailTemplate relatedToType="Account" subject="x">'
           "{!relatedTo.Region__c}</messaging:emailTemplate>\n")
    _md_file(root, "email/Sales/Lex.email-meta.xml", """
<EmailTemplate xmlns="http://soap.sforce.com/2006/04/metadata">
    <name>Lex</name><relatedEntityType>Account</relatedEntityType>
    <subject>{{{Account.Region__c}}}</subject><type>custom</type>
</EmailTemplate>
""")
    _md_file(root, "workflows/Account.workflow-meta.xml", """
<Workflow xmlns="http://soap.sforce.com/2006/04/metadata">
    <alerts><fullName>Notify</fullName><template>Sales/Welcome</template></alerts>
</Workflow>
""")
    return root


def _edge_set(result: dict, relation: str) -> set[tuple[str, str]]:
    return {(e["source"], e["target"]) for e in result["edges"] if e["relation"] == relation}


def test_named_references_end_to_end(tmp_path: Path) -> None:
    """Labels, resources, components, subflows, settings, inheritance and the new
    metadata types resolve across files with no dangling edges or integrity errors."""
    from graphify.salesforce.references import label_nid, resource_nid

    result = extract_sf(_reference_repo(tmp_path))
    _assert_no_dangling_edges(result)
    nodes = {n["id"]: n for n in result["nodes"]}

    handler, base, iface = apex_nid("AccountHandler"), apex_nid("BaseHandler"), apex_nid("IHandler")
    card, badge, utils = "lwc_accountcard", "lwc_regionbadge", "lwc_utils"
    greeting, error_msg = label_nid("Greeting"), label_nid("ErrorMsg")

    # Labels: Apex (strict — the undefined label and ``label.Name`` are dropped),
    # Flow, formula, LWC, Aura, email.
    labels = _edge_set(result, "uses_label")
    assert (handler, greeting) in labels
    assert not any(t in (label_nid("Missing_Label"), label_nid("Name")) for _, t in labels)
    assert label_nid("Missing_Label") not in nodes
    assert ("flow_parent", error_msg) in labels
    assert (field_nid("Account", "Banner__c"), greeting) in labels
    assert (card, greeting) in labels
    assert ("aura_legacypanel", greeting) in labels
    assert (metadata_nid("email_template", "Sales", "Welcome"), greeting) in labels
    assert not nodes[greeting].get("sf_stub")

    # Static resources and components.
    assert _edge_set(result, "uses_resource") == {
        (card, resource_nid("Logo")), ("aura_legacypanel", resource_nid("Logo"))}
    assert nodes[resource_nid("Logo")]["sf_content_type"] == "image/png"
    assert _edge_set(result, "uses_component") == {
        (card, utils), (card, badge), ("aura_legacypanel", card)}
    assert "lwc_oldwidget" not in nodes and "lwc_ghost" not in nodes
    assert apex_method_nid("Old", "run") not in nodes

    # Aura -> Apex controller method.
    assert ("aura_legacypanel", apex_method_nid("AccountHandler", "loadRows")) in \
        _edge_set(result, "aura_calls")

    # Flow subflow; Custom Setting reads from Apex, Flow and formula.
    assert _edge_set(result, "invokes_subflow") == {("flow_parent", "flow_child")}
    assert not nodes["flow_child"].get("sf_stub")
    assert (handler, sobject_nid("AppConfig__c")) in _edge_set(result, "reads_setting")
    limit = field_nid("AppConfig__c", "Limit__c")
    reads = _edge_set(result, "reads_field")
    assert {(handler, limit), ("flow_parent", limit),
            (field_nid("Account", "Banner__c"), limit)} <= reads

    # LWC schema imports: a field path (also through a relationship), not the object.
    assert (card, field_nid("Account", "Region__c")) in reads
    assert (card, field_nid("User", "Name")) in reads

    # Inheritance between the repo's own types; platform interfaces are not linked.
    assert _edge_set(result, "extends") == {(handler, base)}
    assert (base, iface) in _edge_set(result, "implements")

    # Quick Actions.
    deactivate = metadata_nid("quick_action", "Account.Deactivate")
    assert (deactivate, sobject_nid("Account")) in _edge_set(result, "action_for")
    assert (deactivate, field_nid("Account", "Region__c")) in _edge_set(result, "writes_field")
    assert (deactivate, field_nid("Account", "Name")) in _edge_set(result, "places_field")
    dml = {(e["source"], e["target"], e["sf_dml_type"]) for e in result["edges"]
           if e["relation"] == "dml_operates_on"}
    assert (deactivate, sobject_nid("Account"), "UPDATE") in dml
    assert (metadata_nid("quick_action", "NewTask"), sobject_nid("Task"), "INSERT") in dml
    launches = _edge_set(result, "launches")
    assert (metadata_nid("quick_action", "Account.Wizard"), card) in launches
    assert (metadata_nid("quick_action", "Account.RunChild"), "flow_child") in launches

    # Email templates: merge fields on known SObjects only; VF / Lightning forms.
    welcome = metadata_nid("email_template", "Sales", "Welcome")
    assert nodes[welcome]["sf_qualified_name"] == "Sales/Welcome"
    assert {(welcome, field_nid("Account", "Name")),
            (welcome, field_nid("Account", "Region__c")),
            (metadata_nid("email_template", "Sales", "Vf"), field_nid("Account", "Region__c")),
            (metadata_nid("email_template", "Sales", "Lex"), field_nid("Account", "Region__c")),
            } <= reads
    assert not any("receiving_user" in t for _, t in reads)
    assert (metadata_nid("email_template", "Sales", "Lex"), sobject_nid("Account")) in \
        _edge_set(result, "template_for")
    assert ("workflow_account", welcome) in _edge_set(result, "uses_template")
    assert not nodes[welcome].get("sf_stub")

    G = build_sf_graph(result)
    assert validate_sf_graph(G) == []


def test_mdt_mapping_role_words_and_config_records() -> None:
    """camelCase role keys map; role-less config records read fields; role-less
    mapping-type records stay AMBIGUOUS maps_to."""
    from graphify.salesforce.mdt_mapping import mdt_mapping_pass

    def record(rid, mdt_type, values):
        return {"id": rid, "label": rid, "file_type": "cmt_record", "source_file": "x",
                "sf_mdt_type": mdt_type, "sf_values": values}

    quote = {"id": sobject_nid("Quote"), "label": "Quote", "file_type": "sobject",
             "source_file": "q", "sf_api_name": "Quote"}
    nodes = [
        quote,
        record("cmt_clone", "CreateDefaultValueSetting__mdt",
               {"SourceObject__c": "Opportunity", "SourceField__c": "Id",
                "TargetField__c": "Original__c"}),
        record("cmt_track", "ActivityTrackSource__mdt",
               {"ObjectApiName__c": "Account", "DateField__c": "LastModifiedDate",
                "NameField__c": "Name", "Label__c": "Account Tracking"}),
        record("cmt_sync", "SyncFieldsWithQuote__mdt",
               {"QuoteField__c": "AccountId", "VRBQuoteField__c": "Account__c"}),
    ]
    edges: list[dict] = []
    mdt_mapping_pass(nodes, edges)
    by_via = {}
    for e in edges:
        by_via.setdefault(e.get("sf_via") or e["source"], []).append(e)

    clone = by_via["cmt_clone"]
    assert [(e["source"], e["target"], e["confidence"]) for e in clone] == [
        (field_nid("Opportunity", "Id"), field_nid(None, "Original__c"), "INFERRED")]

    track = by_via["cmt_track"]
    assert {(e["relation"], e["target"]) for e in track} == {
        ("reads_field", field_nid("Account", "LastModifiedDate")),
        ("reads_field", field_nid("Account", "Name"))}

    sync = by_via["cmt_sync"]
    assert len(sync) == 1 and sync[0]["relation"] == "maps_to"
    assert sync[0]["confidence"] == "AMBIGUOUS"
    assert sync[0]["source"] == field_nid("Quote", "AccountId")


def test_sf_impact_follows_maps_to_against_arrow() -> None:
    """Upstream (what uses this) from a mapped source field reaches the target
    field and its readers; downstream from the reader does not leak back."""
    from graphify.salesforce.query import sf_impact

    G = nx.MultiDiGraph()
    src, dst = field_nid("Opportunity", "Amount"), field_nid("Quote", "Net__c")
    reader = apex_nid("QuoteService")
    for nid in (src, dst, reader):
        G.add_node(nid, label=nid, file_type="field", source_file="x")
    G.add_edge(src, dst, key="maps_to", relation="maps_to", confidence="INFERRED")
    G.add_edge(reader, dst, key="reads_field", relation="reads_field", confidence="EXTRACTED")

    up = sf_impact(G, src, direction="upstream", depth=2)
    assert set(up["nodes"]) == {src, dst, reader}

    down = sf_impact(G, reader, direction="downstream", depth=3)
    assert set(down["nodes"]) == {reader, dst, src}
    assert sf_impact(G, src, direction="downstream", depth=2)["nodes"] == [src]
