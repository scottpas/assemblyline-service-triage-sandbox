"""DNS mapping must survive real Assemblyline ODM construction and export."""

import json
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import Mock

import pytest
from assemblyline.odm.models.ontology.results.network import LOOKUP_TYPES, NetworkConnection
from assemblyline_service_utilities.common.dynamic_service_helper import OntologyResults
from assemblyline_v4_service.common.ontology_helper import OntologyHelper
from conftest import SAMPLE_ID, build_report
from test_service_integration import find_subsection

from triage_sandbox.report import DynamicReport
from triage_sandbox.service import _attach_dynamic_ontology


def dns_report(raw_type, **dns_overrides):
    report = build_report("behavioral1")
    dns = {
        "domains": ["query.example.com"],
        "questions": [{"name": "query.example.com", "type": raw_type}],
    }
    dns.update(dns_overrides)
    report["network"]["requests"] = [
        {
            "flow": 1,
            "dns_request": dns,
            "dns_response": {"ip": ["9.9.9.9"], "domains": ["answer.example.com"]},
        },
        {"flow": 2, "http_request": {"url": "http://example.com/", "method": "GET"}},
    ]
    return report


def export_connections(dr):
    logger = Mock()
    helper = OntologyHelper(logger, "TriageSandbox")
    service = SimpleNamespace(ontology=helper)
    _attach_dynamic_ontology(cast(Any, service), dr.ontology)
    logger.error.assert_not_called()
    exported = {"file": {}, "results": {}}
    helper.attach_parts(exported)
    assert len(exported["results"]["netflow"]) == len(dr.ontology.get_network_connections())
    return [obj.as_primitives() for obj in helper._result_parts.values() if isinstance(obj, NetworkConnection)]


@pytest.mark.parametrize("record_type", LOOKUP_TYPES)
@pytest.mark.parametrize("prefix", ["", "IN ", " ch\t"])
def test_dns_supported_types_export(record_type, prefix):
    raw = prefix + record_type.lower()
    report = dns_report(raw)
    dr = DynamicReport(ontology=OntologyResults(service_name="TriageSandbox"), task_id="behavioral1", **report)
    connections = export_connections(dr)
    assert len(connections) == 2
    dns = connections[0]["dns_details"]
    assert dns["lookup_type"] == record_type
    assert dns["domain"] == "query.example.com"
    assert dns["resolved_ips"] == ["9.9.9.9"]
    assert dns["resolved_domains"] == ["answer.example.com"]
    assert dr.dns_evidence == [report["network"]["requests"][0]]
    assert dr.diagnostics == []


@pytest.mark.parametrize("raw", ["ANY", "IN ANY", "IN", "", "  ", None, 1, [], {}, "bogus A", "IN A AAAA", "IN/A"])
def test_dns_unrepresentable_type_keeps_connection_and_evidence(raw):
    report = dns_report(raw)
    dr = DynamicReport(ontology=OntologyResults(service_name="TriageSandbox"), task_id="behavioral1", **report)
    connections = export_connections(dr)
    assert len(connections) == 2
    assert connections[0]["dns_details"] is None
    assert connections[0]["connection_type"] is None
    assert connections[0]["destination_ip"] == "8.8.8.8"
    assert connections[1]["connection_type"] == "http"
    assert dr.dns_evidence == [report["network"]["requests"][0]]
    assert len(dr.diagnostics) == 1
    assert "unsupported DNS question type" in dr.diagnostics[0]
    assert repr(raw) in dr.diagnostics[0]


@pytest.mark.parametrize("questions", [[], [{"name": "query.example.com"}]])
def test_dns_missing_type_does_not_fabricate_a(questions):
    report = dns_report("A", questions=questions)
    dr = DynamicReport(ontology=OntologyResults(service_name="TriageSandbox"), task_id="behavioral1", **report)
    assert export_connections(dr)[0]["dns_details"] is None
    assert dr.diagnostics


def test_dns_invalid_answer_is_diagnosed_without_losing_network():
    report = dns_report("IN A")
    report["network"]["requests"][0]["dns_response"]["ip"] = ["not-an-ip"]
    dr = DynamicReport(ontology=OntologyResults(service_name="TriageSandbox"), task_id="behavioral1", **report)
    connections = export_connections(dr)
    assert len(connections) == 2
    assert connections[0]["dns_details"] is None
    assert connections[1]["http_details"]["request_uri"] == "http://example.com/"
    assert "invalid DNS details" in dr.diagnostics[0]
    assert dr.dns_evidence[0]["dns_response"]["ip"] == ["not-an-ip"]


def test_dns_no_domain_keeps_raw_evidence_and_diagnostic():
    report = dns_report("A", domains=[], questions=[{"type": "A"}])
    dr = DynamicReport(ontology=OntologyResults(service_name="TriageSandbox"), task_id="behavioral1", **report)
    assert export_connections(dr)[0]["dns_details"] is None
    assert dr.dns_evidence == [report["network"]["requests"][0]]
    assert len(dr.diagnostics) == 1
    assert "missing DNS question domain" in dr.diagnostics[0]
    assert "Task behavioral1, flow 1" in dr.diagnostics[0]


@pytest.mark.parametrize("raw_type", ["IN A", "IN AAAA", "IN ANY", None])
def test_dns_evidence_visible_and_other_results_survive(
    triage_service, triage_client, requests_mock, make_request, raw_type
):
    report = dns_report(raw_type)
    # Mix supported and unsupported requests on one flow, including a repeated
    # request: normalization must preserve occurrences and answer associations.
    report["network"]["requests"].extend(
        [
            {"flow": 1, "dns_request": {"questions": [{"name": "second.example.com", "type": "IN TXT"}]}},
            report["network"]["requests"][0],
            {"dns_request": {"questions": [{"name": "unlinked.example.com", "type": "IN A"}]}},
        ]
    )
    requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/behavioral1/report_triage.json", json=report)
    request = make_request()
    triage_service.execute(request)
    sandbox = request.result.sections[0]
    task = find_subsection(sandbox, "Task: behavioral1")
    assert json.loads(find_subsection(task, "DNS evidence").body) == [
        r for r in report["network"]["requests"] if "dns_request" in r
    ]
    assert find_subsection(sandbox, "FABOOKIE") is not None
    assert find_subsection(sandbox, "VIDAR") is not None
    completeness = find_subsection(sandbox, "Analysis completeness")
    if raw_type in {"IN A", "IN AAAA"}:
        assert completeness is None
    else:
        assert "unsupported DNS question type" in completeness.body
    exported = {"file": {}, "results": {}}
    triage_service.ontology.attach_parts(exported)
    connections = exported["results"]["netflow"]
    first_task = [c for c in connections if c["objectid"]["session"].endswith("behavioral1")]
    assert len(first_task) == 4
    assert len({c["objectid"]["ontology_id"] for c in first_task}) == 4
    assert any(c.get("connection_type") == "http" for c in first_task)
    assert sum(c.get("dns_details", {}).get("domain") == "second.example.com" for c in first_task) == 1


@pytest.mark.parametrize("response_first", [False, True])
def test_dns_separate_answers_join_by_flow_and_index(response_first):
    report = dns_report("IN A")
    requests = report["network"]["requests"]
    requests[0]["index"] = 1
    response = {"flow": 1, "index": 1, "dns_response": requests[0].pop("dns_response")}
    second = {"flow": 1, "index": 2, "dns_request": {"questions": [{"name": "second.example.com", "type": "AAAA"}]}}
    second_response = {"flow": 1, "index": 2, "dns_response": {"ip": ["2001:4860:4860::8888"]}}
    requests.extend(
        [
            second,
            second_response,
            {"flow": 99, "index": 1, "dns_response": {"ip": ["1.1.1.1"]}},
            {"dns_response": {"ip": ["2.2.2.2"]}},
        ]
    )
    requests.insert(0 if response_first else len(requests), response)
    dr = DynamicReport(ontology=OntologyResults(service_name="TriageSandbox"), task_id="behavioral1", **report)
    connections = export_connections(dr)
    assert len(connections) == 3
    assert connections[0]["dns_details"]["resolved_ips"] == ["9.9.9.9"]
    assert connections[0]["dns_details"]["resolved_domains"] == ["answer.example.com"]
    assert connections[1]["dns_details"]["domain"] == "second.example.com"
    assert connections[1]["dns_details"]["resolved_ips"] == ["2001:4860:4860::8888"]
    assert connections[2]["connection_type"] == "http"
    assert dr.dns_evidence == [r for r in requests if "dns_request" in r or "dns_response" in r]
    assert len(dr.diagnostics) == 2
    assert all("DNS response without request" in diagnostic for diagnostic in dr.diagnostics)


@pytest.mark.parametrize("name", [None, ""])
def test_dns_missing_domain_completeness_visible(triage_service, triage_client, requests_mock, make_request, name):
    question = {"type": "IN A"}
    if name is not None:
        question["name"] = name
    report = dns_report("IN A", domains=[], questions=[question])
    requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/behavioral1/report_triage.json", json=report)
    request = make_request()
    triage_service.execute(request)
    sandbox = request.result.sections[0]
    completeness = find_subsection(sandbox, "Analysis completeness")
    assert completeness is not None
    assert "Task behavioral1, flow 1: missing DNS question domain" in completeness.body
    assert completeness.heuristic is None
    task = find_subsection(sandbox, "Task: behavioral1")
    assert json.loads(find_subsection(task, "DNS evidence").body) == [report["network"]["requests"][0]]
    assert find_subsection(sandbox, "FABOOKIE") is not None
    assert find_subsection(sandbox, "VIDAR") is not None
    exported = {"file": {}, "results": {}}
    triage_service.ontology.attach_parts(exported)
    connections = [c for c in exported["results"]["netflow"] if c["objectid"]["session"].endswith("behavioral1")]
    assert len(connections) == 2
    assert "dns_details" not in connections[0]
    assert connections[0]["destination_ip"] == "8.8.8.8"
    assert connections[1]["connection_type"] == "http"
