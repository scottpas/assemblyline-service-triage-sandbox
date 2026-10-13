"""Reconstruct split transactions without losing occurrence or task identity."""

import json
from copy import deepcopy

import pytest
from assemblyline_service_utilities.common.dynamic_service_helper import OntologyResults
from conftest import SAMPLE_ID, build_report
from test_dns_ontology import export_connections
from test_service_integration import find_subsection

from triage_sandbox.report import DynamicReport


def halves(protocol, index=1, flow=1):
    if protocol == "dns":
        request = {"questions": [{"name": "query.example.com", "type": "IN A"}]}
        response = {"ip": ["9.9.9.9"], "domains": ["answer.example.com"]}
    else:
        request = {"url": "http://query.example.com/", "method": "POST", "headers": ["X-Request: yes"]}
        response = {"status": "201", "headers": ["X-Response: yes"]}
    return (
        {"flow": flow, "index": index, f"{protocol}_request": request},
        {"flow": flow, "index": index, f"{protocol}_response": response},
    )


def parse(records, task_id="behavioral1", **overrides):
    report = build_report(task_id)
    report["network"]["flows"] = report["network"]["flows"][:1]
    report["network"]["requests"] = records
    report.update(overrides)
    return DynamicReport(ontology=OntologyResults(service_name="TriageSandbox"), task_id=task_id, **report)


@pytest.mark.parametrize("protocol", ["dns", "http"])
@pytest.mark.parametrize("response_first", [False, True])
def test_split_transactions_export(protocol, response_first):
    request, response = halves(protocol)
    records = [response, request] if response_first else [request, response]
    dr = parse(records)
    connections = export_connections(dr)
    assert len(connections) == 1
    details = connections[0][f"{protocol}_details"]
    if protocol == "dns":
        assert details["domain"] == "query.example.com"
        assert details["resolved_ips"] == ["9.9.9.9"]
        assert details["resolved_domains"] == ["answer.example.com"]
    else:
        assert details["request_uri"] == "http://query.example.com/"
        assert details["request_method"] == "POST"
        assert details["request_headers"] == {"X-Request": "yes"}
        assert details["response_status_code"] == 201
        assert details["response_headers"] == {"X-Response": "yes"}
    assert dr.diagnostics == []


@pytest.mark.parametrize("protocol", ["dns", "http"])
def test_repeated_split_halves_preserve_occurrences(protocol):
    request, response = halves(protocol)
    records = [request, deepcopy(request), response, deepcopy(response)]
    original = deepcopy(records)
    dr = parse(records)
    connections = export_connections(dr)
    assert len(connections) == 2
    assert all(c[f"{protocol}_details"] == connections[0][f"{protocol}_details"] for c in connections)
    assert len({c["objectid"]["ontology_id"] for c in connections}) == 2
    assert records == original
    assert [c["objectid"]["ontology_id"] for c in export_connections(parse(records))] == [
        c["objectid"]["ontology_id"] for c in connections
    ]


@pytest.mark.parametrize("protocol", ["dns", "http"])
def test_combined_records_keep_their_own_response(protocol):
    request, response = halves(protocol)
    combined = {**request, **response}
    other_response = deepcopy(response)
    if protocol == "dns":
        other_response["dns_response"]["ip"] = ["1.1.1.1"]
    else:
        other_response["http_response"]["status"] = 202
    connections = export_connections(parse([request, combined, other_response]))
    assert len(connections) == 2
    key = "resolved_ips" if protocol == "dns" else "response_status_code"
    expected = [["1.1.1.1"], ["9.9.9.9"]] if protocol == "dns" else [202, 201]
    assert [c[f"{protocol}_details"][key] for c in connections] == expected


@pytest.mark.parametrize("protocol", ["dns", "http"])
def test_missing_halves_and_duplicate_responses_preserve_evidence(protocol):
    request, response = halves(protocol)
    unanswered, _ = halves(protocol, index=2)
    dr = parse([response, deepcopy(response), request, unanswered])
    connections = export_connections(dr)
    assert len(connections) == 3
    assert sum(c[f"{protocol}_details"] is None for c in connections) == 1
    assert len(dr.diagnostics) == 1
    assert f"{protocol.upper()} response without request" in dr.diagnostics[0]
    assert "index 1" in dr.diagnostics[0]
    evidence = getattr(dr, f"{protocol}_evidence")
    assert evidence == [response, response, request, unanswered]


def test_pairing_isolated_by_index_flow_protocol_and_task():
    dns_req, dns_res = halves("dns")
    http_req, http_res = halves("http")
    wrong_index = {**http_res, "index": 2}
    wrong_flow = {**dns_res, "flow": 2}
    dr = parse([http_req, dns_req, wrong_index, wrong_flow, {"flow": 1}])
    connections = export_connections(dr)
    assert len(connections) == 3
    assert connections[0]["http_details"]["response_status_code"] is None
    assert connections[1]["dns_details"]["resolved_ips"] is None
    assert connections[2]["http_details"] is None
    other = parse([http_res, dns_res], task_id="behavioral2")
    assert all(c["http_details"] is None and c["dns_details"] is None for c in export_connections(other))
    assert all(c["objectid"]["session"].endswith("behavioral2") for c in export_connections(other))
    assert len({c["objectid"]["ontology_id"] for c in connections + export_connections(other)}) == 5


@pytest.mark.parametrize("protocol", ["dns", "http"])
def test_omitted_zero_index_pairs_with_explicit_zero(protocol):
    request, response = halves(protocol, index=0)
    del request["index"]
    connections = export_connections(parse([request, response]))
    assert len(connections) == 1
    assert connections[0][f"{protocol}_details"] is not None
    details = connections[0][f"{protocol}_details"]
    assert details["resolved_ips" if protocol == "dns" else "response_status_code"] == (
        ["9.9.9.9"] if protocol == "dns" else 201
    )
    dr = parse([response])
    assert len(dr.diagnostics) == 1


@pytest.mark.parametrize("protocol", ["dns", "http"])
def test_orphan_response_evidence_visible_in_service(
    protocol, triage_service, triage_client, requests_mock, make_request
):
    _, response = halves(protocol)
    unlinked = {f"{protocol}_response": response[f"{protocol}_response"]}
    report = build_report("behavioral1")
    report["network"]["requests"] = [response, unlinked]
    requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/behavioral1/report_triage.json", json=report)
    request = make_request()
    triage_service.execute(request)
    sandbox = request.result.sections[0]
    task = find_subsection(sandbox, "Task: behavioral1")
    assert json.loads(find_subsection(task, f"{protocol.upper()} evidence").body) == [response, unlinked]
    assert f"{protocol.upper()} response without request" in find_subsection(sandbox, "Analysis completeness").body
    exported = {"file": {}, "results": {}}
    triage_service.ontology.attach_parts(exported)
    connections = [c for c in exported["results"]["netflow"] if c["objectid"]["session"].endswith("behavioral1")]
    assert len(connections) == 2
    assert all(f"{protocol}_details" not in c for c in connections)


@pytest.mark.parametrize("protocol", ["dns", "http"])
@pytest.mark.parametrize("response_first", [False, True])
def test_repeated_index_and_multiple_indexes_keep_their_answers(protocol, response_first):
    request, response = halves(protocol)
    second_response = deepcopy(response)
    if protocol == "dns":
        second_response["dns_response"]["ip"] = ["1.1.1.1"]
    else:
        second_response["http_response"]["status"] = 202
    third_request, third_response = halves(protocol, index=2)
    requests = [request, deepcopy(request), third_request]
    responses = [response, second_response, third_response]
    dr = parse(responses + requests if response_first else requests + responses)
    connections = export_connections(dr)
    key = "resolved_ips" if protocol == "dns" else "response_status_code"
    assert [c[f"{protocol}_details"][key] for c in connections] == (
        [["9.9.9.9"], ["1.1.1.1"], ["9.9.9.9"]] if protocol == "dns" else [201, 202, 201]
    )
    assert len({c["objectid"]["ontology_id"] for c in connections}) == 3


@pytest.mark.parametrize("protocol", ["dns", "http"])
def test_transaction_process_and_task_associations(protocol):
    reports = []
    for task_id in ("behavioral1", "behavioral2"):
        report = build_report(task_id)
        request, response = halves(protocol)
        report["network"]["requests"] = [request, response]
        report["network"]["flows"] = report["network"]["flows"][:1]
        report["network"]["flows"][0]["pid"] = report["processes"][0]["pid"]
        dr = DynamicReport(ontology=OntologyResults(service_name="TriageSandbox"), task_id=task_id, **report)
        connection = export_connections(dr)[0]
        assert connection["process"]["pid"] == report["processes"][0]["pid"]
        assert connection["process"]["objectid"]["session"] == connection["objectid"]["session"]
        assert connection["objectid"]["session"].endswith(task_id)
        reports.append(connection)
    assert reports[0]["objectid"]["ontology_id"] != reports[1]["objectid"]["ontology_id"]


def test_null_protocol_fields_do_not_create_transactions():
    dr = parse([{"flow": 1, "dns_request": None, "http_response": None}])
    connections = export_connections(dr)
    assert len(connections) == 1
    assert connections[0]["dns_details"] is None
    assert connections[0]["http_details"] is None
    assert dr.diagnostics == []


@pytest.mark.parametrize("bad_field,bad_value", [("url", ""), ("method", "invalid")])
def test_invalid_http_request_keeps_connection_and_response_evidence(bad_field, bad_value):
    request, response = halves("http")
    request["http_request"][bad_field] = bad_value
    dr = parse([request, response])
    connections = export_connections(dr)
    assert len(connections) == 1
    assert connections[0]["http_details"] is None
    assert "invalid HTTP details" in dr.diagnostics[0]
    assert dr.http_evidence == [request, response]


@pytest.mark.parametrize("status", [None, "", "not-a-status"])
def test_http_optional_or_invalid_status_retains_raw_evidence(status):
    request, response = halves("http")
    response["http_response"]["status"] = status
    dr = parse([request, response])
    connection = export_connections(dr)[0]
    assert dr.http_evidence == [request, response]
    if status == "not-a-status":
        assert connection["http_details"] is None
        assert "invalid HTTP details" in dr.diagnostics[0]
    else:
        assert connection["http_details"]["response_status_code"] is None
        assert connection["http_details"]["response_headers"] == {"X-Response": "yes"}
        assert dr.diagnostics == []
