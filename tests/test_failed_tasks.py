"""Recover terminal-task evidence without hiding execution or retrieval failures."""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from conftest import SAMPLE_ID, build_overview, build_report, build_sample
from requests import ConnectionError
from test_service_integration import find_subsection

from triage_sandbox.client import ServerError
from triage_sandbox.report import Sample, TriageResult
from triage_sandbox.service import wait_for_submission


def report_url(task_id):
    return f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/{task_id}/report_triage.json"


def failed_sample():
    sample = build_sample()
    sample["tasks"][1]["status"] = "failed"
    sample["tasks"][1]["failure"] = "Machine shutdown"
    return sample


@pytest.mark.parametrize("partial", [False, True])
def test_failed_report_recovers_evidence_and_deduplicates_overview(triage_client, requests_mock, partial):
    report = build_report("behavioral1")
    report["errors"] = [{"reason": "Machine shutdown"}]
    if partial:
        report["processes"].insert(0, {})
    requests_mock.get(report_url("behavioral1"), json=report)
    requests_mock.get(
        f"https://api.tria.ge/v1/samples/{SAMPLE_ID}/overview.json",
        json=build_overview(
            signatures=[*report["signatures"], {"label": "overview_only"}],
            configs=[report["extracted"][0]["config"], {"family": "overview_only"}],
        ),
    )

    result = TriageResult(triage_client, failed_sample())

    b1, b2 = result.sample.task_reports
    assert b1.ontology is not b2.ontology
    assert {p.as_primitives()["pid"] for p in b1.ontology.get_processes()} == {2104, 2356}
    assert {p.as_primitives()["pid"] for p in b2.ontology.get_processes()} == {3104, 3356}
    assert len(b1.ontology.get_network_connections()) == 2
    assert "fabookie" in {s.as_primitives()["name"] for s in b1.ontology.get_signatures()}
    assert "vidar" not in {s.as_primitives()["name"] for s in b1.ontology.get_signatures()}
    assert result.overview_signatures == [{"label": "overview_only"}]
    assert result.overview_configs == [{"family": "overview_only"}]
    assert len(result.malware_config) == 3
    assert any("failed" in message for message in result.diagnostics)
    assert any("Machine shutdown" in message for message in result.diagnostics)
    assert any("partially parsed" in message for message in result.diagnostics) == partial
    assert sum(r.url == report_url("behavioral1") for r in requests_mock.request_history) == 1


@pytest.mark.parametrize("status", ["reported", "failed"])
@pytest.mark.parametrize("payload", [{}, [], {"analysis": {}}, None])
def test_unparseable_report_preserves_other_task_and_overview(triage_client, requests_mock, status, payload):
    sample = failed_sample()
    sample["tasks"][1]["status"] = status
    requests_mock.get(report_url("behavioral1"), text=json.dumps(payload))
    requests_mock.get(
        f"https://api.tria.ge/v1/samples/{SAMPLE_ID}/overview.json",
        json=build_overview(signatures=[{"label": "recovered"}]),
    )
    result = TriageResult(triage_client, sample)
    assert [r.task_id for r in result.sample.task_reports] == ["behavioral2"]
    assert any("report could not be parsed" in message for message in result.diagnostics)
    assert result.overview_signatures == [{"label": "recovered"}]


def test_failed_tasks_without_reports_use_overview(triage_client, requests_mock):
    sample = failed_sample()
    sample["tasks"][2]["status"] = "failed"
    for task in ("behavioral1", "behavioral2"):
        requests_mock.get(report_url(task), status_code=404, json={"error": "REPORT_NOT_AVAILABLE"})
    requests_mock.get(
        f"https://api.tria.ge/v1/samples/{SAMPLE_ID}/overview.json",
        json=build_overview(signatures=[{"label": "overview_only"}]),
    )
    result = TriageResult(triage_client, sample)
    assert result.sample.task_reports == []
    assert result.overview_signatures == [{"label": "overview_only"}]
    assert sum("report unavailable" in message for message in result.diagnostics) == 2


@pytest.mark.parametrize("failure", [429, 503, "connection", "json"])
@pytest.mark.parametrize("other_report", ["missing", "usable", "invalid"])
def test_failed_task_fetch_outage_requires_usable_report(triage_client, requests_mock, failure, other_report):
    sample = failed_sample()
    sample["tasks"][2]["status"] = "failed"
    if isinstance(failure, int):
        response, error = {"status_code": failure}, ServerError
    elif failure == "connection":
        response, error = {"exc": ConnectionError("offline")}, ConnectionError
    else:
        response, error = {"text": "invalid json"}, ValueError
    requests_mock.get(report_url("behavioral1"), **response)
    if other_report == "missing":
        requests_mock.get(report_url("behavioral2"), status_code=404)
    elif other_report == "invalid":
        requests_mock.get(report_url("behavioral2"), json={})
    result = Sample(**sample)
    if other_report == "usable":
        result.get_task_reports(triage_client)
        assert [r.task_id for r in result.task_reports] == ["behavioral2"]
        assert any("report fetch failed" in message for message in result.diagnostics)
    else:
        with pytest.raises(error):
            result.get_task_reports(triage_client)


@pytest.mark.parametrize("status", ["pending", "scheduled", "running", "processing", "unknown"])
def test_nonterminal_task_is_not_fetched(triage_client, requests_mock, status):
    sample = failed_sample()
    sample["tasks"][1]["status"] = status
    result = Sample(**sample)
    result.get_task_reports(triage_client)
    assert [r.task_id for r in result.task_reports] == ["behavioral2"]
    assert not any(r.url == report_url("behavioral1") for r in requests_mock.request_history)
    assert any(status in message for message in result.diagnostics)


def test_failed_submission_stops_polling():
    service = SimpleNamespace(client=MagicMock(), log=MagicMock())
    failed = {"id": SAMPLE_ID, "status": "failed"}
    # A second call makes this fail promptly instead of waiting for retry exhaustion.
    service.client.sample_by_id.side_effect = [failed, AssertionError("terminal sample polled twice")]
    assert wait_for_submission(service=service, submission_id=SAMPLE_ID) == failed
    assert service.client.sample_by_id.call_count == 1


def test_terminal_failed_sample_emits_recovered_task_and_warning(
    triage_service, triage_client, requests_mock, make_request
):
    sample = failed_sample()
    sample["status"] = "failed"
    sample.pop("completed")
    requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}", json=sample)
    request = make_request()
    triage_service.execute(request)
    sandbox = request.result.sections[0]
    assert find_subsection(sandbox, "Task: behavioral1") is not None
    assert find_subsection(sandbox, "FABOOKIE") is not None
    diagnostic = find_subsection(sandbox, "Analysis completeness")
    assert "Sample" in diagnostic.body
    assert "failed" in diagnostic.body
    assert "Machine shutdown" in diagnostic.body
    assert diagnostic.heuristic is None


@pytest.mark.parametrize("status", ["reported", "failed"])
@pytest.mark.parametrize(
    "overview", ["empty", "unavailable", "invalid_config", "nameless_signature", "signature", "config"]
)
def test_all_unparseable_reports_require_recovered_evidence(
    triage_service, triage_client, requests_mock, make_request, status, overview
):
    sample = build_sample()
    for task in sample["tasks"][1:]:
        task["status"] = status
        requests_mock.get(report_url(task["id"]), json={})
    requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}", json=sample)
    overview_url = f"https://api.tria.ge/v1/samples/{SAMPLE_ID}/overview.json"
    if overview == "unavailable":
        requests_mock.get(overview_url, status_code=503)
    else:
        payload = {
            "empty": {},
            "invalid_config": build_overview(configs=[{"family": 123}]),
            "nameless_signature": build_overview(signatures=[{}]),
            "signature": build_overview(signatures=[{"label": "recovered", "score": 3}]),
            "config": build_overview(configs=[{"family": "recovered", "c2": ["https://recovered.example/gate"]}]),
        }[overview]
        requests_mock.get(overview_url, json=payload)
    request = make_request()
    if overview in {"signature", "config"}:
        triage_service.execute(request)
        sandbox = request.result.sections[0]
        assert find_subsection(sandbox, "RECOVERED") is not None
        assert "report could not be parsed" in find_subsection(sandbox, "Analysis completeness").body
    else:
        with pytest.raises(TypeError, match="required positional arguments"):
            triage_service.execute(request)
        assert request.result is None


def test_parse_failure_state_is_reset_on_retrieval(triage_client, requests_mock):
    sample = Sample(**failed_sample())
    requests_mock.get(report_url("behavioral1"), json={})
    sample.get_task_reports(triage_client)
    assert isinstance(sample.parse_error, TypeError)
    requests_mock.get(report_url("behavioral1"), json=build_report("behavioral1"))
    sample.get_task_reports(triage_client)
    assert sample.parse_error is None
    assert len(sample.task_reports) == 2
