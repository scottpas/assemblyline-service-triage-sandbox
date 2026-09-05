import pytest
from conftest import SAMPLE_ID, build_report, build_sample
from test_service_integration import find_subsection


@pytest.mark.parametrize("failure", ["failed", "unavailable", "execution", "overview", "artifact"])
def test_incomplete_analysis_keeps_findings(triage_service, triage_client, requests_mock, make_request, failure):
    sample = build_sample()
    report = build_report("behavioral1")
    expected = failure
    if failure == "failed":
        sample["tasks"][2]["status"] = "failed"
    elif failure == "unavailable":
        requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/behavioral2/report_triage.json", status_code=404)
    elif failure == "execution":
        report["errors"] = [{"reason": "execution failed"}, {}]
    elif failure == "overview":
        requests_mock.get(f"https://api.tria.ge/v1/samples/{SAMPLE_ID}/overview.json", status_code=503)
    else:
        requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/behavioral1/dump.pcapng", status_code=404)
        requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/behavioral2/dump.pcapng", status_code=404)
    requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}", json=sample)
    requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/behavioral1/report_triage.json", json=report)
    request = make_request(extract_pcap=failure == "artifact")

    triage_service.execute(request)

    sandbox = request.result.sections[0]
    section = find_subsection(sandbox, "Analysis completeness")
    assert section is not None
    assert expected in section.body.lower()
    assert section.heuristic is None
    assert find_subsection(sandbox, "FABOOKIE") is not None


def test_complete_analysis_has_no_warning(triage_service, triage_client, make_request):
    request = make_request()
    triage_service.execute(request)
    assert find_subsection(request.result.sections[0], "Analysis completeness") is None


@pytest.mark.parametrize("failure", [429, 503, "connection", "json"])
@pytest.mark.parametrize("other_task", ["unavailable", "failed", "reported"])
def test_report_fetch_failure_requires_some_dynamic_evidence(
    triage_service, triage_client, requests_mock, make_request, failure, other_task
):
    from requests import ConnectionError

    from triage_sandbox.client import ServerError

    sample = build_sample()
    if other_task == "failed":
        sample["tasks"][2]["status"] = "failed"
    requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}", json=sample)
    error = ServerError if isinstance(failure, int) else ConnectionError if failure == "connection" else ValueError
    response = (
        {"status_code": failure}
        if isinstance(failure, int)
        else {"exc": ConnectionError("offline")}
        if failure == "connection"
        else {"text": "not json"}
    )
    tasks = ["behavioral1", "behavioral2"] if other_task == "unavailable" else ["behavioral1"]
    for task in tasks:
        requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/{task}/report_triage.json", **response)
    request = make_request()
    if other_task == "reported":
        triage_service.execute(request)
        assert find_subsection(request.result.sections[0], "VIDAR") is not None
        assert find_subsection(request.result.sections[0], "Analysis completeness") is not None
    else:
        with pytest.raises(error):
            triage_service.execute(request)
        assert request.result is None


def test_all_explicitly_failed_tasks_remain_informational(triage_service, triage_client, requests_mock, make_request):
    sample = build_sample()
    for task in sample["tasks"]:
        task["status"] = "failed"
    requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}", json=sample)
    request = make_request()
    triage_service.execute(request)
    assert "failed" in find_subsection(request.result.sections[0], "Analysis completeness").body
