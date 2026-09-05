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
