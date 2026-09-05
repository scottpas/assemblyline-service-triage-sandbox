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


@pytest.mark.parametrize(
    "bad_config",
    [
        {"family": "broken", "keys": [{"value": "x", "kind": 5}]},
        {"family": 123, "c2": ["http://evil.com/"]},
        {"family": "broken", "wallet": [{}]},
        ["invalid config"],
    ],
)
@pytest.mark.parametrize("source", ["behavioral1", "overview"])
def test_bad_config_does_not_discard_good_evidence(
    triage_service, triage_client, requests_mock, make_request, bad_config, source
):
    report = build_report("behavioral1")
    if source == "behavioral1":
        report["extracted"].insert(0, {"config": bad_config})
        requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/behavioral1/report_triage.json", json=report)
    else:
        requests_mock.get(
            f"https://api.tria.ge/v1/samples/{SAMPLE_ID}/overview.json",
            json={"extracted": [{"config": bad_config}, {"config": {"family": "recovered", "mutex": ["lock"]}}]},
        )
    request = make_request()
    triage_service.execute(request)
    sandbox = request.result.sections[0]
    assert find_subsection(sandbox, "FABOOKIE") is not None
    task = find_subsection(sandbox, "Task: behavioral1")
    configs = find_subsection(task, "Malware Config")
    assert find_subsection(configs, "FABOOKIE") is not None
    assert find_subsection(sandbox, "VIDAR") is not None
    assert find_subsection(task, "Network IOCs") is not None
    diagnostic = find_subsection(sandbox, "Analysis completeness")
    assert "invalid malware config" in diagnostic.body
    assert source.lower() in diagnostic.body.lower()
    assert diagnostic.heuristic is None
    if source == "overview":
        assert find_subsection(sandbox, "RECOVERED") is not None


def test_behavioral_config_unknown_fields_are_tolerated(triage_service, triage_client, requests_mock, make_request):
    report = build_report("behavioral1")
    report["extracted"][0]["config"]["future_field"] = "future value"
    requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/behavioral1/report_triage.json", json=report)
    request = make_request()
    triage_service.execute(request)
    assert find_subsection(request.result.sections[0], "FABOOKIE") is not None
    assert find_subsection(request.result.sections[0], "Analysis completeness") is None
    task = find_subsection(request.result.sections[0], "Task: behavioral1")
    configs = find_subsection(task, "Malware Config")
    assert "future value" in find_subsection(configs, "Raw Config").body


def test_invalid_config_rule_does_not_discard_evidence(triage_service, triage_client, requests_mock, make_request):
    report = build_report("behavioral1")
    report["extracted"].insert(0, {"config": {"family": "broken", "rule": ["invalid"]}})
    requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/behavioral1/report_triage.json", json=report)
    request = make_request()
    triage_service.execute(request)
    sandbox = request.result.sections[0]
    assert find_subsection(sandbox, "FABOOKIE") is not None
    assert "invalid malware config" in find_subsection(sandbox, "Analysis completeness").body


@pytest.mark.parametrize("malformed", [{"keys": [{"kind": 5, "value": "x"}]}, {"wallet": [{}]}])
def test_invalid_config_preserves_rule_detection(triage_service, triage_client, requests_mock, make_request, malformed):
    report = build_report("behavioral1")
    report["extracted"].insert(
        0,
        {"config": {"family": "config_only", "rule": "config_only_rule", **malformed}},
    )
    requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/behavioral1/report_triage.json", json=report)
    request = make_request()
    triage_service.execute(request)
    sandbox = request.result.sections[0]
    task = find_subsection(sandbox, "Task: behavioral1")
    signature = find_subsection(find_subsection(task, "Signatures"), "CONFIG_ONLY_RULE")
    assert signature is not None
    assert signature.heuristic.heur_id == 5
    assert signature.tags["dynamic.signature.name"] == ["CONFIG_ONLY_RULE"]
    assert signature.tags["attribution.family"] == ["CONFIG_ONLY"]
    assert find_subsection(find_subsection(task, "Malware Config"), "CONFIG_ONLY") is None
    assert "invalid malware config" in find_subsection(sandbox, "Analysis completeness").body
    assert find_subsection(sandbox, "FABOOKIE") is not None


@pytest.mark.parametrize("family", [None, 123])
def test_invalid_config_family_does_not_create_rule_signature(
    triage_service, triage_client, requests_mock, make_request, family
):
    report = build_report("behavioral1")
    report["extracted"].insert(0, {"config": {"family": family, "rule": "invalid_family_rule"}})
    requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/behavioral1/report_triage.json", json=report)
    request = make_request()
    triage_service.execute(request)
    sandbox = request.result.sections[0]
    assert find_subsection(sandbox, "INVALID_FAMILY_RULE") is None
    assert find_subsection(sandbox, "FABOOKIE") is not None
    assert "invalid malware config" in find_subsection(sandbox, "Analysis completeness").body
