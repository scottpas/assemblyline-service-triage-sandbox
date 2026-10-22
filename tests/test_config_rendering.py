import json

import pytest
from conftest import SAMPLE_ID, build_report

from triage_sandbox.report import TriageResult


@pytest.mark.parametrize(
    "cfg, expected",
    [
        ({"family": "example", "mutex": ["unique-mutex"]}, "unique-mutex"),
        ({"credentials": [{"protocol": "ftp", "username": "alice", "password": "secret"}]}, "alice"),
        ({"family": None, "keys": [{"kind": "rc4", "value": "key-value"}]}, "key-value"),
        ({"family": "  ", "attr": {"install_folder": "C:\\example", "delay": 0}}, "C:\\example"),
        ({"family": "example", "c2": ["https://example.com/gate"]}, "https://example.com/gate"),
    ],
)
def test_recovered_config_readable_and_deduplicated(cfg, expected, triage_service, make_request, mock_triage_api):
    report = build_report("behavioral1")
    report["extracted"] = [{"config": cfg, "resource": "memory/config.dat"}]
    report["signatures"] = []
    mock_triage_api.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/behavioral1/report_triage.json", json=report)
    other = build_report("behavioral2")
    other["extracted"] = []
    mock_triage_api.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/behavioral2/report_triage.json", json=other)
    mock_triage_api.get(
        f"https://api.tria.ge/v1/samples/{SAMPLE_ID}/overview.json", json={"extracted": [{"config": cfg}]}
    )
    req = make_request()
    triage_service.execute(req)
    sandbox = req.result.sections[0]
    task = next(s for s in sandbox.subsections if s.title_text.startswith("Task: behavioral1 "))
    malware = next(s for s in task.subsections if s.title_text == "Malware Config")
    section = malware.subsections[0]
    assert expected in [row["Value"] for row in json.loads(section.section_body.body)]
    assert "memory/config.dat" in section.section_body.body
    family = (cfg.get("family") or "").strip().upper() or "UNKNOWN"
    assert section.title_text == family
    assert section.heuristic.heur_id == 100
    assert (section.tags.get("attribution.family") or []) == ([] if family == "UNKNOWN" else [family])
    assert not any(s.title_text == "Overview" for s in sandbox.subsections)
    result = TriageResult(triage_service.client, triage_service.client.sample_by_id(SAMPLE_ID))
    assert len(result.malware_config) == 1
    assert result.malware_config[0].family == [family]
    if "credentials" in cfg:
        assert result.malware_config[0].ftp[0].username == "alice"


@pytest.mark.parametrize("cfg", [{}, {"family": "", "credentials": [{"protocol": "ftp"}]}, {"mutex": []}])
def test_empty_config_has_no_detection(cfg, triage_service, make_request, mock_triage_api):
    for task_id in ("behavioral1", "behavioral2"):
        report = build_report(task_id)
        report["extracted"] = [{"config": cfg}]
        mock_triage_api.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/{task_id}/report_triage.json", json=report)
    req = make_request()
    triage_service.execute(req)
    assert all(
        sub.title_text != "Malware Config" for task in req.result.sections[0].subsections for sub in task.subsections
    )
    result = TriageResult(triage_service.client, triage_service.client.sample_by_id(SAMPLE_ID))
    assert result.malware_config == []


def test_overview_only_config_without_c2(triage_service, make_request, mock_triage_api):
    cfg = {"mutex": ["overview-mutex"], "attr": {"enabled": False, "empty": None, "ignored": ""}}
    mock_triage_api.get(
        f"https://api.tria.ge/v1/samples/{SAMPLE_ID}/overview.json",
        json={"extracted": [{"config": cfg, "resource": "overview/config.dat"}, {"config": cfg}, {"config": {}}]},
    )
    req = make_request()
    triage_service.execute(req)
    overview = next(s for s in req.result.sections[0].subsections if s.title_text == "Overview")
    configs = next(s for s in overview.subsections if s.title_text == "Malware Config")
    assert len(configs.subsections) == 1
    rows = json.loads(configs.subsections[0].body)
    assert {"Field": "mutex [1]", "Value": "overview-mutex"} in rows
    assert {"Field": "attr.enabled", "Value": False} in rows
    assert {"Field": "Extraction resource", "Value": "overview/config.dat"} in rows


@pytest.mark.parametrize("family", [None, "", "  "])
def test_rule_signature_survives_unknown_family(family, triage_service, make_request, mock_triage_api):
    report = build_report("behavioral1")
    report["extracted"] = [{"config": {"family": family, "rule": "RecoveredRule", "mutex": ["recovered-mutex"]}}]
    report["signatures"] = []
    mock_triage_api.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/behavioral1/report_triage.json", json=report)
    request = make_request()
    triage_service.execute(request)
    task = next(s for s in request.result.sections[0].subsections if s.title_text.startswith("Task: behavioral1 "))
    signatures = next(s for s in task.subsections if s.title_text == "Signatures")
    signature = next(s for s in signatures.subsections if s.title_text == "RECOVEREDRULE")
    assert signature.heuristic.heur_id == 5
    result = TriageResult(triage_service.client, triage_service.client.sample_by_id(SAMPLE_ID))
    rule = next(
        s.as_primitives()
        for s in result.sample.task_reports[0].ontology.get_signatures()
        if s.as_primitives()["name"] == "RecoveredRule"
    )
    assert rule["malware_families"] == ["UNKNOWN"]
    assert result.malware_config[0].family == ["UNKNOWN"]


@pytest.mark.parametrize(
    "credentials, smtp, diagnostic",
    [
        (
            {
                "protocol": "smtp",
                "host": "mail.example.com",
                "port": 25,
                "username": "u",
                "password": "hunter2-secret",
                "email_to": "a@example.com",
                "future": 1,
            },
            True,
            None,
        ),
        (
            {"protocol": "imap", "host": "mail.example.com", "username": "u", "password": "hunter2-secret"},
            False,
            "skipped credentials with no supported content",
        ),
        ({"protocol": "smtp", "port": "not-a-port"}, False, "skipped credentials with no supported content"),
        ({"username": "x"}, False, "invalid credentials (TypeError)"),
    ],
)
def test_standalone_credentials(credentials, smtp, diagnostic, triage_service, make_request, mock_triage_api):
    for task_id in ("behavioral1", "behavioral2"):
        report = build_report(task_id)
        report["extracted"] = [{"credentials": credentials}]
        mock_triage_api.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/{task_id}/report_triage.json", json=report)
    req = make_request()
    triage_service.execute(req)
    result = TriageResult(triage_service.client, triage_service.client.sample_by_id(SAMPLE_ID))
    if smtp:
        assert len(result.malware_config) == 2
        assert result.malware_config[0].smtp[0].mail_to == ["a@example.com"]
    else:
        assert result.malware_config == []
    if diagnostic:
        assert any(diagnostic in d for d in result.diagnostics)
    assert not any("hunter2" in d or "mail.example.com" in d for d in result.diagnostics)
