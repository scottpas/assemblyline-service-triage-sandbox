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
    task = next(s for s in sandbox.subsections if s.title_text == "Task: behavioral1")
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
