"""Signature indicator evidence and source/target process relations."""

import json
from typing import Any

from conftest import SAMPLE_ID, build_report
from test_process_identity import make_report, proc
from test_service_integration import find_subsection

PROCESSES = [proc(1, 100, 4, 0), proc(2, 200, 100, 5, procid_parent=1)]


def attrs(dr: Any, name: str) -> list[dict[str, Any]]:
    sig = next(s for s in dr.ontology.get_signatures() if s.name == name)
    return [a.as_primitives() for a in sig.attributes]


def test_cross_process_indicator_keeps_source_target_and_evidence():
    dr = make_report(
        processes=PROCESSES,
        signatures=[
            {
                "label": "injection",
                "score": 5,
                "indicators": [
                    {"description": "PID 100 wrote to memory of 200", "procid": 1, "procid_target": 2},
                ],
            }
        ],
    )
    [attr] = attrs(dr, "injection")
    assert attr["source"]["guid"] == dr._procid_process[1].objectid.guid
    assert attr["target"]["guid"] == dr._procid_process[2].objectid.guid
    assert attr["meta"] == "PID 100 wrote to memory of 200"
    assert "action" not in attr or attr["action"] is None


def test_unresolved_or_self_target_adds_no_relation():
    dr = make_report(
        processes=PROCESSES,
        signatures=[
            {
                "label": "s",
                "score": 5,
                "indicators": [
                    {"ioc": "a", "procid": 1, "procid_target": 84},
                    {"ioc": "b", "procid": 1, "procid_target": 1},
                ],
            }
        ],
    )
    result = attrs(dr, "s")
    assert [a["meta"] for a in result] == ["a", "b"]
    assert all(a.get("target") is None for a in result)


def test_indicator_without_resolved_source_keeps_evidence_row_only():
    dr = make_report(
        processes=PROCESSES,
        signatures=[
            {"label": "s", "score": 5, "indicators": [{"ioc": "x", "pid": 77, "procid": 9, "procid_target": 2}]}
        ],
    )
    assert attrs(dr, "s") == []
    [row] = dr.signature_indicators["s"]
    assert row["Source"] == "#9 PID 77 (not recorded)"
    assert row["Target"] == "#2 p2.exe (PID 200)"


def test_indicator_rows_kept_alongside_signature_description_and_deduplicated():
    indicator = {
        "description": "Uses yara rule",
        "ioc": "evil",
        "procid": 1,
        "pid_target": 300,
        "flow": 3,
        "resource": "behavioral1/memory/100-1-0x1-memory.dmp",
        "yara_rule": "rule_a",
    }
    dr = make_report(
        processes=PROCESSES,
        signatures=[
            {"label": "s", "score": 5, "desc": "Signature explanation", "indicators": [indicator, indicator]},
            # The same signature reported again accumulates distinct indicators only.
            {"label": "s", "score": 5, "indicators": [indicator, {"pid": 55}, {}]},
        ],
    )
    assert dr.signature_descriptions["s"] == "Signature explanation"
    assert dr.signature_indicators["s"] == [
        {
            "Source": "#1 p1.exe (PID 100)",
            "Target": "PID 300",
            "Description": "Uses yara rule",
            "IOC": "evil",
            "Flow": 3,
            "Resource": "behavioral1/memory/100-1-0x1-memory.dmp",
            "YARA rule": "rule_a",
        },
        {"Source": "PID 55", "Target": "", "Description": "", "IOC": "", "Flow": "", "Resource": "", "YARA rule": ""},
    ]


def test_signature_without_indicators_has_no_rows():
    dr = make_report(signatures=[{"label": "s", "score": 5}])
    assert "s" not in dr.signature_indicators


def test_indicator_table_rendered_with_populated_columns_and_bounded(
    triage_service, triage_client, requests_mock, make_request, monkeypatch
):
    del triage_client  # registers the shared Triage endpoints
    import triage_sandbox.service as service

    monkeypatch.setattr(service, "MAX_TABLE_ROWS", 1)
    report = build_report("behavioral1")
    report["signatures"].append(
        {
            "label": "injection",
            "score": 5,
            "desc": "Writes to another process",
            "indicators": [{"ioc": "one", "procid": 1, "procid_target": 2}, {"ioc": "two", "procid": 2}],
        }
    )
    requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/behavioral1/report_triage.json", json=report)
    request = make_request()

    triage_service.execute(request)

    task = find_subsection(request.result.sections[0], "Task: behavioral1")
    signature = find_subsection(find_subsection(task, "Signatures"), "INJECTION")
    assert "Writes to another process" in signature.body
    table = find_subsection(signature, "Indicators")
    assert table is not None and table.auto_collapse is True
    rows = json.loads(table.section_body.body)
    assert rows == [{"Source": "#1 sample.exe (PID 2104)", "Target": "#2 child.exe (PID 2356)", "IOC": "one"}]
    assert "1 more indicator(s) not shown" in find_subsection(table, "Rows omitted").body


def test_repeated_indicator_adds_one_attribute():
    indicator = {"ioc": "x", "procid": 1, "procid_target": 2}
    dr = make_report(
        processes=PROCESSES,
        signatures=[
            {"label": "s", "score": 5, "indicators": [indicator, indicator]},
            {"label": "s", "indicators": [indicator]},
        ],
    )
    assert len(attrs(dr, "s")) == 1


def test_overview_signature_indicator_table_keeps_raw_process_references(triage_service, make_request, mock_triage_api):
    from conftest import build_overview

    overview = build_overview(
        signatures=[
            {
                "label": "overview_only",
                "score": 5,
                "desc": "Explained",
                "indicators": [
                    {"ioc": "a", "procid": 84, "pid": 4700, "procid_target": 86},
                    {"ioc": "a", "procid": 84, "pid": 4700, "procid_target": 86},
                    {},
                ],
            },
            {"label": "no_indicators", "score": 5, "indicators": [{}]},
        ]
    )
    mock_triage_api.get(f"https://api.tria.ge/v1/samples/{SAMPLE_ID}/overview.json", json=overview)
    request = make_request()

    triage_service.execute(request)

    overview_sigs = find_subsection(find_subsection(request.result.sections[0], "Overview"), "Signatures")
    signature = find_subsection(overview_sigs, "OVERVIEW_ONLY")
    assert "Explained" in signature.body
    rows = json.loads(find_subsection(signature, "Indicators").section_body.body)
    assert rows == [{"Source": "#84 PID 4700", "Target": "#86", "IOC": "a"}]
    assert find_subsection(find_subsection(overview_sigs, "NO_INDICATORS"), "Indicators") is None
