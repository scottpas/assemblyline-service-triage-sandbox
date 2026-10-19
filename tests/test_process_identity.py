"""Process-instance identity: Triage procid drives parentage, signature and network links."""

import json
from typing import Any, cast

import pytest
from assemblyline_service_utilities.common.dynamic_service_helper import OntologyResults
from conftest import SAMPLE_ID, build_report
from test_service_integration import find_subsection

from triage_sandbox.report import DynamicReport


def make_report(**over: Any) -> DynamicReport:
    base: dict[str, Any] = dict(
        ontology=OntologyResults(service_name="Triage"),
        task_id="behavioral1",
        version="1.0",
        sample={"id": "sample123"},
        task={},
        analysis={
            "submitted": "2024-02-02T23:56:27Z",
            "reported": "2024-02-02T23:59:09Z",
            "resource": "win7",
        },
        signatures=[],
        network={},
    )
    base.update(over)
    return DynamicReport(**base)


def proc(procid: int, pid: int, ppid: int, started: int, **extra: Any) -> dict[str, Any]:
    return {
        "procid": procid,
        "pid": pid,
        "ppid": ppid,
        "image": f"p{procid}.exe",
        "cmd": f"p{procid}.exe",
        "started": started,
        **extra,
    }


def by_procid(dr: DynamicReport, procid: int) -> Any:
    return dr._procid_process[procid]


def test_reused_pid_instances_are_all_retained():
    """An earlier instance without a recorded termination must not absorb a later reuse of its PID."""
    dr = make_report(processes=[proc(1, 100, 4, 0), proc(2, 100, 4, 5)])

    processes: list[Any] = dr.ontology.get_processes()
    assert sorted(p.image for p in processes) == ["p1.exe", "p2.exe"]
    assert by_procid(dr, 1).objectid.guid != by_procid(dr, 2).objectid.guid
    assert by_procid(dr, 2).image == "p2.exe"


def test_procid_parent_links_nearest_recorded_ancestor_and_keeps_reported_ppid():
    """Unrecorded forks make procid_parent's PID differ from ppid; neither value is rewritten."""
    dr = make_report(processes=[proc(7, 1520, 1, 10), proc(8, 1523, 1522, 20, procid_parent=7)])

    child, parent = by_procid(dr, 8), by_procid(dr, 7)
    assert child.pobjectid.guid == parent.objectid.guid
    assert child.pimage == "p7.exe"
    assert child.pcommand_line == "p7.exe"
    assert child.ppid == 1522


def test_procid_parent_disambiguates_reused_parent_pid():
    dr = make_report(
        processes=[
            proc(1, 100, 4, 0, terminated=10),
            proc(2, 100, 4, 20),
            proc(3, 300, 100, 30, procid_parent=1),
        ]
    )
    assert by_procid(dr, 3).pobjectid.guid == by_procid(dr, 1).objectid.guid


def test_parent_listed_after_child_resolves():
    dr = make_report(processes=[proc(2, 200, 100, 30, procid_parent=1), proc(1, 100, 4, 0)])
    assert by_procid(dr, 2).pobjectid.guid == by_procid(dr, 1).objectid.guid


@pytest.mark.parametrize("procid_parent", [55, 3, [1], {"procid": 1}])
def test_unresolved_or_self_procid_parent_does_not_fall_back_to_pid(procid_parent):
    """An explicit parent instance that was not recorded is not replaced by a PID guess."""
    dr = make_report(processes=[proc(1, 100, 4, 0), proc(3, 300, 100, 30, procid_parent=procid_parent)])

    child = by_procid(dr, 3)
    assert child.pobjectid is None
    assert child.ppid == 100


@pytest.mark.parametrize("extra", [{}, {"procid_parent": 0}])
def test_missing_procid_parent_falls_back_to_unique_live_ppid(extra):
    dr = make_report(processes=[proc(1, 100, 4, 0, terminated=50), proc(2, 200, 100, 30, **extra)])
    assert by_procid(dr, 2).pobjectid.guid == by_procid(dr, 1).objectid.guid


@pytest.mark.parametrize(
    "candidates",
    [
        # Two instances alive at the child's start: ambiguous.
        [proc(1, 100, 4, 0), proc(2, 100, 4, 5)],
        # The only instance terminated before the child started.
        [proc(1, 100, 4, 0, terminated=10)],
        # The only instance started after the child.
        [proc(1, 100, 4, 40)],
    ],
)
def test_missing_procid_parent_without_single_live_ppid_has_no_parent(candidates):
    dr = make_report(processes=[*candidates, proc(9, 900, 100, 30)])

    child = by_procid(dr, 9)
    assert child.pobjectid is None
    assert child.ppid == 100


def test_duplicate_procid_keeps_first_instance_with_diagnostic():
    dr = make_report(processes=[proc(1, 100, 4, 0), proc(1, 200, 4, 5)])

    processes: list[Any] = dr.ontology.get_processes()
    assert [p.pid for p in processes] == [100]
    assert any("invalid process" in d for d in dr.diagnostics)


def test_process_rows_keep_orig_parent_and_original_command():
    argv = ["/bin/sh", "-c", "echo a b"]
    dr = make_report(
        processes=[
            proc(1, 100, 4, 0, orig=False),
            {**proc(2, 200, 100, 5, procid_parent=1, orig=True), "cmd": argv},
            proc(3, 300, 4, 6, procid_parent=77),
        ]
    )

    assert by_procid(dr, 2).command_line == "/bin/sh -c 'echo a b'"
    rows = {row["Process"]: row for row in dr.process_rows}
    assert rows[2] == {
        "Process": 2,
        "Parent": 1,
        "PID": 200,
        "PPID": 100,
        "Triage orig": True,
        "Image": "p2.exe",
        "Command": json.dumps(argv),
    }
    assert rows[1]["Parent"] == "" and rows[1]["Triage orig"] is False
    # An unrecorded parent instance stays visible as evidence, not as a link.
    assert rows[3]["Parent"] == "77 (not recorded)"
    assert rows[3]["Triage orig"] == ""


def flow(flow_id: int, **extra: Any) -> dict[str, Any]:
    return {"id": flow_id, "src": "10.0.0.5:1000", "dst": "8.8.8.8:53", "proto": "udp", "first_seen": 40, **extra}


def test_flow_owner_resolves_by_procid():
    dr = make_report(
        processes=[proc(1, 100, 4, 0), proc(2, 100, 4, 5), proc(3, 300, 4, 6)],
        network={
            "flows": [
                flow(1, pid=100, procid=2),
                # An unrecorded procid is not replaced by a PID guess.
                flow(2, pid=300, procid=99),
                # Without procid, only an unambiguous PID is linked.
                flow(3, pid=300),
                flow(4, pid=100),
            ]
        },
    )
    connections: list[Any] = dr.ontology.get_network_connections()
    guids = [c.process.objectid.guid if c.process else None for c in connections]
    assert guids == [by_procid(dr, 2).objectid.guid, None, by_procid(dr, 3).objectid.guid, None]


def test_config_signature_source_resolves_through_dumped_procid():
    dump_name = "memory/100-1-0x1000-0x2000-memory.dmp"
    dr = make_report(
        processes=[proc(1, 100, 4, 0), proc(2, 100, 4, 5)],
        dumped=[{"name": dump_name, "procid": 2, "pid": 100, "kind": "region"}, {"name": "files/y", "pid": 100}],
        extracted=[
            {"config": {"family": "fam", "rule": "Fam", "c2": ["1.2.3.4:80"]}, "resource": f"behavioral1/{dump_name}"},
            # A resource with no dump record, or a dump without procid, attaches no process.
            {"config": {"family": "fam", "rule": "Other", "c2": ["1.2.3.5:80"]}, "resource": "behavioral1/memory/x"},
            {"config": {"family": "fam", "rule": "Third", "c2": ["1.2.3.6:80"]}, "resource": "behavioral1/files/y"},
        ],
    )
    signatures: list[Any] = dr.ontology.get_signatures()
    sigs = {s.name: s for s in signatures}
    assert [a.source.guid for a in sigs["Fam"].attributes] == [by_procid(dr, 2).objectid.guid]
    assert sigs["Other"].attributes == []
    assert sigs["Third"].attributes == []


def test_config_signature_source_falls_back_to_unique_dump_pid():
    dr = make_report(
        processes=[proc(1, 100, 4, 0), proc(2, 300, 4, 5)],
        dumped=[{"name": "files/y", "pid": 300}],
        extracted=[
            {"config": {"family": "fam", "rule": "Fam", "c2": ["1.2.3.4:80"]}, "resource": "behavioral1/files/y"}
        ],
    )
    [sig] = cast(list[Any], dr.ontology.get_signatures())
    assert [a.source.guid for a in sig.attributes] == [by_procid(dr, 2).objectid.guid]


def test_process_instances_table_rendered_and_bounded(
    triage_service, triage_client, requests_mock, make_request, monkeypatch
):
    del triage_client  # registers the shared Triage endpoints
    import triage_sandbox.service as service

    monkeypatch.setattr(service, "MAX_TABLE_ROWS", 1)
    report = build_report("behavioral1")
    requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/behavioral1/report_triage.json", json=report)
    request = make_request()

    triage_service.execute(request)

    task = find_subsection(request.result.sections[0], "Task: behavioral1")
    table = find_subsection(task, "Process instances")
    assert table is not None and table.auto_collapse is True
    rows = json.loads(table.section_body.body)
    assert len(rows) == 1
    assert rows[0]["Process"] == 1
    note = find_subsection(table, "Rows omitted")
    assert note is not None and "1 more process instance(s) not shown" in note.body
