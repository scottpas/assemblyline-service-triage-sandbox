"""Timestamp regressions using the real report's millisecond offset shapes."""

from datetime import datetime, timezone

import pytest
from test_dynamic_report import make_report


def process(**over):
    return {"procid": 1, "pid": 100, "ppid": 0, "image": "a.exe", "started": 140, **over}


def flow(**over):
    return {"id": 1, "src": "10.0.0.5:1234", "dst": "8.8.8.8:53", "proto": "udp", **over}


def test_millisecond_offsets_and_ordering():
    dr = make_report(
        processes=[process(terminated=97094)],
        network={"flows": [flow(first_seen=3343, last_seen=3395, pid=100)]},
    )
    p = dr.ontology.get_processes()[0]
    nc = dr.ontology.get_network_connections()[0]
    assert p.start_time == "2024-02-02 23:56:27.140000"
    assert p.objectid.time_observed == p.start_time
    assert p.end_time == "2024-02-02 23:58:04.094000"
    assert nc.objectid.time_observed == "2024-02-02 23:56:30.343000"
    assert nc.process is p
    assert dr.ontology.get_events() == [p, nc]
    assert dr.diagnostics == []


def test_analysis_timezone_and_fractional_seconds():
    dr = make_report(
        analysis={
            "submitted": "2024-02-03T10:56:27.123456+11:00",
            "reported": "2024-02-02T23:59:09.123456Z",
            "resource": "win7",
        },
        processes=[process(started=1)],
    )
    assert dr.start_time == datetime(2024, 2, 2, 23, 56, 27, 123456, tzinfo=timezone.utc)
    assert dr.end_time.tzinfo is timezone.utc
    assert dr.ontology.get_sandboxes()[0].analysis_metadata.start_time == "2024-02-02 23:56:27.123456"
    assert dr.ontology.get_processes()[0].start_time == "2024-02-02 23:56:27.124456"


@pytest.mark.parametrize("terminated", [None, 0, -1, 162001, "bad", True, 1.5, 10**100])
def test_unknown_or_invalid_termination_is_not_an_event(terminated):
    dr = make_report(processes=[process(terminated=terminated)])
    p = dr.ontology.get_processes()[0]
    assert p.end_time is None
    assert p.as_primitives()["end_time"] is None
    dr.ontology.get_process_tree_result_section()
    assert p.end_time is None
    assert bool(dr.diagnostics) == (terminated not in (None, 0))


@pytest.mark.parametrize("started", [None, -1, 162001, "bad", True, 1.5, 10**100])
def test_invalid_start_omits_process_with_diagnostic(started):
    dr = make_report(processes=[process(started=started)])
    assert dr.ontology.get_processes() == []
    assert any("started" in message for message in dr.diagnostics)


def test_zero_offset_is_observed_and_absent_flow_time_is_unknown():
    dr = make_report(processes=[process(started=0)], network={"flows": [flow(first_seen=0), flow(id=2)]})
    assert dr.ontology.get_processes()[0].start_time == "2024-02-02 23:56:27.000000"
    first, absent = dr.ontology.get_network_connections()
    assert first.objectid.time_observed == "2024-02-02 23:56:27.000000"
    assert absent.objectid.time_observed is None
    assert dr.diagnostics == []


@pytest.mark.parametrize("offset", [-1, 162001, "bad", True, 1.5, 10**100])
def test_bad_flow_time_keeps_connection_without_fabricated_time(offset):
    dr = make_report(network={"flows": [flow(first_seen=offset)]})
    assert dr.ontology.get_network_connections()[0].objectid.time_observed is None
    assert any("first_seen" in message for message in dr.diagnostics)


def test_termination_before_start_remains_unknown():
    dr = make_report(processes=[process(started=1000, terminated=500)])
    assert dr.ontology.get_processes()[0].end_time is None
    assert any("terminated" in message for message in dr.diagnostics)


def test_missing_process_start_is_not_invented():
    raw = process()
    del raw["started"]
    dr = make_report(processes=[raw])
    assert dr.ontology.get_processes() == []
    assert "started time unknown" in dr.diagnostics[0]


@pytest.mark.parametrize(
    "submitted,reported,message",
    [
        ("2024-02-02T23:56:27", "2024-02-02T23:59:09Z", "timezone"),
        ("2024-02-02T23:56:27Z", "2024-02-02T23:56:26Z", "precedes"),
    ],
)
def test_invalid_analysis_window_is_explicit(submitted, reported, message):
    with pytest.raises(ValueError, match=message):
        make_report(analysis={"submitted": submitted, "reported": reported, "resource": "win7"})


def test_observed_time_at_analysis_end_is_retained():
    dr = make_report(processes=[process(started=162000, terminated=162000)])
    p = dr.ontology.get_processes()[0]
    assert p.start_time == p.end_time == "2024-02-02 23:59:09.000000"
    assert dr.diagnostics == []


def test_native_event_tree_and_ontology_share_times():
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    from assemblyline.odm.models.ontology.results import NetworkConnection as NetworkConnectionModel
    from assemblyline.odm.models.ontology.results import Process as ProcessModel

    from triage_sandbox.service import _attach_dynamic_ontology

    dr = make_report(
        processes=[process()],
        network={"flows": [flow(first_seen=3343, pid=100), flow(id=2)]},
    )
    svc = SimpleNamespace(ontology=MagicMock())
    _attach_dynamic_ontology(svc, dr.ontology)  # ty: ignore[invalid-argument-type]
    emitted = [
        (model, model(data).as_primitives())
        for model, data in (call.args for call in svc.ontology.add_result_part.call_args_list)
    ]
    exported_process = next(data for model, data in emitted if model is ProcessModel)
    exported_flows = [data for model, data in emitted if model is NetworkConnectionModel]
    assert exported_process["end_time"] is None
    assert exported_flows[0]["process"]["end_time"] is None
    assert exported_flows[1]["objectid"]["time_observed"] is None
    assert exported_process["start_time"].endswith("27.140000Z")
    assert exported_flows[0]["objectid"]["time_observed"].endswith("30.343000Z")
    tree, _ = dr.ontology.get_process_tree()
    assert tree[0]["end_time"] is None
    assert tree[0]["start_time"] == "2024-02-02 23:56:27.140000"
    assert tree[0]["children"][0]["objectid"]["time_observed"] == "2024-02-02 23:56:30.343000"
