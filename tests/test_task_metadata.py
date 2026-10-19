"""Task identity, sandbox machine metadata and completeness diagnostics."""

from typing import Any

import pytest
from assemblyline.odm.models.ontology.results import Sandbox as SandboxModel
from conftest import SAMPLE_ID, build_overview, build_report, build_sample
from test_dynamic_report import make_report
from test_service_integration import find_subsection

from triage_sandbox.report import TriageResult, _diagnostic_text, _machine_platform

OVERVIEW_URL = f"https://api.tria.ge/v1/samples/{SAMPLE_ID}/overview.json"


def report_url(task_id: str) -> str:
    return f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/{task_id}/report_triage.json"


def sandbox_metadata(dr) -> dict[str, Any]:
    (sandbox,) = dr.ontology.get_sandboxes()
    prims = sandbox.as_primitives()
    # Must remain a valid ODM object, including unsupported architectures.
    SandboxModel(prims)
    return prims["analysis_metadata"]


def table_rows(section) -> list[dict[str, Any]]:
    import json

    return json.loads(section.body)


# ---------------------------------------------------------------------------
# Machine metadata (#121)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "label, expected",
    [
        ("windows7_x64", ("Windows", "7", "x64")),
        ("windows10-2004_x64", ("Windows", "10-2004", "x64")),
        ("windows11-ltsc_2024_x64", ("Windows", "11-ltsc_2024", "x64")),
        ("windows10-2004-x64", ("Windows", "10-2004", "x64")),
        ("android-9_x86", ("Android", "9", "x86")),
        ("android_x86_64", ("Android", None, "x64")),
        ("android_x86", ("Android", None, "x86")),
        ("linux_amd64", ("Linux", None, "x64")),
        ("macos_amd64", ("MacOS", None, "x64")),
        ("macos-10.15_amd64", ("MacOS", "10.15", "x64")),
        ("ubuntu-18.04_amd64", ("Linux", "ubuntu-18.04", "x64")),
        ("debian-9_mips", ("Linux", "debian-9", None)),
        ("debian-12_armhf", ("Linux", "debian-12", None)),
        ("linux_mipsel", ("Linux", None, None)),
        ("debian-12_armel", ("Linux", "debian-12", None)),
        ("debian-9_mips64", ("Linux", "debian-9", None)),
        ("Windows10", ("Windows", "10", None)),
        ("freebsd-13_x64", (None, None, "x64")),
        ("", (None, None, None)),
        (None, (None, None, None)),
        (64, (None, None, None)),
    ],
)
def test_machine_platform_normalization(label, expected):
    assert _machine_platform(label) == expected


def test_sandbox_metadata_from_platform():
    dr = make_report(
        analysis={
            "submitted": "2024-02-02T23:56:27Z",
            "reported": "2024-02-02T23:59:09Z",
            "resource": "win10v2004-20260513-en",
            "platform": "windows10-2004_x64",
        }
    )
    metadata = sandbox_metadata(dr)
    assert metadata["task_id"] == "sample123-behavioral1"
    assert metadata["machine_metadata"] == {
        "ip": None,
        "hypervisor": None,
        # A resource names the VM image profile, not a measured hostname.
        "hostname": None,
        "platform": "Windows",
        "version": "10-2004",
        "architecture": "x64",
    }
    assert dr.platform_label == "windows10-2004_x64"
    assert dr.platform_text == "Windows, version 10-2004, x64 (windows10-2004_x64)"


def test_unsupported_architecture_stays_raw_evidence():
    dr = make_report(
        analysis={
            "submitted": "2024-02-02T23:56:27Z",
            "reported": "2024-02-02T23:59:09Z",
            "platform": "debian-9_mips",
        }
    )
    machine = sandbox_metadata(dr)["machine_metadata"]
    assert (machine["platform"], machine["version"], machine["architecture"]) == ("Linux", "debian-9", None)
    assert dr.platform_text == "Linux, version debian-9 (debian-9_mips)"


def test_resource_tag_platform_fallback():
    dr = make_report(
        analysis={
            "submitted": "2024-02-02T23:56:27Z",
            "reported": "2024-02-02T23:59:09Z",
            "resource_tags": ["system", 5, "os:android-11-x64", "os:ignored"],
        }
    )
    machine = sandbox_metadata(dr)["machine_metadata"]
    assert (machine["platform"], machine["version"], machine["architecture"]) == ("Android", "11", "x64")
    assert dr.platform_label == "android-11-x64"


@pytest.mark.parametrize("platform", [None, "", 7, "plan9"])
def test_missing_platform_fabricates_nothing(platform):
    analysis: dict[str, Any] = {"submitted": "2024-02-02T23:56:27Z", "reported": "2024-02-02T23:59:09Z"}
    if platform is not None:
        analysis["platform"] = platform
    dr = make_report(analysis=analysis)
    machine = sandbox_metadata(dr)["machine_metadata"]
    assert all(value is None for value in machine.values())
    assert dr.platform_text == ("plan9" if platform == "plan9" else None)


def test_tasks_with_identical_times_have_distinct_sandbox_objects():
    first, second = make_report(), make_report(task_id="behavioral2")
    oids = {r.ontology.get_sandboxes()[0].objectid.ontology_id for r in (first, second)}
    assert len(oids) == 2


def test_exported_sandbox_matches_task_section(triage_service, triage_client, make_request):
    request = make_request()
    triage_service.execute(request)
    exported: dict[str, Any] = {"file": {}, "results": {}}
    triage_service.ontology.attach_parts(exported)
    sandboxes = {s["analysis_metadata"]["task_id"]: s for s in exported["results"]["sandbox"]}
    assert set(sandboxes) == {f"{SAMPLE_ID}-behavioral1", f"{SAMPLE_ID}-behavioral2"}
    machine = sandboxes[f"{SAMPLE_ID}-behavioral1"]["analysis_metadata"]["machine_metadata"]
    assert (machine["platform"], machine["version"], machine["architecture"]) == ("Windows", "7", "x64")
    task = find_subsection(request.result.sections[0], "Task: behavioral1")
    assert "Platform: Windows, version 7, x64 (windows7_x64)" in task.body
    assert "Resource: win7-20231215-en" in task.body


# ---------------------------------------------------------------------------
# Task target and selection (#119)
# ---------------------------------------------------------------------------


def multi_target(requests_mock):
    sample = build_sample()
    sample["tasks"][1].update(target="a.exe", pick="static1/unpack001/one/a.exe")
    sample["tasks"][2].update(target="a.exe", pick="static1/unpack001/two/a.exe")
    sample["tasks"].append({"id": "behavioral3", "status": "failed", "target": "b.dll", "pick": "static1/b.dll"})
    b1, b2 = build_report("behavioral1"), build_report("behavioral2")
    b1["task"].update(target="a.exe", pick="static1/unpack001/one/a.exe")
    b2["task"] = {}  # older reports: target comes from the sample's task list
    b2["analysis"]["platform"] = "windows10-2004_x64"
    requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}", json=sample)
    requests_mock.get(report_url("behavioral1"), json=b1)
    requests_mock.get(report_url("behavioral2"), json=b2)
    requests_mock.get(report_url("behavioral3"), status_code=404)
    overview = build_overview()
    overview["tasks"] = {
        f"{SAMPLE_ID}-behavioral3": {
            "name": "behavioral3",
            "kind": "behavioral",
            "status": "failed",
            "os": "debian-9-mips",
            "failure": "Failed to schedule task (check tags)",
        },
        f"{SAMPLE_ID}-behavioral4": {
            "name": "behavioral4",
            "status": "reported",
            "target": "c.sh",
            "platform": "linux_amd64",
            "resource": "ubuntu1804",
        },
        f"{SAMPLE_ID}-static1": {"name": "static1", "kind": "static", "status": "reported"},
        "malformed": "not a task",
    }
    requests_mock.get(OVERVIEW_URL, json=overview)
    return sample


def test_task_summary_lists_each_target_and_selection(triage_service, triage_client, requests_mock, make_request):
    multi_target(requests_mock)
    request = make_request()
    triage_service.execute(request)
    sandbox = request.result.sections[0]
    summary = find_subsection(sandbox, "Analysis tasks")
    assert table_rows(summary) == [
        {
            "Task": "behavioral1",
            "Target": "a.exe",
            "Selection": "static1/unpack001/one/a.exe",
            "Platform": "windows7_x64",
            "Resource": "win7-20231215-en",
            "Status": "reported",
        },
        {
            "Task": "behavioral2",
            "Target": "a.exe",
            "Selection": "static1/unpack001/two/a.exe",
            "Platform": "windows10-2004_x64",
            "Resource": "win7-20231215-en",
            "Status": "reported",
        },
        {
            "Task": "behavioral3",
            "Target": "b.dll",
            "Selection": "static1/b.dll",
            "Platform": "debian-9-mips",
            "Resource": "",
            "Status": "failed",
        },
        {
            "Task": "behavioral4",
            "Target": "c.sh",
            "Selection": "",
            "Platform": "linux_amd64",
            "Resource": "ubuntu1804",
            "Status": "reported",
        },
    ]
    titles = [s.title_text for s in sandbox.subsections]
    assert "Task: behavioral1 - a.exe (windows7_x64)" in titles
    assert "Task: behavioral2 - a.exe (windows10-2004_x64)" in titles
    b1 = find_subsection(sandbox, "Task: behavioral1")
    assert "Target: a.exe" in b1.body
    assert "Selection: static1/unpack001/one/a.exe" in b1.body
    # Same target on different platforms remains distinguishable.
    b2 = find_subsection(sandbox, "Task: behavioral2")
    assert "Selection: static1/unpack001/two/a.exe" in b2.body
    assert "Platform: Windows, version 10-2004, x64" in b2.body


@pytest.mark.parametrize(
    "target, platform, expected",
    [
        (None, "windows7_x64", "Task: behavioral1 (windows7_x64)"),
        ("a.exe", None, "Task: behavioral1 - a.exe"),
        (None, None, "Task: behavioral1"),
    ],
)
def test_task_label_with_incomplete_information(triage_client, requests_mock, target, platform, expected):
    sample = build_sample()
    sample["tasks"][1].pop("target")
    report = build_report("behavioral1")
    report["task"] = {"target": target} if target else {"target": ["not", "text"]}
    report["analysis"].pop("platform")
    if platform:
        report["analysis"]["platform"] = platform
    requests_mock.get(report_url("behavioral1"), json=report)
    result = TriageResult(triage_client, sample)
    assert result.task_label("behavioral1") == expected.removeprefix("Task: ")
    assert result.task_label("unknown") == "unknown"


def test_overview_evidence_names_contributing_targets(triage_service, triage_client, requests_mock, make_request):
    overview = build_overview(signatures=[{"label": "overview_only", "score": 5}, {"name": "untargeted"}])
    overview["extracted"] = [
        {"config": {"family": "overview_family"}, "tasks": ["behavioral1", "static1", 5]},
        {"config": {"family": "no_tasks"}, "tasks": "behavioral1"},
    ]
    overview["targets"] = [
        {
            "target": "sample.exe",
            "tasks": ["behavioral1", "behavioral2"],
            "signatures": [{"label": "overview_only"}, {"name": "overview_only"}],
        },
        {"target": "other.exe", "tasks": [], "signatures": [{"name": "overview_only"}, "bad"]},
        {"signatures": [{"label": "overview_only"}]},
        "malformed",
    ]
    requests_mock.get(OVERVIEW_URL, json=overview)
    request = make_request()
    triage_service.execute(request)
    sandbox = request.result.sections[0]
    signature = find_subsection(find_subsection(sandbox, "Overview"), "OVERVIEW_ONLY")
    assert "Observed in: sample.exe (behavioral1, behavioral2); other.exe" in signature.body
    assert "Observed in" not in (find_subsection(sandbox, "UNTARGETED").body or "")
    config = find_subsection(find_subsection(sandbox, "Overview"), "OVERVIEW_FAMILY")
    assert {"Field": "Tasks", "Value": "behavioral1 - sample.exe (windows7_x64), static1"} in table_rows(config)
    no_tasks = find_subsection(find_subsection(sandbox, "Overview"), "NO_TASKS")
    assert all(row["Field"] != "Tasks" for row in table_rows(no_tasks))


def test_static_only_sample_has_no_task_summary(triage_service, triage_client, requests_mock, make_request):
    sample = build_sample()
    sample["tasks"] = sample["tasks"][:1]
    requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}", json=sample)
    request = make_request()
    triage_service.execute(request)
    assert find_subsection(request.result.sections[0], "Analysis tasks") is None


def test_extracted_artifacts_name_their_target(triage_service, triage_client, requests_mock, make_request):
    for task in ("behavioral1", "behavioral2"):
        requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/{task}/dump.pcapng", content=b"pcap")
    request = make_request(extract_pcap=True)
    triage_service.execute(request)
    descriptions = [call.kwargs["description"] for call in request.add_extracted.call_args_list]
    assert f"PCAP file from task {SAMPLE_ID}-behavioral1 (sample.exe)" in descriptions


# ---------------------------------------------------------------------------
# Completeness diagnostics (#118)
# ---------------------------------------------------------------------------


def test_overview_errors_and_task_failures_reach_completeness(
    triage_service, triage_client, requests_mock, make_request
):
    multi_target(requests_mock)
    b1 = build_report("behavioral1")
    b1["errors"] = [{"reason": "Machine shutdown"}, {"reason": "Machine shutdown"}, "malformed"]
    requests_mock.get(report_url("behavioral1"), json=b1)
    request_overview = {
        **build_overview(),
        "tasks": {
            f"{SAMPLE_ID}-behavioral3": {"name": "behavioral3", "failure": "Failed to schedule task (check tags)"}
        },
        "errors": [
            {"task": "behavioral3", "reason": "Failed to schedule task (check tags)"},
            {"task": "behavioral1", "reason": "machine shutdown"},
            {"task": "behavioral2", "reason": "Payload did not run: futex\nSIGSEGV: segmentation violation"},
            {"reason": "Sample could not be unpacked"},
            {"task": "behavioral2"},
            "malformed",
        ],
    }
    requests_mock.get(OVERVIEW_URL, json=request_overview)
    request = make_request()
    triage_service.execute(request)
    lines = find_subsection(request.result.sections[0], "Analysis completeness").body.splitlines()
    assert "Task behavioral3: failed execution (Failed to schedule task (check tags)); analysis incomplete." in lines
    assert "Task behavioral3: report unavailable (HTTP 404)." in lines
    assert "Task behavioral1: analysis error: Machine shutdown" in lines
    assert "Task behavioral2: analysis error: Payload did not run: futex" in lines
    assert "Overview: analysis error: Sample could not be unpacked" in lines
    body = "\n".join(lines)
    # Equivalent reasons for one task appear once; raw multi-line details are not dumped.
    assert body.lower().count("machine shutdown") == 1
    assert body.count("Failed to schedule task") == 1
    assert "SIGSEGV" not in body
    assert "reason unavailable" not in body


@pytest.mark.parametrize(
    "errors, expected",
    [
        (None, []),
        ("bad", []),
        ({"task": "behavioral1"}, []),
        ([None, 5, {"reason": ["x"]}], ["Overview: analysis error: unspecified analysis error"]),
    ],
)
def test_malformed_overview_errors_do_not_block_result(triage_client, requests_mock, errors, expected):
    requests_mock.get(OVERVIEW_URL, json={"errors": errors, "tasks": ["malformed"]})
    result = TriageResult(triage_client, build_sample())
    assert len(result.sample.task_reports) == 2
    assert [d for d in result.diagnostics if "analysis error" in d] == expected


def test_parse_rejection_survives_recovery(triage_client, requests_mock):
    requests_mock.get(report_url("behavioral1"), json={"analysis": {}})
    requests_mock.get(OVERVIEW_URL, json=build_overview(signatures=[{"label": "recovered"}]))
    result = TriageResult(triage_client, build_sample())
    assert [r.task_id for r in result.sample.task_reports] == ["behavioral2"]
    assert result.overview_signatures == [{"label": "recovered"}]
    assert any(d.startswith("Task behavioral1: report could not be parsed") for d in result.diagnostics)


@pytest.mark.parametrize(
    "value, expected",
    [
        ("  Machine shutdown  ", "Machine shutdown"),
        ("\n\nfirst line\nsecond line", "first line"),
        ("x" * 300, "x" * 197 + "..."),
        ("  \n ", None),
        (None, None),
        (["list"], None),
    ],
)
def test_diagnostic_text(value, expected):
    assert _diagnostic_text(value) == expected
