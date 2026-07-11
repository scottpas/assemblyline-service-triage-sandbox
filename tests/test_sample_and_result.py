"""
Tests for triage_sandbox.report.Sample.get_task_reports and TriageResult.

Uses the `triage_client` fixture from conftest.py which registers all
tria.ge API endpoints on requests_mock and returns a TriageClient.
"""

import copy
import json

from triage_sandbox.report import DynamicReport, Sample, TriageResult

OVERVIEW_URL = "https://api.tria.ge/v1/samples/{id}/overview.json"

SAMPLE_ID = "240202-3y8f7sefen"


# ---------------------------------------------------------------------------
# Sample.get_task_reports tests
# ---------------------------------------------------------------------------


def test_get_task_reports_filters_non_behavioral(triage_client, sample_json):
    """static1 task must be excluded; only behavioral tasks produce reports."""
    sample = Sample(**sample_json)
    sample.get_task_reports(triage_client)

    assert len(sample.task_reports) == 2
    for report in sample.task_reports:
        assert isinstance(report, DynamicReport)
        assert report.task_id in {"behavioral1", "behavioral2"}


def test_get_task_reports_skips_failed(triage_client, sample_json):
    """A behavioral task with status 'failed' must be skipped before HTTP fetch."""
    sd = copy.deepcopy(sample_json)
    for task in sd["tasks"]:
        if task["id"] == "behavioral2":
            task["status"] = "failed"

    sample = Sample(**sd)
    sample.get_task_reports(triage_client)

    assert len(sample.task_reports) == 1
    assert sample.task_reports[0].task_id == "behavioral1"


def test_get_task_reports_filters_unexpected_fields(triage_client, sample_json):
    """
    The raw Triage report JSON may contain keys beyond DynamicReport's fields.
    get_task_reports uses an expected_fields filter so construction must not
    raise TypeError regardless of extra keys in the API response.
    """
    sample = Sample(**sample_json)
    # This must not raise TypeError despite the raw JSON having extra keys
    sample.get_task_reports(triage_client)
    assert len(sample.task_reports) == 2


def _collect_pids(items):
    """Recursively collect all process_pid values from a process tree body."""
    pids = set()
    for item in items:
        pids.add(item["process_pid"])
        pids.update(_collect_pids(item.get("children", [])))
    return pids


def test_get_task_reports_ontologies_are_isolated(triage_client, sample_json):
    """
    Each task must receive its own OntologyResults — data from one task must
    not bleed into another task's ontology.

    Verified from two angles:
    - Signatures: FABOOKIE (behavioral1) and VIDAR (behavioral2) must not cross.
    - Process trees (via get_process_tree_result_section()): behavioral1 owns
      PIDs 2104/2356 and behavioral2 owns PIDs 3104/3356; neither should appear
      in the other task's spawned-process-tree section.
    """
    sample = Sample(**sample_json)
    sample.get_task_reports(triage_client)

    b1 = next(r for r in sample.task_reports if r.task_id == "behavioral1")
    b2 = next(r for r in sample.task_reports if r.task_id == "behavioral2")

    # --- signature isolation ---
    b1_families = {f for sig in b1.ontology.get_signatures() for f in sig.malware_families}
    b2_families = {f for sig in b2.ontology.get_signatures() for f in sig.malware_families}
    assert "VIDAR" not in b1_families, "behavioral1 ontology must not contain behavioral2's VIDAR signature"
    assert "FABOOKIE" not in b2_families, "behavioral2 ontology must not contain behavioral1's FABOOKIE signature"

    # --- process tree isolation via get_process_tree_result_section() ---
    b1_tree = b1.ontology.get_process_tree_result_section()
    b2_tree = b2.ontology.get_process_tree_result_section()

    b1_pids = _collect_pids(b1_tree.section_body._data)
    b2_pids = _collect_pids(b2_tree.section_body._data)

    # behavioral1 PIDs 2104/2356 must not appear in behavioral2's tree and vice versa
    assert not {3104, 3356} & b1_pids, f"behavioral1 process tree must not contain behavioral2 PIDs; got {b1_pids}"
    assert not {2104, 2356} & b2_pids, f"behavioral2 process tree must not contain behavioral1 PIDs; got {b2_pids}"


# ---------------------------------------------------------------------------
# TriageResult tests
# ---------------------------------------------------------------------------


def test_triageresult(triage_client):
    """TriageResult must build two task reports from the fixture sample."""
    tr = TriageResult(triage_client, triage_client.sample_by_id(SAMPLE_ID))

    assert tr.sample.id == SAMPLE_ID
    assert len(tr.sample.task_reports) == 2
    assert len(tr.malware_config) > 0


def test_triageresult_malware_config_chaining(triage_client):
    """
    TriageResult.malware_config must equal the union of per-task malware_config
    lists when the overview returns no additional configs.
    """
    tr = TriageResult(triage_client, triage_client.sample_by_id(SAMPLE_ID))

    expected_total = sum(len(r.malware_config) for r in tr.sample.task_reports)
    assert len(tr.malware_config) == expected_total


# ---------------------------------------------------------------------------
# TriageResult overview recovery tests
# ---------------------------------------------------------------------------


def _make_quasar_overview(sample_id: str) -> dict:
    """Overview shaped like the real quasar sample: config absent from behavioral reports."""
    return {
        "analysis": {"family": ["quasar"], "score": 10, "tags": ["family:quasar"]},
        "extracted": [
            {
                "config": {
                    "family": "quasar",
                    "rule": "Quasar",
                    "c2": ["5.75.188.31:4782", "95.179.201.247:4782"],
                    "botnet": "Admin@Quasar",
                    "mutex": ["QSR_MUTEX_1ab34ef"],
                    "attr": {
                        "encryption_key": "B9190F8255DE3C0B619CB5B7719B9B61206842F7",
                        "key_salt": "bfeb1e56fbcd973bb219022430a57843003d5644d21e62b9d4f180e7e6c33941",
                        "install_name": "vcredist.exe",
                        "reconnect_delay": 5000,
                    },
                },
                "resource": "sample",
                "tasks": ["behavioral1"],
            }
        ],
        "signatures": [
            {
                "label": "quasar",
                "name": "Family: Quasar",
                "score": 10,
                "desc": "Quasar is a remote administration tool.",
                "tags": ["family:quasar"],
            }
        ],
    }


def test_overview_config_recovered_when_behavioral_has_none(requests_mock, sample_json):
    """
    When behavioral reports have no extracted config, TriageResult must recover
    the config from the overview report.
    Simulates the quasar scenario: behavioral tasks have empty extracted blocks.
    """
    from triage import Client as TriageClient

    # Build sample + behavioral reports with NO extracted block
    sample_no_config = copy.deepcopy(sample_json)
    b1 = _behavioral_report_no_config("behavioral1")
    b2 = _behavioral_report_no_config("behavioral2")
    overview = _make_quasar_overview(SAMPLE_ID)

    requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}", text=json.dumps(sample_no_config))
    requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/behavioral1/report_triage.json", text=json.dumps(b1))
    requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/behavioral2/report_triage.json", text=json.dumps(b2))
    requests_mock.get(f"https://api.tria.ge/v1/samples/{SAMPLE_ID}/overview.json", text=json.dumps(overview))

    client = TriageClient(token="TESTING")
    tr = TriageResult(client, client.sample_by_id(SAMPLE_ID))

    assert len(tr.overview_configs) == 1
    assert tr.overview_configs[0]["family"] == "quasar"
    # The config must land in malware_config (behavioral contributed 0)
    families = [mc.as_primitives(strip_null=True).get("family", []) for mc in tr.malware_config]
    assert any("QUASAR" in f for f in families)


def test_overview_config_skipped_when_already_in_behavioral(requests_mock, sample_json):
    """
    When a config from the overview is identical (same filtered content) to one already
    extracted from behavioral reports, it must NOT be added again (no double-scoring).
    """
    from triage import Client as TriageClient

    # Build overview with same family+c2 as what build_report() puts in behavioral
    b1_family = "fabookie"
    b1_c2 = f"http://{b1_family}.example/gate/"
    overview = {
        "extracted": [
            {
                "config": {
                    "family": b1_family,
                    "c2": [b1_c2],
                    "rule": b1_family.capitalize(),
                },
                "tasks": ["behavioral1"],
            }
        ],
        "signatures": [],
    }
    from conftest import build_report

    b1 = build_report("behavioral1", family=b1_family)
    b2 = build_report("behavioral2", family="vidar")
    requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}", text=json.dumps(sample_json))
    requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/behavioral1/report_triage.json", text=json.dumps(b1))
    requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/behavioral2/report_triage.json", text=json.dumps(b2))
    requests_mock.get(f"https://api.tria.ge/v1/samples/{SAMPLE_ID}/overview.json", text=json.dumps(overview))

    client = TriageClient(token="TESTING")
    tr = TriageResult(client, client.sample_by_id(SAMPLE_ID))

    # No overview configs should be added (identical to behavioral1's fabookie config)
    assert tr.overview_configs == []
    # Total malware_config count must equal only what behavioral reports produced (2 tasks)
    behavioral_total = sum(len(r.malware_config) for r in tr.sample.task_reports)
    assert len(tr.malware_config) == behavioral_total


def test_overview_signatures_recovered_when_absent_from_behavioral(requests_mock, sample_json):
    """Overview-only signatures must be captured in overview_signatures."""
    from triage import Client as TriageClient

    b1 = _behavioral_report_no_config("behavioral1")
    b2 = _behavioral_report_no_config("behavioral2")
    overview = _make_quasar_overview(SAMPLE_ID)

    requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}", text=json.dumps(sample_json))
    requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/behavioral1/report_triage.json", text=json.dumps(b1))
    requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/behavioral2/report_triage.json", text=json.dumps(b2))
    requests_mock.get(f"https://api.tria.ge/v1/samples/{SAMPLE_ID}/overview.json", text=json.dumps(overview))

    client = TriageClient(token="TESTING")
    tr = TriageResult(client, client.sample_by_id(SAMPLE_ID))

    assert len(tr.overview_signatures) == 1
    assert tr.overview_signatures[0]["label"] == "quasar"
    assert tr.overview_signatures[0].get("desc") == "Quasar is a remote administration tool."


def test_overview_error_is_non_fatal(requests_mock, sample_json):
    """A 404 or error from overview_report must not crash TriageResult."""
    from conftest import build_report
    from triage import Client as TriageClient

    b1 = build_report("behavioral1")
    b2 = build_report("behavioral2", family="vidar")
    requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}", text=json.dumps(sample_json))
    requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/behavioral1/report_triage.json", text=json.dumps(b1))
    requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/behavioral2/report_triage.json", text=json.dumps(b2))
    requests_mock.get(f"https://api.tria.ge/v1/samples/{SAMPLE_ID}/overview.json", status_code=404)

    client = TriageClient(token="TESTING")
    tr = TriageResult(client, client.sample_by_id(SAMPLE_ID))

    # Must not raise; behavioral configs still collected
    assert len(tr.sample.task_reports) == 2
    assert tr.overview_configs == []


def test_invalid_overview_config_is_non_fatal(requests_mock, sample_json):
    """Malformed best-effort overview configs must not discard behavioral results."""
    from conftest import build_report
    from triage import Client as TriageClient

    b1 = build_report("behavioral1")
    b2 = build_report("behavioral2", family="vidar")
    overview = {
        "extracted": [{"config": {"family": 123}, "tasks": ["behavioral1"]}],
        "signatures": [],
    }
    requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}", text=json.dumps(sample_json))
    requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/behavioral1/report_triage.json", text=json.dumps(b1))
    requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/behavioral2/report_triage.json", text=json.dumps(b2))
    requests_mock.get(f"https://api.tria.ge/v1/samples/{SAMPLE_ID}/overview.json", text=json.dumps(overview))

    tr = TriageResult(TriageClient(token="TESTING"), sample_json)

    assert len(tr.sample.task_reports) == 2
    assert tr.overview_configs == []


# ---------------------------------------------------------------------------
# Helpers for overview tests
# ---------------------------------------------------------------------------


def _behavioral_report_no_config(task_id: str) -> dict:
    """Behavioral report with empty signatures and no extracted config (like quasar)."""
    pid = 2104 if task_id == "behavioral1" else 3104
    return {
        "version": "0.3.0",
        "sample": {
            "id": SAMPLE_ID,
            "score": 10,
            "target": "sample.exe",
            "size": 2048,
            "md5": "0" * 32,
            "sha1": "0" * 40,
            "sha256": "0" * 64,
            "sha512": "0" * 128,
            "ssdeep": "48:abc",
            "static_tags": [],
            "submitted": "2024-02-02T23:56:27Z",
        },
        "task": {
            "target": "sample.exe",
            "size": 2048,
            "md5": "0" * 32,
            "sha1": "0" * 40,
            "sha256": "0" * 64,
            "sha512": "0" * 128,
            "ssdeep": "48:abc",
            "static_tags": [],
        },
        "analysis": {
            "score": 10,
            "submitted": "2024-02-02T23:56:27Z",
            "reported": "2024-02-02T23:59:09Z",
            "resource": "win7-20231215-en",
            "platform": "windows7_x64",
            "tags": [],
            "resource_tags": [],
            "features": [],
            "backend": "host",
            "max_time_kernel": 180,
            "max_time_network": 180,
        },
        "processes": [
            {
                "procid": 1,
                "procid_parent": 0,
                "pid": pid,
                "ppid": 1220,
                "image": "C:\\Windows\\vcredist.exe",
                "cmd": '"C:\\Windows\\vcredist.exe"',
                "orig": True,
                "started": 154,
            }
        ],
        "signatures": [],
        "network": {"flows": [], "requests": []},
        "extracted": [],
        "dumped": [],
        "tags": [],
    }


# ---------------------------------------------------------------------------
# Regression: unknown Triage sample fields must not crash TriageResult (issue #48)
# ---------------------------------------------------------------------------


def test_triageresult_tolerates_unknown_sample_fields(triage_client, sample_json):
    """
    Triage API may add new top-level sample fields (e.g. user_id) that the
    Sample dataclass doesn't declare.  TriageResult must filter unknown keys
    before constructing Sample so it never raises TypeError.
    """
    import copy

    sample_with_extras = copy.deepcopy(sample_json)
    sample_with_extras["user_id"] = "u-abc123"  # the field from issue #48
    sample_with_extras["_future_field"] = "some-value"  # guard against the next one too

    # Must not raise TypeError: Sample.__init__() got an unexpected keyword argument 'user_id'
    tr = TriageResult(triage_client, sample_with_extras)
    assert tr.sample.id == sample_json["id"]
