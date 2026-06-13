"""
Tests for triage_sandbox.report.Sample.get_task_reports and TriageResult.

Uses the `triage_client` fixture from conftest.py which registers all
tria.ge API endpoints on requests_mock and returns a TriageClient.
"""

import copy

from triage_sandbox.report import DynamicReport, Sample, TriageResult

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
    lists, confirming itertools.chain(*...) wiring.
    """
    tr = TriageResult(triage_client, triage_client.sample_by_id(SAMPLE_ID))

    expected_total = sum(len(r.malware_config) for r in tr.sample.task_reports)
    assert len(tr.malware_config) == expected_total
