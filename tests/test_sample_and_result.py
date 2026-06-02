"""
Tests for helper.Sample.get_task_reports and helper.TriageResult.

Uses the `triage_client` fixture from conftest.py which registers all
tria.ge API endpoints on requests_mock and returns a TriageClient.
"""

import copy

from assemblyline_service_utilities.common.dynamic_service_helper import OntologyResults

from helper import DynamicReport, Sample, TriageResult

SAMPLE_ID = "240202-3y8f7sefen"


# ---------------------------------------------------------------------------
# Sample.get_task_reports tests
# ---------------------------------------------------------------------------


def test_get_task_reports_filters_non_behavioral(triage_client, sample_json):
    """static1 task must be excluded; only behavioral tasks produce reports."""
    sample = Sample(**sample_json)
    sample.get_task_reports(triage_client, OntologyResults(service_name="Triage"))

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
    sample.get_task_reports(triage_client, OntologyResults(service_name="Triage"))

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
    sample.get_task_reports(triage_client, OntologyResults(service_name="Triage"))
    assert len(sample.task_reports) == 2


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
