"""
Integration tests for TriageSandbox.execute(), search_triage(), and submit_triage().
"""

import json
import os
import re
import tempfile
from types import SimpleNamespace

import pytest
import requests
from requests import utils as req_utils
from retrying import Attempt, RetryError
from triage.client import ServerError

SAMPLE_ID = "240202-3y8f7sefen"
SAMPLE_SHA256 = "7d50e22081955b574b989561277ce0e835117e716817736373ac8799774b6f03"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def find_subsection(section, substr):
    """Recursively find the first subsection whose title_text contains substr."""
    for sub in section.subsections:
        if substr in sub.title_text:
            return sub
        found = find_subsection(sub, substr)
        if found is not None:
            return found
    return None


# ---------------------------------------------------------------------------
# search_triage / submit_triage tests
# (set svc.client = triage_client; methods use self.client)
# ---------------------------------------------------------------------------


def test_search_triage_by_sha256_found(triage_service, triage_client, make_request):
    """search_triage finds an existing sample by sha256 and returns its id."""
    svc = triage_service
    svc.client = triage_client
    req = make_request()
    result = svc.search_triage(req)
    assert result is not None
    assert result["id"] == SAMPLE_ID


def test_search_triage_by_url(triage_service, triage_client, requests_mock, make_request):
    """search_triage with uri_info+submit_as_url searches by url query."""
    svc = triage_service
    svc.client = triage_client
    uri = "http://mal.test/x"
    encoded = req_utils.quote(f'url:"{uri}"')
    requests_mock.get(
        f"https://api.tria.ge/v0/search?query={encoded}&limit=1",
        json={"data": [{"id": SAMPLE_ID}], "next": None},
    )
    req = make_request(uri_info=SimpleNamespace(uri=uri), submit_as_url=True)
    result = svc.search_triage(req)
    assert result is not None
    assert result["id"] == SAMPLE_ID


def test_search_triage_not_found_returns_none(triage_service, triage_client, requests_mock, make_request):
    """search_triage swallows StopIteration and returns None when no results exist."""
    svc = triage_service
    svc.client = triage_client
    encoded = req_utils.quote(f"sha256:{SAMPLE_SHA256}")
    requests_mock.get(
        f"https://api.tria.ge/v0/search?query={encoded}&limit=1",
        json={"data": [], "next": None},
    )
    req = make_request()
    result = svc.search_triage(req)
    assert result is None


def test_submit_triage_url(triage_service, triage_client, requests_mock, make_request):
    """submit_triage posts a URL submission and returns the response."""
    svc = triage_service
    svc.client = triage_client
    uri = "http://mal.test/x"
    requests_mock.post(
        "https://api.tria.ge/v0/samples",
        json={"id": "newid", "status": "pending"},
    )
    req = make_request(uri_info=SimpleNamespace(uri=uri), submit_as_url=True)
    result = svc.submit_triage(req)
    assert result is not None
    assert result["id"] == "newid"


def test_submit_triage_file(triage_service, triage_client, requests_mock, make_request):
    """submit_triage POSTs a file for a supported file type and returns the response."""
    svc = triage_service
    svc.client = triage_client
    requests_mock.post(
        "https://api.tria.ge/v0/samples",
        json={"id": "fileid", "status": "pending"},
    )
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
        tmp.write(b"MZ\x90\x00test")
        tmp_path = tmp.name
    try:
        req = make_request(file_type="executable/windows/pe32", file_path=tmp_path)
        result = svc.submit_triage(req)
        assert result is not None
        assert result["id"] == "fileid"
    finally:
        os.unlink(tmp_path)


def test_submit_triage_unsupported_returns_none(triage_service, triage_client, make_request):
    """submit_triage returns None for unsupported file types."""
    svc = triage_service
    svc.client = triage_client
    req = make_request(file_type="unsupported/type", uri_info=None)
    result = svc.submit_triage(req)
    assert result is None


# ---------------------------------------------------------------------------
# execute() tests — use triage_service + make_request + mock_triage_api
# ---------------------------------------------------------------------------


def test_execute_happy_path_builds_sandbox_section(triage_service, make_request, mock_triage_api):
    """execute() sets request.result with a 'Sandbox Information' section containing task subsections."""
    svc = triage_service
    req = make_request()
    svc.execute(req)

    assert req.result is not None
    sections = req.result.sections
    assert len(sections) >= 1

    sandbox_section = sections[0]
    assert sandbox_section.title_text == "Sandbox Information"

    # Body should contain URL, Submitted, Completed lines
    body = sandbox_section.body or ""
    assert "URL:" in body
    assert "Submitted:" in body
    assert "Completed:" in body

    task_ids = {s.title_text for s in sandbox_section.subsections}
    assert "Task: behavioral1" in task_ids
    assert "Task: behavioral2" in task_ids


def test_execute_signatures_section_and_heuristics(triage_service, make_request, mock_triage_api):
    """Each task section contains a Signatures subsection whose entries have heur_ids in {1,2,3,4,5}."""
    svc = triage_service
    req = make_request()
    svc.execute(req)

    sandbox_section = req.result.sections[0]
    for task_section in sandbox_section.subsections:
        sigs = find_subsection(task_section, "Signatures")
        assert sigs is not None, f"No Signatures subsection in {task_section.title_text}"
        assert len(sigs.subsections) >= 1, f"Signatures section has no entries in {task_section.title_text}"
        for sig_sub in sigs.subsections:
            assert sig_sub.heuristic is not None, f"Signature '{sig_sub.title_text}' has no heuristic"
            assert sig_sub.heuristic.heur_id in {1, 2, 3, 4, 5}, (
                f"Unexpected heur_id {sig_sub.heuristic.heur_id} for '{sig_sub.title_text}'"
            )


def test_execute_network_iocs_section(triage_service, make_request, mock_triage_api):
    """Each task section contains a Network IOCs subsection."""
    svc = triage_service
    req = make_request()
    svc.execute(req)

    sandbox_section = req.result.sections[0]
    for task_section in sandbox_section.subsections:
        ioc = find_subsection(task_section, "Network IOCs")
        assert ioc is not None, f"No 'Network IOCs' subsection in {task_section.title_text}"


def test_execute_malware_config_section(triage_service, make_request, mock_triage_api):
    """Each task section contains a Malware Config subsection with at least one family table (heur_id 100)."""
    svc = triage_service
    req = make_request()
    svc.execute(req)

    sandbox_section = req.result.sections[0]
    for task_section in sandbox_section.subsections:
        mc = find_subsection(task_section, "Malware Config")
        assert mc is not None, f"No 'Malware Config' subsection in {task_section.title_text}"
        assert len(mc.subsections) >= 1, f"Malware Config has no family entries in {task_section.title_text}"
        family_table = mc.subsections[0]
        assert family_table.heuristic is not None, "Family table has no heuristic"
        assert family_table.heuristic.heur_id == 100


def test_execute_attack_ids_on_signature_heuristics(triage_service, make_request, mock_triage_api):
    """
    ATT&CK techniques from signatures with TTPs must be attached to their signature
    subsection heuristics, NOT in a standalone 'ATT&CK Techniques' section.

    The fixture family signature carries ttp:['T1082'] (conftest.py:140-146).
    After execution: at least one signature subsection in each task must have T1082
    in its heuristic attack_ids, and no standalone 'ATT&CK Techniques' section may exist.
    """
    svc = triage_service
    req = make_request()
    svc.execute(req)

    sandbox_section = req.result.sections[0]
    for task_section in sandbox_section.subsections:
        # Standalone section must be gone
        ttp_standalone = find_subsection(task_section, "ATT&CK Techniques")
        assert ttp_standalone is None, (
            f"Standalone 'ATT&CK Techniques' section must not exist in {task_section.title_text}"
        )

        # At least one signature subsection must carry T1082 on its heuristic
        sigs = find_subsection(task_section, "Signatures")
        assert sigs is not None, f"No Signatures subsection in {task_section.title_text}"
        attack_ids_found = set()
        for sig_sub in sigs.subsections:
            if sig_sub.heuristic and sig_sub.heuristic.attack_ids:
                attack_ids_found.update(sig_sub.heuristic.attack_ids)
        assert "T1082" in attack_ids_found, (
            f"Expected T1082 in signature heuristic attack_ids for {task_section.title_text}; got {attack_ids_found}"
        )


def test_execute_pcap_extraction(triage_service, make_request, mock_triage_api):
    """execute() extracts PCAP files when extract_pcap=True."""
    svc = triage_service
    # Register the pcap endpoints
    mock_triage_api.get(
        f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/behavioral1/dump.pcapng",
        content=b"PCAPDATA",
    )
    mock_triage_api.get(
        f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/behavioral2/dump.pcapng",
        content=b"PCAPDATA",
    )

    req = make_request(extract_pcap=True)
    svc.execute(req)

    calls = req.add_extracted.call_args_list
    assert len(calls) >= 1
    names = [c.kwargs.get("name", "") or (c.args[1] if len(c.args) > 1 else "") for c in calls]
    assert any(n.endswith("dump.pcapng") for n in names), f"No dump.pcapng in add_extracted calls: {names}"


def test_execute_memdump_extraction(triage_service, make_request, mock_triage_api):
    """execute() extracts memory dump files when extract_memdump=True."""
    svc = triage_service

    mock_triage_api.get(
        re.compile(r"https://api\.tria\.ge/v0/samples/.+/.+/memory/.+\.dmp"),
        content=b"MEMDUMPDATA",
    )

    req = make_request(extract_memdump=True)
    svc.execute(req)

    calls = req.add_extracted.call_args_list
    assert len(calls) >= 1, "add_extracted was never called"
    descriptions = [c.kwargs.get("description", "") or (c.args[2] if len(c.args) > 2 else "") for c in calls]
    assert any("Memdump" in d for d in descriptions), f"No Memdump description in add_extracted calls: {descriptions}"


def test_execute_dropped_files_extraction(triage_service, make_request, mock_triage_api):
    """execute() extracts dropped files when extract_dropped_files=True."""
    svc = triage_service

    mock_triage_api.get(
        re.compile(r"https://api\.tria\.ge/v0/samples/.+/.+/files/.+\.dat"),
        content=b"DROPPEDDATA",
    )

    req = make_request(extract_dropped_files=True)
    svc.execute(req)

    calls = req.add_extracted.call_args_list
    assert len(calls) >= 1, "add_extracted was never called"
    descriptions = [c.kwargs.get("description", "") or (c.args[2] if len(c.args) > 2 else "") for c in calls]
    assert any("Dropped" in d for d in descriptions), f"No Dropped description in add_extracted calls: {descriptions}"


def test_execute_not_found_returns_none(triage_service, make_request, mock_triage_api):
    """execute() returns None (and leaves request.result unset) when the sample is not found."""
    svc = triage_service
    encoded = req_utils.quote(f"sha256:{SAMPLE_SHA256}")
    mock_triage_api.get(
        f"https://api.tria.ge/v0/search?query={encoded}&limit=1",
        json={"data": [], "next": None},
    )
    req = make_request(allow_dynamic_submit=False)
    result = svc.execute(req)
    assert result is None
    assert req.result is None


def test_execute_server_error_reraised(triage_service, make_request, mock_triage_api):
    """execute() re-raises ServerError from the Triage API (e.g. 500 response)."""
    svc = triage_service
    encoded = req_utils.quote(f"sha256:{SAMPLE_SHA256}")
    # Override the search endpoint with a 500 response
    mock_triage_api.get(
        f"https://api.tria.ge/v0/search?query={encoded}&limit=1",
        status_code=500,
        json={"error": "internal_error", "message": "server failed"},
    )
    req = make_request()
    with pytest.raises(ServerError):
        svc.execute(req)


def test_execute_retry_error_reraised(triage_service, make_request, mock_triage_api, monkeypatch):
    """execute() re-raises RetryError when wait_for_submission exhausts retries."""
    retry_err = RetryError(Attempt(ValueError("timeout"), 1, True))

    def _raise_retry(*args, **kwargs):
        raise retry_err

    monkeypatch.setattr("triage_sandbox.service.wait_for_submission", _raise_retry)

    req = make_request()
    with pytest.raises(RetryError):
        triage_service.execute(req)


def test_execute_web_url_default(triage_service):
    """TriageSandbox derives web_url from root_url by stripping 'api.' prefix."""
    assert triage_service.web_url == "https://tria.ge"


def test_start_logs_service_name(triage_service):
    """start() must not raise and should reference the configured service name."""
    triage_service.start()


# ---------------------------------------------------------------------------
# Overview rendering (service.py execute(): "Overview" section)
# ---------------------------------------------------------------------------


def test_execute_overview_signatures_rendered_with_heuristics_family_and_ttps(
    triage_service, make_request, mock_triage_api
):
    """Overview signatures must render under Overview -> Signatures with the correct
    heuristic tier per score, an attribution.family tag from 'family:' tags, known-TTP
    attack ids (unknown TTPs ignored), and a description line when present."""
    from conftest import build_overview

    overview = build_overview(
        signatures=[
            {"label": "sig5", "score": 10, "tags": ["family:emotet"], "ttp": ["T1082", "T9999999"], "desc": "d5"},
            {"label": "sig4", "score": 8},
            {"label": "sig3", "score": 5},
            {"label": "sig2", "score": 1},
            {"name": "Sig Zero", "score": 0},
        ]
    )
    mock_triage_api.get(f"https://api.tria.ge/v1/samples/{SAMPLE_ID}/overview.json", json=overview)

    req = make_request()
    triage_service.execute(req)

    sandbox_section = req.result.sections[0]
    overview_section = find_subsection(sandbox_section, "Overview")
    assert overview_section is not None
    sigs_section = find_subsection(overview_section, "Signatures")
    assert sigs_section is not None

    by_title = {s.title_text: s for s in sigs_section.subsections}
    assert by_title["SIG5"].heuristic.heur_id == 5
    assert by_title["SIG4"].heuristic.heur_id == 4
    assert by_title["SIG3"].heuristic.heur_id == 3
    assert by_title["SIG2"].heuristic.heur_id == 2
    assert by_title["SIG ZERO"].heuristic.heur_id == 1  # name-derived title, zero score

    assert by_title["SIG5"].tags.get("attribution.family") == ["EMOTET"]
    assert "T1082" in by_title["SIG5"].heuristic.attack_ids
    assert "T9999999" not in by_title["SIG5"].heuristic.attack_ids
    assert "d5" in (by_title["SIG5"].body or "")

    # No description supplied -> no line added (falsy sig.get("desc") branch)
    assert not (by_title["SIG4"].body or "")


def test_execute_overview_signature_yara_rule_preferred_over_name(triage_service, make_request, mock_triage_api):
    """A static YARA match with no 'label' must be titled by its short yara_rule
    identifier, not the verbose rule description in 'name'."""
    from conftest import build_overview

    overview = build_overview(
        signatures=[
            {
                "name": "Detects binaries (Windows and macOS) referencing many web browsers. "
                "Observed in information stealers",
                "score": 10,
                "indicators": [{"resource": "sample", "yara_rule": "INDICATOR_SUSPICIOUS_Binary_References_Browsers"}],
            }
        ]
    )
    mock_triage_api.get(f"https://api.tria.ge/v1/samples/{SAMPLE_ID}/overview.json", json=overview)

    req = make_request()
    triage_service.execute(req)

    sandbox_section = req.result.sections[0]
    overview_section = find_subsection(sandbox_section, "Overview")
    sigs_section = find_subsection(overview_section, "Signatures")
    by_title = {s.title_text: s for s in sigs_section.subsections}
    assert "INDICATOR_SUSPICIOUS_BINARY_REFERENCES_BROWSERS" in by_title
    # The verbose rule text has nowhere else to go once yara_rule is used as the title,
    # so it must be preserved as the section body.
    assert "Detects binaries" in (by_title["INDICATOR_SUSPICIOUS_BINARY_REFERENCES_BROWSERS"].body or "")


def test_execute_overview_signature_yara_rule_ignored_for_non_sample_resource(
    triage_service, make_request, mock_triage_api
):
    """A behavioral signature can carry a yara_rule on a *file* indicator (resource is a
    task-relative path, not "sample") — that must not override the behavior's own name."""
    from conftest import build_overview

    overview = build_overview(
        signatures=[
            {
                "name": "Suspicious behavior: use of VirtualAllocEx",
                "score": 3,
                "indicators": [{"resource": "behavioral1/files/0x1-1.dat", "yara_rule": "r"}],
            }
        ]
    )
    mock_triage_api.get(f"https://api.tria.ge/v1/samples/{SAMPLE_ID}/overview.json", json=overview)

    req = make_request()
    triage_service.execute(req)

    sandbox_section = req.result.sections[0]
    overview_section = find_subsection(sandbox_section, "Overview")
    sigs_section = find_subsection(overview_section, "Signatures")
    by_title = {s.title_text: s for s in sigs_section.subsections}
    assert "SUSPICIOUS BEHAVIOR: USE OF VIRTUALALLOCEX" in by_title


def test_execute_overview_signature_description_falls_back_to_indicator_text(
    triage_service, make_request, mock_triage_api
):
    """When an overview signature has no 'desc', per-indicator description/ioc text
    should be surfaced instead of leaving the section body empty."""
    from conftest import build_overview

    overview = build_overview(
        signatures=[
            {
                "label": "program_crash",
                "score": 3,
                "indicators": [{"description": "PID 3340 crashed PID 3396", "pid": 3340, "pid_target": 3396}],
            }
        ]
    )
    mock_triage_api.get(f"https://api.tria.ge/v1/samples/{SAMPLE_ID}/overview.json", json=overview)

    req = make_request()
    triage_service.execute(req)

    sandbox_section = req.result.sections[0]
    overview_section = find_subsection(sandbox_section, "Overview")
    sigs_section = find_subsection(overview_section, "Signatures")
    by_title = {s.title_text: s for s in sigs_section.subsections}
    assert by_title["PROGRAM_CRASH"].body == "PID 3340 crashed PID 3396"


def test_execute_overview_configs_rendered_as_table_with_raw_config(triage_service, make_request, mock_triage_api):
    """Overview configs must render as a ResultTableSection with heur_id 100, an
    attribution.family tag, and a nested 'Raw Config' JSON subsection."""
    from conftest import build_overview

    overview = build_overview(configs=[{"family": "quasar", "c2": ["1.2.3.4:4782"]}])
    mock_triage_api.get(f"https://api.tria.ge/v1/samples/{SAMPLE_ID}/overview.json", json=overview)

    req = make_request()
    triage_service.execute(req)

    sandbox_section = req.result.sections[0]
    overview_section = find_subsection(sandbox_section, "Overview")
    assert overview_section is not None
    mc_section = find_subsection(overview_section, "Malware Config")
    assert mc_section is not None

    family_table = next(s for s in mc_section.subsections if s.title_text == "QUASAR")
    assert family_table.heuristic.heur_id == 100
    assert family_table.tags.get("attribution.family") == ["QUASAR"]
    raw_config = next(s for s in family_table.subsections if s.title_text == "Raw Config")
    assert raw_config.body_format == "JSON"
    assert "quasar" in raw_config.body


def test_execute_overview_signatures_only_no_malware_config_subsection(triage_service, make_request, mock_triage_api):
    """When the overview has signatures but no configs, no 'Malware Config' subsection
    is added under Overview."""
    from conftest import build_overview

    overview = build_overview(signatures=[{"label": "onlysig", "score": 5}])
    mock_triage_api.get(f"https://api.tria.ge/v1/samples/{SAMPLE_ID}/overview.json", json=overview)

    req = make_request()
    triage_service.execute(req)

    sandbox_section = req.result.sections[0]
    overview_section = find_subsection(sandbox_section, "Overview")
    assert overview_section is not None
    assert find_subsection(overview_section, "Signatures") is not None
    assert find_subsection(overview_section, "Malware Config") is None


def test_execute_overview_configs_only_no_signatures_subsection(triage_service, make_request, mock_triage_api):
    """When the overview has configs but no signatures, no 'Signatures' subsection is
    added under Overview."""
    from conftest import build_overview

    overview = build_overview(configs=[{"family": "onlyconfig"}])
    mock_triage_api.get(f"https://api.tria.ge/v1/samples/{SAMPLE_ID}/overview.json", json=overview)

    req = make_request()
    triage_service.execute(req)

    sandbox_section = req.result.sections[0]
    overview_section = find_subsection(sandbox_section, "Overview")
    assert overview_section is not None
    assert find_subsection(overview_section, "Malware Config") is not None
    assert find_subsection(overview_section, "Signatures") is None


def test_execute_no_overview_data_omits_overview_section(triage_service, make_request, mock_triage_api):
    """When the overview report is empty, no 'Overview' section is added at all."""
    sandbox_section = None
    req = make_request()
    triage_service.execute(req)
    sandbox_section = req.result.sections[0]
    assert find_subsection(sandbox_section, "Overview") is None


# Minimal custom sample and behavioral report with a negative signature score.
_FAKE_SAMPLE_ID = "test00-fakesampleid01"
_FAKE_SHA256 = "aabbccdd" * 8  # 64 hex chars

_FAKE_SAMPLE = {
    "id": _FAKE_SAMPLE_ID,
    "status": "reported",
    "kind": "file",
    "filename": "neg_score.exe",
    "private": True,
    "submitted": "2024-02-02T23:56:27Z",
    "completed": "2024-02-02T23:59:09Z",
    "sha256": _FAKE_SHA256,
    "tasks": [
        {"id": "behavioral1", "status": "reported"},
    ],
}

_FAKE_BEHAVIORAL_REPORT = {
    "version": "0.2.3",
    "sample": {"id": _FAKE_SAMPLE_ID},
    "task": {"id": "behavioral1"},
    "analysis": {
        "score": 0,
        "submitted": "2024-02-02T23:56:27Z",
        "reported": "2024-02-02T23:59:09Z",
        "resource": "win7",
        "backend": "raven",
        "platform": "windows",
    },
    "signatures": [
        {"label": "neg_sig", "score": -1},
    ],
    "network": {},
    "processes": None,
    "extracted": None,
    "dumped": None,
}


def test_execute_skips_search_when_use_existing_submission_false(triage_service, make_request, mock_triage_api):
    """use_existing_submission=False must skip search_triage and fall through to
    submit_triage when allow_dynamic_submit is also enabled."""
    mock_triage_api.post(
        "https://api.tria.ge/v0/samples",
        json={"id": SAMPLE_ID, "status": "pending"},
    )
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
        tmp.write(b"MZ\x90\x00test")
        tmp_path = tmp.name
    try:
        req = make_request(use_existing_submission=False, allow_dynamic_submit=True, file_path=tmp_path)
        triage_service.execute(req)
        assert req.result is not None
    finally:
        os.unlink(tmp_path)


def test_execute_search_generic_exception_reraised(triage_service, make_request, mock_triage_api, monkeypatch):
    """A non-ServerError exception from search_triage must be logged and re-raised."""

    def _raise(*args, **kwargs):
        raise ValueError("boom")

    monkeypatch.setattr(triage_service, "search_triage", _raise)
    req = make_request()
    with pytest.raises(ValueError):
        triage_service.execute(req)


# ---------------------------------------------------------------------------
# Per-task signature dedup (same signature reached via __add_signatures AND
# __add_extracted's rule match) + no-c2 extracted config
# ---------------------------------------------------------------------------

_DUP_SAMPLE_ID = "test00-dupsigid0001"
_DUP_SHA256 = "d0d0d0d0" * 8

_DUP_SAMPLE = {
    "id": _DUP_SAMPLE_ID,
    "status": "reported",
    "kind": "file",
    "filename": "dup.exe",
    "private": True,
    "submitted": "2024-02-02T23:56:27Z",
    "completed": "2024-02-02T23:59:09Z",
    "sha256": _DUP_SHA256,
    "tasks": [{"id": "behavioral1", "status": "reported"}],
}

_DUP_BEHAVIORAL_REPORT = {
    "version": "0.2.3",
    "sample": {"id": _DUP_SAMPLE_ID},
    "task": {"id": "behavioral1"},
    "analysis": {
        "score": 5,
        "submitted": "2024-02-02T23:56:27Z",
        "reported": "2024-02-02T23:59:09Z",
        "resource": "win7",
        "backend": "raven",
        "platform": "windows",
    },
    "processes": [
        {"procid": 1, "pid": 100, "ppid": 0, "image": "a.exe", "cmd": "a", "started": 1},
    ],
    "signatures": [
        {"label": "dupsig", "score": 5, "ttp": ["T1082"], "indicators": [{"procid": 1}]},
    ],
    "network": {},
    # No 'c2' key -> exercises the "extracted item without c2" and "no Malware Config
    # subsection" branches, while the matching 'rule' name causes __add_extracted to
    # reuse (and re-add) the same Signature object created by __add_signatures.
    "extracted": [{"config": {"family": "x", "rule": "dupsig"}}],
    "dumped": None,
}


def test_execute_duplicate_signature_merges_processtree_and_attacks(requests_mock, make_request, triage_service):
    """When a task's ontology contains the same Signature object twice (behavioral label
    and extracted rule resolve to the same tag), the second occurrence must merge its
    process-tree tag and attack ids into the already-built section rather than duplicate it.
    The extracted item also has no 'c2', so no Malware Config subsection should be added."""
    encoded = req_utils.quote(f"sha256:{_DUP_SHA256}")
    requests_mock.get(
        f"https://api.tria.ge/v0/search?query={encoded}&limit=1",
        json={"data": [{"id": _DUP_SAMPLE_ID}], "next": None},
    )
    requests_mock.get(f"https://api.tria.ge/v0/samples/{_DUP_SAMPLE_ID}", json=_DUP_SAMPLE)
    requests_mock.get(
        f"https://api.tria.ge/v0/samples/{_DUP_SAMPLE_ID}/behavioral1/report_triage.json",
        json=_DUP_BEHAVIORAL_REPORT,
    )
    requests_mock.get(f"https://api.tria.ge/v1/samples/{_DUP_SAMPLE_ID}/overview.json", json={})

    req = make_request(sha256=_DUP_SHA256)
    triage_service.execute(req)

    sandbox_section = req.result.sections[0]
    task_section = find_subsection(sandbox_section, "Task: behavioral1")
    assert task_section is not None

    sigs_section = find_subsection(task_section, "Signatures")
    dup_sections = [s for s in sigs_section.subsections if s.title_text == "DUPSIG"]
    assert len(dup_sections) == 1, "the duplicate occurrence must merge, not create a second section"
    assert "T1082" in dup_sections[0].heuristic.attack_ids
    assert dup_sections[0].tags.get("dynamic.processtree_id")

    # No 'c2' in the extracted config -> no Malware Config subsection at all.
    assert find_subsection(task_section, "Malware Config") is None


# ---------------------------------------------------------------------------
# program_crash: crashed-process list rendered as a process-tree-style subsection
# ---------------------------------------------------------------------------

_CRASH_SAMPLE_ID = "test00-crashsigid001"
_CRASH_SHA256 = "c4a5c4a5" * 8

_CRASH_SAMPLE = {
    "id": _CRASH_SAMPLE_ID,
    "status": "reported",
    "kind": "file",
    "filename": "crash.exe",
    "private": True,
    "submitted": "2024-02-02T23:56:27Z",
    "completed": "2024-02-02T23:59:09Z",
    "sha256": _CRASH_SHA256,
    "tasks": [{"id": "behavioral1", "status": "reported"}],
}

_CRASH_BEHAVIORAL_REPORT = {
    "version": "0.2.3",
    "sample": {"id": _CRASH_SAMPLE_ID},
    "task": {"id": "behavioral1"},
    "analysis": {
        "score": 3,
        "submitted": "2024-02-02T23:56:27Z",
        "reported": "2024-02-02T23:59:09Z",
        "resource": "win7",
        "backend": "raven",
        "platform": "windows",
    },
    "processes": [
        {
            "procid": 100,
            "pid": 3340,
            "ppid": 0,
            "image": "C:\\Windows\\SysWOW64\\WerFault.exe",
            "cmd": "WerFault.exe -u -p 3396 -s 1188",
            "started": 1,
        },
        {
            "procid": 83,
            "pid": 3396,
            "ppid": 0,
            "image": "C:\\Users\\Admin\\malware.exe",
            "cmd": '"C:\\Users\\Admin\\malware.exe"',
            "started": 1,
        },
    ],
    "signatures": [
        {
            "label": "program_crash",
            "score": 3,
            "indicators": [{"pid": 3340, "procid": 100, "pid_target": 3396, "procid_target": 83}],
        },
    ],
    "network": {},
    "extracted": None,
    "dumped": None,
}


def test_execute_program_crash_renders_crashed_process_tree(requests_mock, make_request, triage_service):
    """PROGRAM_CRASH must include a 'Crashed Process(es)' process-tree subsection listing
    only the process that actually crashed (procid_target) — not the crash reporter
    (procid, e.g. WerFault.exe)."""
    encoded = req_utils.quote(f"sha256:{_CRASH_SHA256}")
    requests_mock.get(
        f"https://api.tria.ge/v0/search?query={encoded}&limit=1",
        json={"data": [{"id": _CRASH_SAMPLE_ID}], "next": None},
    )
    requests_mock.get(f"https://api.tria.ge/v0/samples/{_CRASH_SAMPLE_ID}", json=_CRASH_SAMPLE)
    requests_mock.get(
        f"https://api.tria.ge/v0/samples/{_CRASH_SAMPLE_ID}/behavioral1/report_triage.json",
        json=_CRASH_BEHAVIORAL_REPORT,
    )
    requests_mock.get(f"https://api.tria.ge/v1/samples/{_CRASH_SAMPLE_ID}/overview.json", json={})

    req = make_request(sha256=_CRASH_SHA256)
    triage_service.execute(req)

    sandbox_section = req.result.sections[0]
    task_section = find_subsection(sandbox_section, "Task: behavioral1")
    sigs_section = find_subsection(task_section, "Signatures")
    crash_section = find_subsection(sigs_section, "PROGRAM_CRASH")
    assert crash_section is not None

    crash_tree = find_subsection(crash_section, "Crashed Process(es)")
    assert crash_tree is not None
    assert crash_tree.auto_collapse is True
    procs = json.loads(crash_tree.section_body.body)
    assert len(procs) == 1
    assert procs[0]["process_pid"] == 3396
    assert procs[0]["process_name"] == "C:\\Users\\Admin\\malware.exe"
    assert procs[0]["command_line"] == '"C:\\Users\\Admin\\malware.exe"'


# ---------------------------------------------------------------------------
# Download error paths (pcap / memdump / dropped files) - must log and continue
# ---------------------------------------------------------------------------


def test_execute_download_failures_are_non_fatal(triage_service, make_request, mock_triage_api):
    """A failed pcap/memdump/dropped-file download must be logged and must not raise
    or call add_extracted, and execute() must still produce a result. _req_file() never
    inspects the HTTP status (it just returns .content), so the failure must be a
    transport-level error rather than a non-2xx status code."""
    mock_triage_api.get(
        re.compile(r"https://api\.tria\.ge/v0/samples/.+/.+/dump\.pcapng"),
        exc=requests.exceptions.ConnectionError,
    )
    mock_triage_api.get(
        re.compile(r"https://api\.tria\.ge/v0/samples/.+/.+/memory/.+\.dmp"),
        exc=requests.exceptions.ConnectionError,
    )
    mock_triage_api.get(
        re.compile(r"https://api\.tria\.ge/v0/samples/.+/.+/files/.+\.dat"),
        exc=requests.exceptions.ConnectionError,
    )

    req = make_request(extract_pcap=True, extract_memdump=True, extract_dropped_files=True)
    triage_service.execute(req)

    assert req.result is not None
    req.add_extracted.assert_not_called()


def test_execute_signature_attribute_non_process_source_skips_processtree_tag(
    requests_mock, make_request, triage_service, monkeypatch
):
    """A signature Attribute whose source isn't a process (ontology_id doesn't start with
    'process_') must not add a dynamic.processtree_id tag. Exercised in both the
    new-signature branch and the merged-duplicate branch via the same DUPSIG fixture."""
    from assemblyline_service_utilities.common.dynamic_service_helper import OntologyResults

    def _fake_get_process_by_pid(self, pid=None):
        return SimpleNamespace(objectid=OntologyResults.create_objectid(tag="filetag", ontology_id="file_deadbeef"))

    monkeypatch.setattr(OntologyResults, "get_process_by_pid", _fake_get_process_by_pid)

    encoded = req_utils.quote(f"sha256:{_DUP_SHA256}")
    requests_mock.get(
        f"https://api.tria.ge/v0/search?query={encoded}&limit=1",
        json={"data": [{"id": _DUP_SAMPLE_ID}], "next": None},
    )
    requests_mock.get(f"https://api.tria.ge/v0/samples/{_DUP_SAMPLE_ID}", json=_DUP_SAMPLE)
    requests_mock.get(
        f"https://api.tria.ge/v0/samples/{_DUP_SAMPLE_ID}/behavioral1/report_triage.json",
        json=_DUP_BEHAVIORAL_REPORT,
    )
    requests_mock.get(f"https://api.tria.ge/v1/samples/{_DUP_SAMPLE_ID}/overview.json", json={})

    req = make_request(sha256=_DUP_SHA256)
    triage_service.execute(req)

    sandbox_section = req.result.sections[0]
    task_section = find_subsection(sandbox_section, "Task: behavioral1")
    sigs_section = find_subsection(task_section, "Signatures")
    dup_section = next(s for s in sigs_section.subsections if s.title_text == "DUPSIG")
    assert "dynamic.processtree_id" not in dup_section.tags


def test_execute_negative_score_signature(requests_mock, make_request, triage_service):
    """execute() should complete without AttributeError when a signature has a negative score."""
    encoded = req_utils.quote(f"sha256:{_FAKE_SHA256}")
    requests_mock.get(
        f"https://api.tria.ge/v0/search?query={encoded}&limit=1",
        json={"data": [{"id": _FAKE_SAMPLE_ID}], "next": None},
    )
    requests_mock.get(
        f"https://api.tria.ge/v0/samples/{_FAKE_SAMPLE_ID}",
        json=_FAKE_SAMPLE,
    )
    requests_mock.get(
        f"https://api.tria.ge/v0/samples/{_FAKE_SAMPLE_ID}/behavioral1/report_triage.json",
        json=_FAKE_BEHAVIORAL_REPORT,
    )

    req = make_request(sha256=_FAKE_SHA256)
    svc = triage_service
    svc.execute(req)
    assert req.result is not None
