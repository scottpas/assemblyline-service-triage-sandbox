"""
Integration tests for TriageSandbox.execute(), search_triage(), and submit_triage().
"""

import os
import re
import tempfile
from types import SimpleNamespace

import pytest
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


def test_execute_attack_techniques_section_attached(triage_service, make_request, mock_triage_api):
    """Each task section should contain an ATT&CK Techniques subsection (analysis.ttp is present)."""
    svc = triage_service
    req = make_request()
    svc.execute(req)

    sandbox_section = req.result.sections[0]
    for task_section in sandbox_section.subsections:
        ttp = find_subsection(task_section, "ATT&CK Techniques")
        assert ttp is not None, f"ATT&CK Techniques subsection missing from {task_section.title_text}"


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

    monkeypatch.setattr("service.wait_for_submission", _raise_retry)

    req = make_request()
    with pytest.raises(RetryError):
        triage_service.execute(req)


def test_execute_web_url_default(triage_service):
    """TriageSandbox derives web_url from root_url by stripping 'api.' prefix."""
    assert triage_service.web_url == "https://tria.ge"


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
