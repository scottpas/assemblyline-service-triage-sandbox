"""
Shared pytest fixtures for the TriageSandbox service test suite.

Key architectural notes:
- TriageSandbox(ServiceBase) reads service_manifest.yml from the repo root at
  construction time (via get_service_attributes()), so no special constructor
  args are required; a plain `TriageSandbox()` call succeeds in the test
  environment as long as the CWD is the repo root.
- ServiceRequest is mocked with MagicMock so tests remain independent of the
  full assemblyline task machinery.
- The Triage HTTP client is requests-based; requests_mock intercepts all calls
  transparently.
- The sample fixture's status is "reported", so wait_for_submission exits on
  the very first poll (no sleep / retry needed).
- The search endpoint called by client.search(query, max=1).__next__() is:
    GET /v0/search?query=<url-encoded-query>&limit=1
  The Paginator reads resp['data'] and resp['next'] from the JSON body.
"""

import json
from typing import Any, Dict, Optional
from unittest.mock import MagicMock

import pytest
from requests import utils as req_utils

# ---------------------------------------------------------------------------
# Synthetic fixture constants
# ---------------------------------------------------------------------------

SAMPLE_ID = "240202-3y8f7sefen"
SHA256 = "7d50e22081955b574b989561277ce0e835117e716817736373ac8799774b6f03"


# ---------------------------------------------------------------------------
# Synthetic data builders
# ---------------------------------------------------------------------------


def build_sample() -> Dict[str, Any]:
    """Build a minimal synthetic Triage sample object (GET /v0/samples/{id})."""
    return {
        "id": SAMPLE_ID,
        "status": "reported",
        "kind": "file",
        "filename": "sample.exe",
        "private": False,
        "tasks": [
            {"id": "static1", "status": "reported"},
            {"id": "behavioral1", "status": "reported", "target": "sample.exe"},
            {"id": "behavioral2", "status": "reported", "target": "sample.exe"},
        ],
        "submitted": "2024-02-02T23:56:27Z",
        "completed": "2024-02-02T23:59:13Z",
        "sha256": SHA256,
    }


def build_report(task_id: str, family: str = "fabookie") -> Dict[str, Any]:
    """Build a minimal synthetic Triage task report (GET /v0/samples/{id}/{task_id}/report_triage.json)."""
    # Use task-specific PIDs so process tree isolation tests can distinguish tasks.
    # behavioral1 owns 2104/2356; behavioral2 owns 3104/3356.
    parent_pid = 2104 if task_id == "behavioral1" else 3104
    child_pid = 2356 if task_id == "behavioral1" else 3356

    return {
        "version": "0.3.0",
        "sample": {
            "id": SAMPLE_ID,
            "score": 10,
            "target": "sample.exe",
            "size": 2048,
            "md5": "0" * 32,
            "sha1": "0" * 40,
            "sha256": SHA256,
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
            "sha256": SHA256,
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
            "ttp": ["T1082", "T1012", "T1120"],
            "tags": ["trojan"],
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
                "pid": parent_pid,
                "ppid": 1220,
                "image": "C:\\Users\\Admin\\AppData\\Local\\Temp\\sample.exe",
                "cmd": '"C:\\Users\\Admin\\AppData\\Local\\Temp\\sample.exe"',
                "orig": True,
                "started": 154,
                "terminated": 450,
            },
            {
                "procid": 2,
                "procid_parent": 1,
                "pid": child_pid,
                "ppid": parent_pid,
                "image": "C:\\Users\\Admin\\AppData\\Local\\Temp\\child.exe",
                "cmd": "child.exe",
                "orig": False,
                "started": 200,
            },
        ],
        "signatures": [
            {"label": "low_confidence_behavior", "indicators": []},
            {
                "name": "Suspicious behavior: use of WriteProcessMemory",
                "score": 3,
                "indicators": [{"resource": f"{task_id}/files/0x1-1.dat", "yara_rule": "r"}],
            },
            {"label": "interesting_sig", "score": 3},
            {"label": "suspicious_sig", "score": 6},
            {"label": "likely_malicious_sig", "score": 9},
            {
                "label": family,
                "score": 10,
                "desc": "family detected",
                "tags": ["stealer", f"family:{family}"],
                "ttp": ["T1082"],
            },
        ],
        "network": {
            "flows": [
                {
                    "id": 1,
                    "src": "10.127.0.103:59655",
                    "dst": "8.8.8.8:53",
                    "proto": "udp",
                    "pid": parent_pid,
                    "procid": 1,
                    "first_seen": 3343,
                    "last_seen": 3395,
                    "protocols": ["dns"],
                    "domain": "a.example.co",
                },
                {
                    "id": 2,
                    "src": "10.127.0.103:49000",
                    "dst": "93.184.216.34:80",
                    "proto": "tcp",
                    "pid": parent_pid,
                    "procid": 1,
                    "first_seen": 3400,
                    "protocols": ["http"],
                },
            ],
            "requests": [],
            "ips": [],
        },
        "extracted": [
            {
                "config": {
                    "family": family,
                    "rule": family.capitalize(),
                    "c2": [f"http://{family}.example/gate/"],
                },
                "resource": f"{task_id}/files/0x1-1.dat",
            },
        ],
        "dumped": [
            {
                "at": 747,
                "pid": child_pid,
                "procid": 2,
                "name": f"memory/{child_pid}-{task_id}-0x6B280000-memory.dmp",
                "kind": "region",
                "origin": "exception",
                "addr": 1797783552,
                "length": 155648,
            },
            {
                "at": 435,
                "pid": parent_pid,
                "procid": 1,
                "path": "\\Users\\Admin\\AppData\\Local\\Temp\\setup.exe",
                "name": f"files/0x1-2-{task_id}.dat",
                "kind": "martian",
                "origin": "imgload",
                "md5": "0" * 32,
                "sha256": "0" * 64,
                "size": 1288123,
            },
        ],
        "tags": ["trojan"],
    }


# ---------------------------------------------------------------------------
# Raw fixture data fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def sample_json() -> Dict[str, Any]:
    """Synthetic top-level sample object (id, status, tasks, …)."""
    return build_sample()


@pytest.fixture(scope="session")
def behavioral1_json() -> Dict[str, Any]:
    """Synthetic behavioral1 triage task report."""
    return build_report("behavioral1")


@pytest.fixture(scope="session")
def behavioral2_json() -> Dict[str, Any]:
    """Synthetic behavioral2 triage task report (different family for variety)."""
    return build_report("behavioral2", family="vidar")


@pytest.fixture(scope="session")
def sample_text() -> str:
    """JSON-serialised sample fixture (for requests_mock text= parameter)."""
    return json.dumps(build_sample())


@pytest.fixture(scope="session")
def behavioral1_text() -> str:
    """JSON-serialised behavioral1 fixture."""
    return json.dumps(build_report("behavioral1"))


@pytest.fixture(scope="session")
def behavioral2_text() -> str:
    """JSON-serialised behavioral2 fixture."""
    return json.dumps(build_report("behavioral2", family="vidar"))


# ---------------------------------------------------------------------------
# TriageClient fixture (pre-wired with requests_mock)
# ---------------------------------------------------------------------------


@pytest.fixture
def triage_client(requests_mock, sample_text, behavioral1_text, behavioral2_text, sample_json):
    """
    Return a TriageClient(token="TESTING") with all three tria.ge API
    endpoints pre-registered on requests_mock.

    Registered endpoints
    --------------------
    GET /v0/samples/240202-3y8f7sefen
        -> sample object (status "reported")
    GET /v0/samples/240202-3y8f7sefen/behavioral1/report_triage.json
        -> behavioral1 task report
    GET /v0/samples/240202-3y8f7sefen/behavioral2/report_triage.json
        -> behavioral2 task report
    GET /v0/search?query=sha256:<sha>&limit=1
        -> search result page containing the sample id

    The fixture also registers the sha256-based search endpoint so that
    search_triage() (use_existing_submission=True path) works without network.
    """
    from triage import Client as TriageClient

    sha256 = sample_json["sha256"]
    encoded_query = req_utils.quote(f"sha256:{sha256}")
    search_url = f"https://api.tria.ge/v0/search?query={encoded_query}&limit=1"
    search_body = json.dumps({"data": [{"id": SAMPLE_ID}], "next": None})

    requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}", text=sample_text)
    requests_mock.get(
        f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/behavioral1/report_triage.json",
        text=behavioral1_text,
    )
    requests_mock.get(
        f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/behavioral2/report_triage.json",
        text=behavioral2_text,
    )
    requests_mock.get(search_url, text=search_body)

    return TriageClient(token="TESTING")


# ---------------------------------------------------------------------------
# Default submission parameters (mirrors service_manifest.yml defaults)
# ---------------------------------------------------------------------------

DEFAULT_PARAMS: Dict[str, Any] = {
    "analysis_timeout_in_seconds": 150,
    "network": "internet",
    "api_key": "",
    "use_existing_submission": True,
    "extract_pcap": False,
    "extract_memdump": False,
    "extract_dropped_files": False,
    "allow_dynamic_submit": False,
    "submit_as_url": False,
}


# ---------------------------------------------------------------------------
# Mock ServiceRequest factory
# ---------------------------------------------------------------------------


@pytest.fixture
def make_request(sample_json):
    """
    Factory fixture that returns a configured MagicMock standing in for
    assemblyline_v4_service.common.request.ServiceRequest.

    Usage
    -----
    def test_something(make_request):
        request = make_request()                   # all defaults
        request = make_request(use_existing_submission=False)
        request = make_request(sha256="abc…")
    """

    def _factory(
        sha256: Optional[str] = None,
        file_type: str = "executable/windows/pe32",
        file_name: Optional[str] = None,
        file_path: str = "/tmp/test_sample",
        uri_info=None,
        **param_overrides: Any,
    ) -> MagicMock:
        params = {**DEFAULT_PARAMS, **param_overrides}

        request = MagicMock()
        request.get_param.side_effect = lambda name: params.get(name)
        request.sha256 = sha256 or sample_json["sha256"]
        request.file_type = file_type
        request.file_name = file_name or sample_json.get("filename", "sample") + ".exe"
        request.file_path = file_path
        request.task.fileinfo.uri_info = uri_info
        request.result = None
        return request

    return _factory


# ---------------------------------------------------------------------------
# TriageSandbox service fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def triage_service():
    """
    Instantiate a TriageSandbox ready for execute() calls.

    Construction recipe
    -------------------
    TriageSandbox() with no arguments works because ServiceBase.__init__
    calls get_service_attributes() which reads service_manifest.yml from the
    current working directory (the repo root when pytest is invoked).

    The resulting object has:
      svc.config       = {'root_url': 'https://api.tria.ge', 'api_key': '', …}
      svc.web_url      = 'https://tria.ge'
      svc.log          = standard Python logger
      svc.ontology     = OntologyHelper instance (from assemblyline_v4_service)
      svc.working_directory  -> auto-created temp dir on first access

    execute() also instantiates svc.client (TriageClient) from request params,
    so tests that mock at the HTTP level (via requests_mock) do not need to
    pre-set svc.client.
    """
    from service import TriageSandbox

    return TriageSandbox()


@pytest.fixture
def mock_triage_api(requests_mock, sample_text, behavioral1_text, behavioral2_text, sample_json):
    """Register the tria.ge endpoints on requests_mock for execute() tests (which build their own client)."""
    sha256 = sample_json["sha256"]
    encoded = req_utils.quote(f"sha256:{sha256}")
    requests_mock.get(f"https://api.tria.ge/v0/samples/{SAMPLE_ID}", text=sample_text)
    requests_mock.get(
        f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/behavioral1/report_triage.json",
        text=behavioral1_text,
    )
    requests_mock.get(
        f"https://api.tria.ge/v0/samples/{SAMPLE_ID}/behavioral2/report_triage.json",
        text=behavioral2_text,
    )
    requests_mock.get(
        f"https://api.tria.ge/v0/search?query={encoded}&limit=1",
        text=json.dumps({"data": [{"id": SAMPLE_ID}], "next": None}),
    )
    return requests_mock
