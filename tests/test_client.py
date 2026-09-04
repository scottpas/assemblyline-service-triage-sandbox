"""Unit tests for triage_sandbox.client."""

import io
import json

import pytest
from requests import utils as req_utils

from triage_sandbox import client as client_module
from triage_sandbox.client import (
    DEFAULT_ROOT_URL,
    DOWNLOAD_TIMEOUT,
    REQUEST_TIMEOUT,
    ServerError,
    TriageClient,
)

BASE = "https://api.tria.ge"
SID = "240202-3y8f7sefen"


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_defaults():
    c = TriageClient(token="T")
    assert c.root_url == DEFAULT_ROOT_URL
    assert c.timeout == REQUEST_TIMEOUT
    assert c.download_timeout == DOWNLOAD_TIMEOUT


def test_explicit_root_url_and_timeouts():
    c = TriageClient(token="T", root_url="https://private.tria.ge/api/", timeout=5, download_timeout=7)
    assert c.root_url == "https://private.tria.ge/api"
    assert c.timeout == 5
    assert c.download_timeout == 7


def test_missing_token_sends_empty_bearer(requests_mock):
    requests_mock.get(f"{BASE}/v0/samples/{SID}", json={})
    TriageClient(token=None).sample_by_id(SID)
    assert requests_mock.last_request.headers["Authorization"] == "Bearer "


def test_auth_and_user_agent_headers(requests_mock):
    requests_mock.get(f"{BASE}/v0/samples/{SID}", json={})
    TriageClient(token="TESTING").sample_by_id(SID)
    req = requests_mock.last_request
    assert req.headers["Authorization"] == "Bearer TESTING"
    assert req.headers["User-Agent"] == client_module.USER_AGENT


# ---------------------------------------------------------------------------
# Transport properties — the security regressions this module exists to prevent
# ---------------------------------------------------------------------------


def test_tls_verification_is_never_disabled(requests_mock):
    requests_mock.get(f"{BASE}/v0/samples/{SID}", json={})
    TriageClient(token="T").sample_by_id(SID)
    assert requests_mock.last_request.verify is not False


def test_json_calls_carry_request_timeout(requests_mock):
    requests_mock.get(f"{BASE}/v0/samples/{SID}", json={})
    TriageClient(token="T", timeout=11).sample_by_id(SID)
    assert requests_mock.last_request.timeout == 11


# ---------------------------------------------------------------------------
# _request / ServerError
# ---------------------------------------------------------------------------


def test_request_returns_json_on_ok(requests_mock):
    requests_mock.get(f"{BASE}/v0/samples/{SID}", json={"id": SID, "status": "reported"})
    assert TriageClient(token="T").sample_by_id(SID) == {"id": SID, "status": "reported"}


def test_server_error_from_json_body(requests_mock):
    requests_mock.get(
        f"{BASE}/v0/samples/{SID}",
        status_code=500,
        json={"error": "internal_error", "message": "server failed"},
    )
    with pytest.raises(ServerError) as excinfo:
        TriageClient(token="T").sample_by_id(SID)
    err = excinfo.value
    assert err.status == 500
    assert err.kind == "internal_error"
    assert err.message == "server failed"
    assert str(err) == "triage: 500 internal_error: server failed"


def test_server_error_from_non_json_body(requests_mock):
    requests_mock.get(f"{BASE}/v0/samples/{SID}", status_code=404, text="not found")
    with pytest.raises(ServerError) as excinfo:
        TriageClient(token="T").sample_by_id(SID)
    err = excinfo.value
    assert err.status == 404
    assert err.kind == ""
    assert err.message == ""


def test_server_error_from_non_dict_json_body(requests_mock):
    requests_mock.get(f"{BASE}/v0/samples/{SID}", status_code=400, json=[1, 2])
    with pytest.raises(ServerError) as excinfo:
        TriageClient(token="T").sample_by_id(SID)
    assert excinfo.value.kind == ""
    assert excinfo.value.message == ""


# ---------------------------------------------------------------------------
# Endpoint shapes
# ---------------------------------------------------------------------------


def test_sample_by_id_path(requests_mock):
    m = requests_mock.get(f"{BASE}/v0/samples/{SID}", json={})
    TriageClient(token="T").sample_by_id(SID)
    assert m.last_request.path == f"/v0/samples/{SID}"


def test_task_report_path(requests_mock):
    m = requests_mock.get(f"{BASE}/v0/samples/{SID}/behavioral1/report_triage.json", json={})
    TriageClient(token="T").task_report(SID, "behavioral1")
    assert m.last_request.path == f"/v0/samples/{SID}/behavioral1/report_triage.json"


def test_overview_report_uses_v1(requests_mock):
    m = requests_mock.get(f"{BASE}/v1/samples/{SID}/overview.json", json={})
    TriageClient(token="T").overview_report(SID)
    assert m.last_request.path == f"/v1/samples/{SID}/overview.json"


# ---------------------------------------------------------------------------
# search_one
# ---------------------------------------------------------------------------


def test_search_one_returns_first_hit(requests_mock):
    query = "sha256:abc123"
    url = f"{BASE}/v0/search?query={req_utils.quote(query)}&limit=1"
    requests_mock.get(url, json={"data": [{"id": SID}, {"id": "other"}], "next": None})
    assert TriageClient(token="T").search_one(query) == {"id": SID}


def test_search_one_empty_data_returns_none(requests_mock):
    requests_mock.get(
        f"{BASE}/v0/search?query={req_utils.quote('sha256:x')}&limit=1",
        json={"data": []},
    )
    assert TriageClient(token="T").search_one("sha256:x") is None


def test_search_one_null_data_returns_none(requests_mock):
    requests_mock.get(
        f"{BASE}/v0/search?query={req_utils.quote('sha256:x')}&limit=1",
        json={"data": None},
    )
    assert TriageClient(token="T").search_one("sha256:x") is None


def test_search_one_encodes_quoted_url_query(requests_mock):
    query = 'url:"http://mal.test/x"'
    requests_mock.get(
        f"{BASE}/v0/search?query={req_utils.quote(query)}&limit=1",
        json={"data": [{"id": SID}], "next": None},
    )
    TriageClient(token="T").search_one(query)
    assert f"query={req_utils.quote(query)}" in requests_mock.last_request.url


# ---------------------------------------------------------------------------
# submit_sample_url
# ---------------------------------------------------------------------------


def test_submit_sample_url_body(requests_mock):
    requests_mock.post(f"{BASE}/v0/samples", json={"id": SID})
    result = TriageClient(token="T").submit_sample_url("http://evil.test/x")
    assert result == {"id": SID}
    req = requests_mock.last_request
    assert req.json() == {
        "kind": "url",
        "url": "http://evil.test/x",
        "interactive": False,
        "profiles": [],
    }
    assert req.headers["Content-Type"] == "application/json"


# ---------------------------------------------------------------------------
# submit_sample_file
# ---------------------------------------------------------------------------


def test_submit_sample_file_multipart_body(requests_mock):
    requests_mock.post(f"{BASE}/v0/samples", json={"id": SID})
    TriageClient(token="T").submit_sample_file("sample.exe", io.BytesIO(b"MZpayload"), network="tor", timeout=200)
    body = requests_mock.last_request.text
    assert 'name="_json"' in body
    assert (
        json.dumps(
            {
                "kind": "file",
                "interactive": False,
                "profiles": [],
                "defaults": {"timeout": 200, "network": "tor"},
            }
        )
        in body
    )
    assert 'name="file"' in body
    assert 'filename="sample.exe"' in body
    assert "MZpayload" in body


def test_submit_sample_file_defaults(requests_mock):
    requests_mock.post(f"{BASE}/v0/samples", json={})
    TriageClient(token="T").submit_sample_file("a.bin", io.BytesIO(b"x"))
    assert '"defaults": {"timeout": 150, "network": "internet"}' in requests_mock.last_request.text


def test_submit_sample_file_escapes_quote_in_filename(requests_mock):
    requests_mock.post(f"{BASE}/v0/samples", json={})
    TriageClient(token="T").submit_sample_file('a"b.exe', io.BytesIO(b"x"))
    # urllib3 2.x percent-encodes the double quote per WHATWG rather than backslash-escaping.
    assert 'filename="a%22b.exe"' in requests_mock.last_request.text


# ---------------------------------------------------------------------------
# download_task_file
# ---------------------------------------------------------------------------


def test_download_task_file_writes_streamed_bytes(requests_mock, tmp_path, monkeypatch):
    monkeypatch.setattr(client_module, "ARTIFACT_CHUNK_SIZE", 4)
    requests_mock.get(
        f"{BASE}/v0/samples/{SID}/behavioral1/dump.pcapng",
        content=b"abcdefghij",
    )
    path = TriageClient(token="T").download_task_file(SID, "behavioral1", "dump.pcapng", str(tmp_path))
    assert open(path, "rb").read() == b"abcdefghij"
    req = requests_mock.last_request
    assert req.stream is True
    assert req.timeout == DOWNLOAD_TIMEOUT


def test_download_task_file_skips_empty_chunks(tmp_path):
    class FakeResponse:
        ok = True

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def iter_content(self, chunk_size):
            return [b"first", b"", b"second"]

    class FakeSession:
        def get(self, *a, **k):
            return FakeResponse()

    c = TriageClient(token="T")
    c.session = FakeSession()  # ty: ignore[invalid-assignment]
    path = c.download_task_file(SID, "behavioral1", "x.dmp", str(tmp_path))
    assert open(path, "rb").read() == b"firstsecond"


def test_download_task_file_non_2xx_raises_and_leaves_no_file(requests_mock, tmp_path):
    requests_mock.get(
        f"{BASE}/v0/samples/{SID}/behavioral1/missing.dmp",
        status_code=500,
        json={"error": "boom", "message": "nope"},
    )
    with pytest.raises(ServerError):
        TriageClient(token="T").download_task_file(SID, "behavioral1", "missing.dmp", str(tmp_path))
    assert list(tmp_path.iterdir()) == []


def test_download_task_file_unlinks_partial_file_on_write_error(requests_mock, tmp_path, monkeypatch):
    requests_mock.get(
        f"{BASE}/v0/samples/{SID}/behavioral1/dump.pcapng",
        content=b"partial",
    )

    class FailingFile:
        def __init__(self, fd):
            self.fd = fd

        def __enter__(self):
            return self

        def __exit__(self, *args):
            client_module.os.close(self.fd)

        def write(self, chunk):
            raise OSError("disk full")

    monkeypatch.setattr(client_module.os, "fdopen", lambda fd, mode: FailingFile(fd))

    with pytest.raises(OSError, match="disk full"):
        TriageClient(token="T").download_task_file(SID, "behavioral1", "dump.pcapng", str(tmp_path))
    assert list(tmp_path.iterdir()) == []


def test_download_task_file_nested_name_path(requests_mock, tmp_path):
    m = requests_mock.get(
        f"{BASE}/v0/samples/{SID}/behavioral1/memory/2356-x-memory.dmp",
        content=b"d",
    )
    TriageClient(token="T").download_task_file(SID, "behavioral1", "memory/2356-x-memory.dmp", str(tmp_path))
    assert m.last_request.path == f"/v0/samples/{SID}/behavioral1/memory/2356-x-memory.dmp"


# ---------------------------------------------------------------------------
# close
# ---------------------------------------------------------------------------


def test_close_is_idempotent():
    c = TriageClient(token="T")
    c.close()
    c.close()
