"""Unit tests for module-level functions in triage_sandbox.service."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from triage.client import ServerError

import triage_sandbox.service as service
from triage_sandbox.service import (
    _attach_dynamic_ontology,
    _download_artifact,
    _is_submission_not_reported,
    _retry_on_not_found,
    wait_for_submission,
)


def make_server_error(status: int) -> ServerError:
    """Construct a ServerError with a given HTTP status without a real response object.

    ServerError.__init__ requires a requests.Response-like object, so we use
    __new__ and set attributes directly.
    """
    err = ServerError.__new__(ServerError)
    err.status = status
    err.kind = ""
    err.message = ""
    return err


# ---------------------------------------------------------------------------
# _is_submission_not_reported
# ---------------------------------------------------------------------------


def test_not_reported_none():
    assert _is_submission_not_reported(None) is True


def test_not_reported_missing_status():
    assert _is_submission_not_reported({}) is True


def test_not_reported_reported():
    assert _is_submission_not_reported({"status": "reported"}) is False


def test_not_reported_other_status():
    assert _is_submission_not_reported({"status": "pending"}) is True


# ---------------------------------------------------------------------------
# _retry_on_not_found
# ---------------------------------------------------------------------------


def test_retry_on_404():
    err = make_server_error(404)
    assert _retry_on_not_found(err) is True


def test_retry_on_500():
    err = make_server_error(500)
    assert _retry_on_not_found(err) is False


def test_retry_on_non_servererror():
    assert _retry_on_not_found(ValueError("x")) is False


# ---------------------------------------------------------------------------
# wait_for_submission
# ---------------------------------------------------------------------------


def test_wait_for_submission_returns_on_reported():
    svc = SimpleNamespace(client=MagicMock(), log=MagicMock())
    expected = {"id": "s1", "status": "reported"}
    svc.client.sample_by_id.return_value = expected

    result = wait_for_submission(service=svc, submission_id="s1")

    assert result == expected
    assert svc.client.sample_by_id.call_count == 1


# ---------------------------------------------------------------------------
# _download_artifact
# ---------------------------------------------------------------------------


def test_download_artifact_streams_chunks_and_ignores_empty_chunks(monkeypatch, tmp_path):
    client = MagicMock()
    request = MagicMock(url="https://api.tria.ge/artifact")
    client._new_request.return_value = request
    response = MagicMock()
    response.__enter__.return_value = response
    response.iter_content.return_value = [b"first", b"", b"second"]
    session = MagicMock()
    session.__enter__.return_value = session
    session.send.return_value = response
    session.merge_environment_settings.return_value = {"verify": True, "stream": True}
    session_factory = MagicMock(return_value=session)
    monkeypatch.setattr(service, "Session", session_factory)

    artifact_path = _download_artifact(client, "/artifact", str(tmp_path))

    assert (tmp_path / artifact_path.split("/")[-1]).read_bytes() == b"firstsecond"
    client._new_request.assert_called_once_with(method="GET", path="/artifact")
    request.prepare.assert_called_once()
    # stream must be requested through merge_environment_settings (3rd positional arg) and
    # verify left as the session/env default (verify=None), never disabled.
    session.merge_environment_settings.assert_called_once_with(request.url, {}, True, None, None)
    session.send.assert_called_once_with(request.prepare.return_value, stream=True, verify=True)
    response.iter_content.assert_called_once_with(chunk_size=service.ARTIFACT_DOWNLOAD_CHUNK_SIZE)
    response.raise_for_status.assert_called_once()


def test_download_artifact_removes_partial_file_when_write_fails(monkeypatch, tmp_path):
    client = MagicMock()
    request = MagicMock(url="https://api.tria.ge/artifact")
    client._new_request.return_value = request
    response = MagicMock()
    response.__enter__.return_value = response
    response.iter_content.return_value = [b"partial"]
    session = MagicMock()
    session.__enter__.return_value = session
    session.send.return_value = response
    session.merge_environment_settings.return_value = {}
    monkeypatch.setattr(service, "Session", MagicMock(return_value=session))

    class FailingFile:
        def __init__(self, fd):
            self.fd = fd

        def __enter__(self):
            return self

        def __exit__(self, *args):
            service.os.close(self.fd)

        def write(self, chunk):
            raise OSError("disk full")

    monkeypatch.setattr(service.os, "fdopen", lambda fd, mode: FailingFile(fd))

    with pytest.raises(OSError, match="disk full"):
        _download_artifact(client, "/artifact", str(tmp_path))

    assert not list(tmp_path.iterdir())


# ---------------------------------------------------------------------------
# _attach_dynamic_ontology
# ---------------------------------------------------------------------------


def test_attach_dynamic_ontology_network_connection_without_process_passed_through():
    """A network connection whose primitives have no 'process' key must be forwarded
    unfiltered. The nested-process filtering branch only applies when 'process' is present.
    """
    svc = SimpleNamespace(ontology=MagicMock())
    nc = MagicMock()
    nc.as_primitives.return_value = {"destination_ip": "1.2.3.4"}
    ontres = SimpleNamespace(
        get_processes=lambda: [],
        get_sandboxes=lambda: [],
        get_signatures=lambda: [],
        get_network_connections=lambda: [nc],
    )

    _attach_dynamic_ontology(svc, ontres)  # ty: ignore[invalid-argument-type]

    call_args = svc.ontology.add_result_part.call_args_list
    assert len(call_args) == 1
    _, prims = call_args[0].args
    assert prims == {"destination_ip": "1.2.3.4"}
