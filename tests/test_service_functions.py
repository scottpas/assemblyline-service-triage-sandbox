"""Unit tests for module-level functions in triage_sandbox.service."""

from types import SimpleNamespace
from unittest.mock import MagicMock

from triage.client import ServerError

from triage_sandbox.service import _is_submission_not_reported, _retry_on_not_found, wait_for_submission


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
