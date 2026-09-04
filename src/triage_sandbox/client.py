"""Minimal HTTP client for the Hatching Triage API.

Replaces the unmaintained ``hatching-triage`` package (0.2.0, 2023-10-09), which
disabled TLS verification on every request via
``merge_environment_settings(url, {}, None, False, None)`` and silenced the
resulting warnings with ``urllib3.disable_warnings()``.

This client keeps a single long-lived :class:`requests.Session` with
``verify`` left at its default of ``True`` (so ``REQUESTS_CA_BUNDLE`` and proxy
environment variables are still honoured) and an explicit timeout on every call.
Only the endpoints the service actually uses are implemented.
"""

import json
import os
import platform
import tempfile
from typing import Any, BinaryIO, Optional

import requests
from requests.utils import quote

DEFAULT_ROOT_URL = "https://api.tria.ge"
ARTIFACT_CHUNK_SIZE = 1024 * 1024

# JSON calls are quick; artifact downloads stream multi-MB bodies. requests' timeout
# is connect + inter-chunk read (not a total budget), so a slow large memdump is safe.
REQUEST_TIMEOUT = int(os.environ.get("TRIAGE_REQUEST_TIMEOUT", "30"))
DOWNLOAD_TIMEOUT = int(os.environ.get("TRIAGE_DOWNLOAD_TIMEOUT", "300"))

USER_AGENT = f"Assemblyline TriageSandbox Python/{platform.python_version()}"


class ServerError(Exception):
    """A non-2xx response from the Triage API."""

    def __init__(self, status: int, kind: str = "", message: str = "") -> None:
        super().__init__(f"triage: {status} {kind}: {message}")
        self.status = status
        self.kind = kind
        self.message = message

    def __str__(self) -> str:
        return f"triage: {self.status} {self.kind}: {self.message}"

    @classmethod
    def from_response(cls, response: requests.Response) -> "ServerError":
        try:
            body = response.json()
        except ValueError:
            body = {}
        if not isinstance(body, dict):
            body = {}
        return cls(status=response.status_code, kind=body.get("error", ""), message=body.get("message", ""))


class TriageClient:
    def __init__(
        self,
        token: Optional[str],
        root_url: Optional[str] = None,
        timeout: Optional[float] = None,
        download_timeout: Optional[float] = None,
    ) -> None:
        self.root_url = (root_url or DEFAULT_ROOT_URL).rstrip("/")
        self.timeout = timeout or REQUEST_TIMEOUT
        self.download_timeout = download_timeout or DOWNLOAD_TIMEOUT
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {token or ''}", "User-Agent": USER_AGENT})

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[dict[str, Any]] = None,  # type: ignore[type-arg]
        files: Optional[dict[str, Any]] = None,  # type: ignore[type-arg]
    ) -> dict[str, Any]:  # type: ignore[type-arg]
        response = self.session.request(
            method, f"{self.root_url}{path}", json=json_body, files=files, timeout=self.timeout
        )
        if not response.ok:
            raise ServerError.from_response(response)
        return response.json()

    def sample_by_id(self, sample_id: str) -> dict[str, Any]:  # type: ignore[type-arg]
        return self._request("GET", f"/v0/samples/{sample_id}")

    def task_report(self, sample_id: str, task_id: str) -> dict[str, Any]:  # type: ignore[type-arg]
        return self._request("GET", f"/v0/samples/{sample_id}/{task_id}/report_triage.json")

    def overview_report(self, sample_id: str) -> dict[str, Any]:  # type: ignore[type-arg]
        return self._request("GET", f"/v1/samples/{sample_id}/overview.json")

    def search_one(self, query: str) -> Optional[dict[str, Any]]:  # type: ignore[type-arg]
        """Return the most recent sample matching ``query``, or ``None``."""
        page = self._request("GET", f"/v0/search?query={quote(query)}&limit=1")
        data = page.get("data") or []
        return data[0] if data else None

    def submit_sample_url(self, url: str) -> dict[str, Any]:  # type: ignore[type-arg]
        return self._request(
            "POST",
            "/v0/samples",
            json_body={"kind": "url", "url": url, "interactive": False, "profiles": []},
        )

    def submit_sample_file(
        self, filename: str, file: BinaryIO, network: str = "internet", timeout: int = 150
    ) -> dict[str, Any]:  # type: ignore[type-arg]
        payload = {
            "kind": "file",
            "interactive": False,
            "profiles": [],
            "defaults": {"timeout": timeout, "network": network},
        }
        return self._request(
            "POST",
            "/v0/samples",
            files={
                "_json": (None, json.dumps(payload), "application/json"),
                "file": (filename, file),
            },
        )

    def download_task_file(self, sample_id: str, task_id: str, name: str, directory: str) -> str:
        """Stream a task artifact into a new temp file under ``directory``; return its path."""
        url = f"{self.root_url}/v0/samples/{sample_id}/{task_id}/{name}"
        with self.session.get(url, stream=True, timeout=self.download_timeout) as response:
            if not response.ok:
                raise ServerError.from_response(response)
            fd, temp_path = tempfile.mkstemp(dir=directory)
            try:
                with os.fdopen(fd, "wb") as fh:
                    for chunk in response.iter_content(chunk_size=ARTIFACT_CHUNK_SIZE):
                        if chunk:
                            fh.write(chunk)
            except BaseException:
                os.unlink(temp_path)
                raise
        return temp_path

    def close(self) -> None:
        self.session.close()
