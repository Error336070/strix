"""Browser origin checks for the local viewer's state-changing endpoints."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import TYPE_CHECKING

import pytest

from strix.interface.viewer.server import authorized_url, serve


if TYPE_CHECKING:
    from pathlib import Path


def _request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
) -> tuple[int, dict[str, str], bytes]:
    request = urllib.request.Request(  # noqa: S310 - test server only
        url, data=data, headers=headers or {}, method=method
    )
    try:
        with urllib.request.urlopen(request) as response:  # noqa: S310 - test server only
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), error.read()


def test_steering_rejects_cross_origin_browser_posts(tmp_path: Path) -> None:
    run_dir = tmp_path / "runs" / "live"
    run_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text(
        json.dumps({"run_name": "live", "status": "running", "case_id": "case"}),
        encoding="utf-8",
    )
    delivered: list[tuple[str, str]] = []

    def steer(agent_id: str, message: str) -> bool:
        delivered.append((agent_id, message))
        return True

    server, url, token = serve(run_dir, open_browser=False, steer_handler=steer)
    try:
        status, headers, _ = _request(authorized_url(url, token))
        assert status == 200
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        body = json.dumps({"run": "live", "agent_id": "root", "message": "focus on auth"}).encode()
        base_headers = {"Cookie": cookie, "Content-Type": "text/plain"}

        for origin, fetch_site in (
            ("http://127.0.0.1:9999", "same-site"),
            ("null", "cross-site"),
            (url, "cross-site"),
        ):
            status, _, response = _request(
                f"{url}/api/agents/steer",
                method="POST",
                headers={**base_headers, "Origin": origin, "Sec-Fetch-Site": fetch_site},
                data=body,
            )
            assert status == 403
            assert json.loads(response)["error"] == "cross_origin"
        assert delivered == []

        status, _, _ = _request(
            f"{url}/api/agents/steer",
            method="POST",
            headers={**base_headers, "Origin": url, "Sec-Fetch-Site": "same-origin"},
            data=body,
        )
        assert status == 200
        assert delivered == [("root", "focus on auth")]

        # The new POST boundary must not close the shared run history.
        status, _, response = _request(f"{url}/api/runs", headers={"Cookie": cookie})
        assert status == 200
        assert json.loads(response)["runs"][0]["name"] == "live"
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("path", ["/api/auth/forget", "/api/report/send"])
def test_other_privileged_posts_reject_cross_origin(tmp_path: Path, path: str) -> None:
    run_dir = tmp_path / "runs" / "live"
    run_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text('{"status":"running"}', encoding="utf-8")
    server, url, token = serve(run_dir, open_browser=False)
    try:
        _, headers, _ = _request(authorized_url(url, token))
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        status, _, response = _request(
            f"{url}{path}",
            method="POST",
            headers={"Cookie": cookie, "Origin": "http://127.0.0.1:9999"},
            data=b"{}",
        )
        assert status == 403
        assert json.loads(response)["error"] == "cross_origin"
    finally:
        server.shutdown()
        server.server_close()
