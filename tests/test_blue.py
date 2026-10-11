import json
from pathlib import Path

import pytest

from strix.interface.blue import BlueError, _copy_snapshot, build_manifest, inventory
from strix.interface.blue_codex import _read_scope_file
from strix.interface.blue_local import run_local, validate_loopback_endpoint


def test_inventory_hashes_local_file(tmp_path: Path) -> None:
    target = tmp_path / "owned.cs"
    target.write_text("class Safe {}\n", encoding="utf-8")
    entries = inventory(target)
    assert len(entries) == 1
    assert entries[0]["path"] == "owned.cs"
    assert len(entries[0]["sha256"]) == 64


def test_inventory_rejects_symlink(tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    target = tmp_path / "target"
    target.mkdir()
    link = target / "link.txt"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("This Windows account cannot create symlinks")
    with pytest.raises(BlueError, match="symlink"):
        inventory(target)


def test_prepare_rejects_binary_snapshot(tmp_path: Path) -> None:
    target = tmp_path / "binary.dll"
    target.write_bytes(b"MZ\x00\x01")
    manifest = build_manifest(target, tmp_path / "evidence", "gpt-6-sol", "deny")
    with pytest.raises(BlueError, match="UTF-8 text only"):
        _copy_snapshot(manifest)


def test_output_cannot_overlap_target(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "source.cs").write_text("class Safe {}", encoding="utf-8")
    with pytest.raises(BlueError, match="outside"):
        build_manifest(target, target / "evidence", "gpt-6-sol", "deny")


def test_manifest_defaults_to_no_escalation(tmp_path: Path) -> None:
    target = tmp_path / "owned.cs"
    target.write_text("class Safe {}", encoding="utf-8")
    manifest = build_manifest(target, tmp_path / "evidence", "gpt-6-sol", "deny")
    assert manifest["approval"] == "deny"
    assert manifest["sandbox"] == {"type": "readOnly", "networkAccess": False}
    assert manifest["strix_native_tools"] == []


def test_read_tool_denies_unlisted_paths_and_changed_snapshot(tmp_path: Path) -> None:
    target = tmp_path / "owned.cs"
    target.write_text("class Safe {}\n", encoding="utf-8")
    manifest = build_manifest(target, tmp_path / "evidence", "gpt-6-sol", "deny")
    _copy_snapshot(manifest)
    denied = _read_scope_file(manifest, {"path": "..\\secret.txt"})
    assert denied["success"] is False
    allowed = _read_scope_file(manifest, {"path": "owned.cs"})
    assert allowed["success"] is True
    (tmp_path / "evidence" / "inputs" / "owned.cs").write_text("changed", encoding="utf-8")
    assert _read_scope_file(manifest, {"path": "owned.cs"})["success"] is False


def test_local_endpoint_must_be_loopback() -> None:
    validate_loopback_endpoint("http://127.0.0.1:11434/v1")
    with pytest.raises(ValueError):
        validate_loopback_endpoint("https://example.com/v1")
    with pytest.raises(ValueError):
        validate_loopback_endpoint("http://192.168.1.2:11434/v1")


def test_local_model_receives_snapshot_without_tools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "owned.cs"
    target.write_text("class Safe {}\n", encoding="utf-8")
    output = tmp_path / "evidence"
    manifest = build_manifest(
        target, output, "local-test", "deny", "local", "http://127.0.0.1:11434/v1"
    )
    _copy_snapshot(manifest)
    observed: dict[str, object] = {}

    class FakeResponse:
        status = 200

        def read(self, _limit: int) -> bytes:
            return b'{"choices":[{"message":{"content":"No findings."}}]}'

    class FakeConnection:
        def __init__(self, host: str, port: int, timeout: int) -> None:
            observed["connection"] = (host, port, timeout)

        def request(self, method: str, path: str, body: bytes, headers: dict[str, str]) -> None:
            observed["request"] = (method, path, json.loads(body))
            observed["headers"] = headers

        def getresponse(self) -> FakeResponse:
            return FakeResponse()

        def close(self) -> None:
            pass

    monkeypatch.setattr("strix.interface.blue_local.http.client.HTTPConnection", FakeConnection)
    assert run_local(manifest, output) == "completed"
    assert observed["connection"] == ("127.0.0.1", 11434, 120)
    request = observed["request"]
    assert isinstance(request, tuple)
    assert request[0:2] == ("POST", "/v1/chat/completions")
    assert "tools" not in request[2]
    assert "class Safe" in request[2]["messages"][1]["content"]
