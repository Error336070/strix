import hashlib
import json
from pathlib import Path

import pytest

from strix.interface import blue
from strix.interface.blue import BlueError, _copy_snapshot, build_manifest, inventory
from strix.interface.blue_codex import _read_scope_file
from strix.interface.blue_local import run_local, validate_loopback_endpoint
from strix.interface.blue_pe import inspect_pe, validate_helper_record


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


def test_prepare_rejects_linked_target_before_resolving(
    tmp_path: Path,
) -> None:
    target = tmp_path / "owned.cs"
    target.write_text("class Owned {}\n", encoding="utf-8")
    link = tmp_path / "linked.cs"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("This Windows account cannot create symlinks")
    with pytest.raises(BlueError, match="symlink"):
        build_manifest(link, tmp_path / "run", "gpt-6-sol", "deny")


def test_prepare_preserves_binary_snapshot(tmp_path: Path) -> None:
    target = tmp_path / "binary.dll"
    target.write_bytes(b"MZ\x00\x01")
    manifest = build_manifest(target, tmp_path / "evidence", "gpt-6-sol", "deny")
    _copy_snapshot(manifest)
    assert (tmp_path / "evidence" / "inputs" / "binary.dll").read_bytes() == target.read_bytes()


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


def test_pe_helper_is_operator_selected_and_dependency_pinned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "owned.dll"
    target.write_bytes(b"MZ\0\0")
    helper_dir = tmp_path / "tools"
    helper_dir.mkdir()
    helper = helper_dir / "pe-audit.exe"
    helper.write_bytes(b"trusted apphost")
    dependency = helper_dir / "pe-audit.dll"
    dependency.write_bytes(b"trusted implementation")
    output = tmp_path / "run"

    with pytest.raises(ValueError, match="STRIX_PE_AUDIT_HELPER"):
        build_manifest(target, output, "gpt-6-sol", "deny", pe_audit=helper)
    monkeypatch.setenv("STRIX_PE_AUDIT_HELPER", str(helper))
    with pytest.raises(ValueError, match="outside the audited target"):
        build_manifest(helper, output, "gpt-6-sol", "deny", pe_audit=helper)
    manifest = build_manifest(target, output, "gpt-6-sol", "deny", pe_audit=helper)
    assert manifest["pe_audit"]["path"] == str(helper)
    assert {item["name"] for item in manifest["pe_audit"]["bundle"]} == {
        "pe-audit.exe",
        "pe-audit.dll",
    }
    validate_helper_record(manifest)
    dependency.write_bytes(b"changed implementation")
    with pytest.raises(ValueError, match="dependency bundle changed"):
        validate_helper_record(manifest)
    _copy_snapshot(manifest)
    monkeypatch.setattr(
        "strix.interface.blue_pe.subprocess.run",
        lambda *_args, **_kwargs: pytest.fail("Changed helper must not execute"),
    )
    result = inspect_pe(manifest, {"path": "owned.dll"})
    assert result["success"] is False
    assert "dependency bundle changed" in result["contentItems"][0]["text"]


def test_prepared_run_binds_full_manifest_before_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "owned.cs"
    target.write_text("class Owned {}\n", encoding="utf-8")
    manifest = blue.prepare_blue(target, tmp_path / "run")
    manifest_path = Path(manifest["output"]) / "manifest.json"
    preview_hash = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    changed = json.loads(manifest_path.read_text(encoding="utf-8"))
    changed["model"] = "different-model"
    manifest_path.write_text(json.dumps(changed), encoding="utf-8")
    monkeypatch.setattr(
        "builtins.input", lambda _prompt: pytest.fail("No approval prompt expected")
    )
    with pytest.raises(BlueError, match="changed since the scope preview"):
        blue._run_prepared(manifest_path, expected_manifest_sha256=preview_hash)


def test_prepared_run_reports_actual_failed_outcome(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "owned.cs"
    target.write_text("class Owned {}\n", encoding="utf-8")
    manifest = blue.prepare_blue(target, tmp_path / "run")
    manifest_path = Path(manifest["output"]) / "manifest.json"
    phrase = f"RUN {manifest['files'][0]['sha256'][:8]}"
    monkeypatch.setattr(blue, "run_codex", lambda *_args: "failed")
    assert blue._run_prepared(manifest_path, confirmed_phrase=phrase) == "failed"
    assert json.loads(manifest_path.read_text(encoding="utf-8"))["status"] == "failed"

    next_manifest = blue.prepare_blue(target, tmp_path / "next-run")
    next_path = Path(next_manifest["output"]) / "manifest.json"
    monkeypatch.setattr(
        "builtins.input", lambda _prompt: f"RUN {next_manifest['files'][0]['sha256'][:8]}"
    )
    assert blue.run_blue(["run", str(next_path)]) == 1


def test_completed_status_is_published_after_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "owned.cs"
    target.write_text("class Owned {}\n", encoding="utf-8")
    manifest = blue.prepare_blue(target, tmp_path / "run")
    output = Path(manifest["output"])
    manifest_path = output / "manifest.json"
    monkeypatch.setattr(blue, "run_codex", lambda *_args: "completed")

    def delayed_save(_output: Path, _manifest: dict[str, object]) -> int:
        assert json.loads(manifest_path.read_text(encoding="utf-8"))["status"] == "running"
        events = [
            json.loads(line) for line in (output / "blue-events.jsonl").read_text().splitlines()
        ]
        assert all(event["kind"] != "run_finished" for event in events)
        (output / "vulnerabilities.json").write_text("[]\n", encoding="utf-8")
        return 0

    monkeypatch.setattr(blue, "save_findings", delayed_save)
    phrase = f"RUN {manifest['files'][0]['sha256'][:8]}"
    assert blue._run_prepared(manifest_path, confirmed_phrase=phrase) == "completed"
    assert (output / "vulnerabilities.json").exists()
    assert json.loads(manifest_path.read_text(encoding="utf-8"))["status"] == "completed"
    kinds = [
        json.loads(line)["kind"]
        for line in (output / "blue-events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert kinds[-2:] == ["findings_recorded", "run_finished"]


def test_findings_save_failure_marks_run_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "owned.cs"
    target.write_text("class Owned {}\n", encoding="utf-8")
    manifest = blue.prepare_blue(target, tmp_path / "run")
    output = Path(manifest["output"])
    manifest_path = output / "manifest.json"
    monkeypatch.setattr(blue, "run_codex", lambda *_args: "completed")
    monkeypatch.setattr(
        blue, "save_findings", lambda *_args: (_ for _ in ()).throw(ValueError("invalid findings"))
    )
    phrase = f"RUN {manifest['files'][0]['sha256'][:8]}"
    assert blue._run_prepared(manifest_path, confirmed_phrase=phrase) == "failed"
    assert json.loads(manifest_path.read_text(encoding="utf-8"))["status"] == "failed"
    assert "invalid findings" in (output / "findings-validation-error.txt").read_text()
    kinds = [
        json.loads(line)["kind"]
        for line in (output / "blue-events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert kinds[-1] == "run_finished"
    assert "findings_recorded" not in kinds


def test_malformed_manifest_and_closed_stdin_get_clean_cli_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    malformed = tmp_path / "malformed.json"
    malformed.write_text("[]", encoding="utf-8")
    assert blue.run_blue(["run", str(malformed)]) == 2
    target = tmp_path / "owned.cs"
    target.write_text("class Owned {}\n", encoding="utf-8")
    manifest = blue.prepare_blue(target, tmp_path / "run")
    monkeypatch.setattr("builtins.input", lambda _prompt: (_ for _ in ()).throw(EOFError()))
    assert blue.run_blue(["run", str(Path(manifest["output"]) / "manifest.json")]) == 2


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
