import json
import tempfile
from pathlib import Path

from macos_maid.audit_log import AuditLog


def test_audit_log_add_action():
    log = AuditLog()
    log.add_action(
        module="homebrew", action="cleanup", detail="removed 12 old versions", bytes_reclaimed=3000
    )
    assert len(log.actions) == 1
    assert log.actions[0]["module"] == "homebrew"
    assert log.actions[0]["bytes"] == 3000


def test_audit_log_add_error():
    log = AuditLog()
    log.add_error(module="docker", error="docker not found")
    assert len(log.errors) == 1


def test_audit_log_total_bytes():
    log = AuditLog()
    log.add_action(module="a", action="x", detail="", bytes_reclaimed=100)
    log.add_action(module="b", action="y", detail="", bytes_reclaimed=200)
    assert log.total_bytes_reclaimed == 300


def test_audit_log_save_and_load():
    log = AuditLog()
    log.add_action(module="trash", action="empty", detail="emptied trash", bytes_reclaimed=500)

    with tempfile.TemporaryDirectory() as tmpdir:
        log_dir = Path(tmpdir)
        log.save(log_dir)

        saved = log_dir / "last_run.json"
        assert saved.exists()

        data = json.loads(saved.read_text())
        assert data["total_bytes_reclaimed"] == 500
        assert len(data["actions"]) == 1
        assert "timestamp" in data
        assert "duration_seconds" in data


def test_audit_log_records_modules_run():
    log = AuditLog()
    log.record_module("homebrew")
    log.record_module("docker")
    assert log.modules_run == ["homebrew", "docker"]
