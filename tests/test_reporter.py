# tests/test_reporter.py
from macos_maid.modules.base import AuditResult, CleanResult, Finding, ScanResult
from macos_maid.reporter import Reporter
from macos_maid.system import Platform


def _fake_platform() -> Platform:
    return Platform(
        arch="arm64",
        macos_version=(15, 4, 0),
        macos_name="Sequoia",
        filesystem="apfs",
        homebrew_prefix="/opt/homebrew",
        wifi_interface="en0",
        is_apple_silicon=True,
    )


def test_reporter_terminal_output_has_header():
    reporter = Reporter(platform=_fake_platform(), output_format="terminal")
    clean_results: dict[str, CleanResult] = {
        "trash": CleanResult(items_cleaned=["emptied trash"], bytes_reclaimed=1000000, errors=[]),
    }
    output = reporter.format_clean(clean_results)
    assert "Sequoia" in output
    assert "arm64" in output


def test_reporter_json_output():
    reporter = Reporter(platform=_fake_platform(), output_format="json")
    clean_results: dict[str, CleanResult] = {
        "trash": CleanResult(items_cleaned=["emptied trash"], bytes_reclaimed=1000000, errors=[]),
    }
    output = reporter.format_clean(clean_results)
    import json

    data = json.loads(output)
    assert "trash" in data


def test_reporter_audit_output():
    reporter = Reporter(platform=_fake_platform(), output_format="terminal")
    audit_results: dict[str, AuditResult] = {
        "system_integrity": AuditResult(
            status="fail",
            findings=[
                Finding(severity="pass", title="SIP enabled", detail="OK"),
                Finding(severity="fail", title="Firewall off", detail="Disabled"),
            ],
        ),
    }
    output = reporter.format_audit(audit_results)
    assert "SIP enabled" in output or "Firewall off" in output


def test_reporter_markdown_output():
    reporter = Reporter(platform=_fake_platform(), output_format="markdown")
    clean_results: dict[str, CleanResult] = {
        "trash": CleanResult(items_cleaned=["emptied trash"], bytes_reclaimed=1000000, errors=[]),
    }
    output = reporter.format_clean(clean_results)
    assert "#" in output  # markdown headers


def test_reporter_dry_run_output():
    reporter = Reporter(platform=_fake_platform(), output_format="terminal")
    scan_results: dict[str, ScanResult] = {
        "homebrew": ScanResult(
            items=["would update 5 packages"], bytes_reclaimable=5000000, requires_sudo=False
        ),
    }
    output = reporter.format_dry_run(scan_results)
    assert "would update" in output or "DRY RUN" in output.upper() or "Preview" in output


def test_format_bytes():
    from macos_maid.reporter import format_bytes

    assert format_bytes(0) == "0 B"
    assert format_bytes(1024) == "1.0 KB"
    assert format_bytes(1048576) == "1.0 MB"
    assert format_bytes(1073741824) == "1.0 GB"
