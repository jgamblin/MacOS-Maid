# tests/modules/test_network.py
from unittest.mock import patch

import pytest

from macos_maid.modules.base import AuditResult, CleanResult, Finding, ScanResult
from macos_maid.modules.network import NetworkModule


@pytest.fixture
def network_module():
    """Create a NetworkModule instance for testing."""
    return NetworkModule()


def test_network_module_metadata(network_module):
    """Test module metadata is set correctly."""
    assert network_module.name == "network"
    assert network_module.category == "security"
    assert network_module.requires_sudo is True


def test_network_scan_returns_flush_dns(network_module):
    """Test scan returns DNS flush action."""
    result = network_module.scan()

    assert isinstance(result, ScanResult)
    assert len(result.items) == 1
    assert result.items[0] == "Flush DNS cache"
    assert result.bytes_reclaimable == 0
    assert result.requires_sudo is True


def test_network_clean_flushes_dns(network_module):
    """Test clean successfully flushes DNS cache."""
    with patch.object(network_module, "_flush_dns") as mock_flush:
        mock_flush.return_value = None

        result = network_module.clean()

        assert isinstance(result, CleanResult)
        assert mock_flush.called
        assert len(result.items_cleaned) == 1
        assert result.items_cleaned[0] == "Flushed DNS cache"
        assert result.bytes_reclaimed == 0
        assert result.errors == []


def test_network_clean_handles_flush_error(network_module):
    """Test clean handles DNS flush errors gracefully."""
    with patch.object(network_module, "_flush_dns") as mock_flush:
        mock_flush.side_effect = Exception("DNS flush failed")

        result = network_module.clean()

        assert isinstance(result, CleanResult)
        assert result.items_cleaned == []
        assert result.bytes_reclaimed == 0
        assert len(result.errors) == 1
        assert "Failed to flush DNS" in result.errors[0]


def test_network_audit_firewall_enabled(network_module):
    """Test audit reports pass when firewall is enabled."""
    with (
        patch.object(network_module, "_check_firewall_enabled", return_value=True),
        patch.object(network_module, "_get_open_ports", return_value=[]),
        patch.object(network_module, "_get_vpn_profiles", return_value=[]),
    ):
        result = network_module.audit()

        assert isinstance(result, AuditResult)
        # Status should be pass or info (info for informational findings)
        assert result.status in ["pass", "info"]
        # Should have findings for firewall (pass), open ports, and VPN
        assert len(result.findings) >= 1
        # Check firewall finding
        firewall_finding = next(f for f in result.findings if "firewall" in f.title.lower())
        assert firewall_finding.severity == "pass"


def test_network_audit_firewall_disabled(network_module):
    """Test audit reports fail when firewall is disabled."""
    with (
        patch.object(network_module, "_check_firewall_enabled", return_value=False),
        patch.object(network_module, "_get_open_ports", return_value=[]),
        patch.object(network_module, "_get_vpn_profiles", return_value=[]),
    ):
        result = network_module.audit()

        assert isinstance(result, AuditResult)
        assert result.status == "fail"
        # Check firewall finding
        firewall_finding = next(f for f in result.findings if "firewall" in f.title.lower())
        assert firewall_finding.severity == "fail"
        assert "disabled" in firewall_finding.detail.lower()


def test_network_audit_with_open_ports(network_module):
    """Test audit reports open ports."""
    open_ports = [
        ("8080", "Python"),
        ("3000", "node"),
    ]

    with (
        patch.object(network_module, "_check_firewall_enabled", return_value=True),
        patch.object(network_module, "_get_open_ports", return_value=open_ports),
        patch.object(network_module, "_get_vpn_profiles", return_value=[]),
    ):
        result = network_module.audit()

        assert isinstance(result, AuditResult)
        # Status should be at least "info" or "warn"
        assert result.status in ["pass", "info", "warn"]
        # Should have a finding about open ports
        port_findings = [f for f in result.findings if "port" in f.title.lower()]
        assert len(port_findings) > 0


def test_network_audit_with_vpn_profiles(network_module):
    """Test audit reports VPN profiles."""
    vpn_profiles = ["Work VPN", "Home VPN"]

    with (
        patch.object(network_module, "_check_firewall_enabled", return_value=True),
        patch.object(network_module, "_get_open_ports", return_value=[]),
        patch.object(network_module, "_get_vpn_profiles", return_value=vpn_profiles),
    ):
        result = network_module.audit()

        assert isinstance(result, AuditResult)
        # Should have a finding about VPN
        vpn_findings = [f for f in result.findings if "vpn" in f.title.lower()]
        assert len(vpn_findings) > 0


def test_network_audit_empty_does_not_crash(network_module):
    """Test audit with no findings doesn't crash."""
    with (
        patch.object(network_module, "_check_firewall_enabled", return_value=True),
        patch.object(network_module, "_get_open_ports", return_value=[]),
        patch.object(network_module, "_get_vpn_profiles", return_value=[]),
    ):
        result = network_module.audit()

        assert isinstance(result, AuditResult)
        assert result.status in ["pass", "info", "warn", "fail"]
        assert isinstance(result.findings, list)
