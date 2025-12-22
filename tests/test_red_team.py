"""
Tests for cyber red team orchestration with authentication and automated safety.
"""

from detection.red_team import RedTeamCredential, RedTeamExercise
from detection.threat_detector import CVEEntry, VulnerabilityScanner


def test_red_team_assessment_requires_valid_token():
    """Red team assessment should fail when authentication is invalid."""
    exercise = RedTeamExercise(allowed_tokens={"REDTEAM-DEFAULT"})
    credentials = RedTeamCredential(team_id="alpha", token="")

    result = exercise.run_assessment(credentials)

    assert result["success"] is False
    assert result["authentication"]["authenticated"] is False
    assert result["automated_safety"]["highest_severity"] == "NONE"
    assert result["automated_safety"]["actions"] == []


def test_red_team_assessment_applies_automated_safety():
    """Authenticated assessment should evaluate vulnerabilities and safety actions."""
    vuln_scanner = VulnerabilityScanner()
    vuln_scanner.load_cve_entry(
        CVEEntry(
            cve_id="CVE-2025-0001",
            severity="CRITICAL",
            cvss_score=9.9,
            affected_products=["nginx"],
            affected_versions=["1.18.0"],
            description="Test critical vulnerability",
        )
    )

    exercise = RedTeamExercise(
        vulnerability_scanner=vuln_scanner,
        allowed_tokens={"REDTEAM-DEFAULT"},
    )
    credentials = RedTeamCredential(team_id="alpha", token="REDTEAM-DEFAULT")

    result = exercise.run_assessment(
        credentials,
        open_ports=[80],
        banners={80: "nginx/1.18.0"},
    )

    assert result["success"] is True
    assert result["authentication"]["authenticated"] is True
    assert result["automated_safety"]["highest_severity"] == "CRITICAL"
    assert "BLOCK_BUILD" in result["automated_safety"]["actions"]
    assert result["vulnerabilities"]["risk_score"] >= 0
