"""
Tests for cyber red team orchestration with authentication and automated safety.
"""

import time

from detection.red_team import RedTeamCredential, RedTeamExercise
from detection.threat_detector import CVEEntry, VulnerabilityScanner


class DummyIntrusionDetector:
    def __init__(self, risk_score: float = 0.0):
        self.risk_score = risk_score

    def scan_system(self):
        return {
            "threats_detected": 0,
            "risk_assessment": {
                "overall_risk": "LOW",
                "risk_score": self.risk_score,
            },
        }


class DummyVulnerabilityScanner:
    def __init__(self, vulnerabilities=None):
        self.vulnerabilities = vulnerabilities or []
        self.last_open_ports = None
        self.last_banners = None

    def scan_target(self, open_ports, banners=None):
        self.last_open_ports = open_ports
        self.last_banners = banners
        return {
            "open_ports": open_ports,
            "services": [],
            "vulnerabilities": self.vulnerabilities,
            "os_inference": {},
            "risk_score": 0.0,
        }


class DummyPolicyEngine:
    def __init__(self):
        self.last_input = None

    def evaluate(self, input_data):
        self.last_input = input_data
        return (["TEST_ACTION"], [])


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


def test_expired_credentials_are_rejected():
    """Expired credentials should not authenticate."""
    exercise = RedTeamExercise(allowed_tokens={"VALID"})
    credentials = RedTeamCredential(
        team_id="alpha",
        token="VALID",
        expires_at=time.time() - 10,
    )

    result = exercise.run_assessment(credentials)

    assert result["success"] is False
    assert result["authentication"]["authenticated"] is False


def test_generated_token_one_time_retrieval_and_use():
    """Auto-generated token should be retrievable once and remain valid."""
    dummy_detector = DummyIntrusionDetector()
    dummy_scanner = DummyVulnerabilityScanner()
    exercise = RedTeamExercise(
        intrusion_detector=dummy_detector,
        vulnerability_scanner=dummy_scanner,
    )

    token = exercise.generated_token
    assert token is not None
    assert exercise.generated_token is None  # Cleared after first access

    credentials = RedTeamCredential(team_id="alpha", token=token)
    result = exercise.run_assessment(credentials)

    assert result["authentication"]["authenticated"] is True
    assert result["success"] is True


def test_scope_is_preserved_in_authentication():
    """Scope should be echoed back in authentication result."""
    scope = ["scan", "report"]
    exercise = RedTeamExercise(allowed_tokens={"VALID"})
    credentials = RedTeamCredential(team_id="alpha", token="VALID", scope=scope)

    result = exercise.run_assessment(credentials)

    assert result["authentication"]["scope"] == scope


def test_default_ports_used_when_none_provided():
    """Default ports should be applied when open_ports is None."""
    dummy_scanner = DummyVulnerabilityScanner()
    exercise = RedTeamExercise(
        intrusion_detector=DummyIntrusionDetector(),
        vulnerability_scanner=dummy_scanner,
        policy_engine=DummyPolicyEngine(),
        allowed_tokens={"VALID"},
    )
    credentials = RedTeamCredential(team_id="alpha", token="VALID")

    exercise.run_assessment(credentials, open_ports=None, banners=None)

    assert dummy_scanner.last_open_ports == list(RedTeamExercise.DEFAULT_PORTS)
    assert dummy_scanner.last_banners is None


def test_negative_inputs_are_sanitized():
    """Safety inputs should be sanitized to non-negative values."""
    policy = DummyPolicyEngine()
    exercise = RedTeamExercise(
        intrusion_detector=DummyIntrusionDetector(),
        vulnerability_scanner=DummyVulnerabilityScanner(),
        policy_engine=policy,
        allowed_tokens={"VALID"},
    )
    credentials = RedTeamCredential(team_id="alpha", token="VALID")

    exercise.run_assessment(
        credentials,
        failed_logins=-5,
        time_window_minutes=0,
        data_transfer_mb=-1.0,
        new_location=True,
        destination_external=True,
    )

    assert policy.last_input["failed_logins"] == 0
    assert policy.last_input["time_window_minutes"] == 1
    assert policy.last_input["data_transfer_mb"] == 0.0
    assert policy.last_input["new_location"] is True
    assert policy.last_input["destination_external"] is True
