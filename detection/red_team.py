"""
Cyber Red Team orchestration module.

Provides deterministic, policy-driven red team exercises that:
- authenticate red team credentials
- run vulnerability and intrusion assessments
- apply automated safety policies to contain findings
"""

import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from detection.intrusion_detector import IntrusionDetector
from detection.threat_detector import VulnerabilityScanner
from response.lts_engine import PolicyEngine, create_security_policies


@dataclass
class RedTeamCredential:
    """
    Represents credentials for a red team engagement.
    
    Attributes:
        team_id: Identifier for the red team or engagement.
        token: Authentication token used to authorize the red team.
        scope: List of permitted operations or targets for this credential.
        expires_at: Optional UNIX timestamp in seconds (UTC) that marks when the credential is no longer valid.
    """

    team_id: str
    token: str
    scope: List[str] = field(default_factory=list)
    expires_at: Optional[float] = None  # UNIX timestamp (seconds, UTC)


class RedTeamExercise:
    """Coordinates authenticated red team assessments with automated safety."""

    DEFAULT_PORTS = (22, 80, 443)
    # Normalize risk_score (0-10) into a 0-1 confidence value
    CONFIDENCE_DIVISOR = 10.0
    # Length in bytes used when auto-generating red team tokens
    TOKEN_BYTES = 32

    def __init__(
        self,
        intrusion_detector: Optional[IntrusionDetector] = None,
        vulnerability_scanner: Optional[VulnerabilityScanner] = None,
        policy_engine: Optional[PolicyEngine] = None,
        allowed_tokens: Optional[Set[str]] = None,
    ):
        self._intrusion_detector = intrusion_detector or IntrusionDetector()
        self._vulnerability_scanner = vulnerability_scanner or VulnerabilityScanner()
        self._policy_engine = policy_engine or create_security_policies()

        if allowed_tokens:
            self._allowed_tokens: Set[str] = set(allowed_tokens)
            self._generated_token: Optional[str] = None
        else:
            token = secrets.token_urlsafe(self.TOKEN_BYTES)
            self._allowed_tokens = {token}
            self._generated_token = token

    def authenticate(self, credentials: RedTeamCredential) -> Dict[str, Any]:
        """Validate red team credentials and scope."""
        now = time.time()
        token_valid = credentials.token in self._allowed_tokens
        is_expired = (
            credentials.expires_at is not None and credentials.expires_at < now
        )
        authenticated = token_valid and not is_expired

        if not token_valid:
            reason = "Invalid token"
        elif is_expired:
            reason = "Token expired"
        else:
            reason = "Authenticated"

        return {
            "team_id": credentials.team_id,
            "scope": credentials.scope,
            "authenticated": authenticated,
            "reason": reason,
        }

    @property
    def generated_token(self) -> Optional[str]:
        """
        Return the auto-generated token when no allowlist was provided.
        
        This is a one-time retrieval of a sensitive credential. The token is
        cleared from memory after the first access to reduce exposure risk.
        Callers must treat the returned value as secret and avoid logging it.
        """
        token = self._generated_token
        self._generated_token = None
        return token
    def run_assessment(
        self,
        credentials: RedTeamCredential,
        open_ports: Optional[List[int]] = None,
        banners: Optional[Dict[int, str]] = None,
        failed_logins: int = 0,
        time_window_minutes: int = 15,
        new_location: bool = False,
        data_transfer_mb: float = 0.0,
        destination_external: bool = False,
    ) -> Dict[str, Any]:
        """
        Execute a red team self-assessment with authentication and safety controls.
        
        Intrusion detection runs against the current host; vulnerability scanning
        uses the supplied target characteristics (ports/banners).
        """
        auth = self.authenticate(credentials)
        if not auth["authenticated"]:
            empty_safety = self._build_safety([], [], "NONE", 0.0)
            return {
                "success": False,
                "authentication": auth,
                "intrusion_overview": {},
                "vulnerabilities": {},
                "automated_safety": empty_safety,
            }

        sanitized_failed_logins = max(0, failed_logins)
        sanitized_time_window = max(1, time_window_minutes)
        sanitized_data_transfer = max(0.0, data_transfer_mb)

        port_set = open_ports or list(self.DEFAULT_PORTS)
        intrusion_result = self._intrusion_detector.scan_system()
        vuln_result = self._vulnerability_scanner.scan_target(
            open_ports=port_set,
            banners=banners,
        )

        highest_severity = self._highest_severity(vuln_result["vulnerabilities"])
        risk_assessment = intrusion_result.get("risk_assessment", {})
        safety_context = {
            "vulnerability_severity": highest_severity,
            "failed_logins": sanitized_failed_logins,
            "time_window_minutes": sanitized_time_window,
            "login_risk_score": risk_assessment.get("risk_score", 0),
            "new_location": new_location,
            "threat_type": "red_team",
            "confidence": min(
                1.0,
                vuln_result["risk_score"] / self.CONFIDENCE_DIVISOR,
            ),
            "data_transfer_mb": sanitized_data_transfer,
            "destination_external": destination_external,
        }
        safety_actions, safety_violations = self._policy_engine.evaluate(
            safety_context
        )

        return {
            "success": True,
            "authentication": auth,
            "intrusion_overview": {
                "threats_detected": intrusion_result["threats_detected"],
                "risk": intrusion_result["risk_assessment"]["overall_risk"],
            },
            "vulnerabilities": vuln_result,
            "automated_safety": self._build_safety(
                safety_actions,
                safety_violations,
                highest_severity,
                vuln_result["risk_score"],
            ),
        }

    @staticmethod
    def _highest_severity(vulnerabilities: List[Dict[str, Any]]) -> str:
        """Return highest severity from vulnerability list."""
        if not vulnerabilities:
            return "NONE"

        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        for level in order:
            if any(v.get("severity") == level for v in vulnerabilities):
                return level
        return "UNKNOWN"

    @staticmethod
    def _build_safety(
        actions: List[str],
        violations: List[Dict[str, Any]],
        highest_severity: str,
        risk_score: float,
    ) -> Dict[str, Any]:
        """Create a consistent automated safety payload."""
        return {
            "actions": actions,
            "violations": violations,
            "highest_severity": highest_severity,
            "risk_score": risk_score,
        }
