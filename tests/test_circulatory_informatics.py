"""
Tests for Circulatory Informatics Framework.

Tests the biological-to-cybersecurity mapping framework including:
- All nine biological system components
- System interconnections
- Symptom correlation
- Systemic diagnosis
"""

import json
import time
import pytest
from typing import Dict, Any

from core.circulatory_informatics import (
    BiologicalSystem,
    SystemHealth,
    DiagnosticSeverity,
    SystemMetrics,
    DiagnosticFinding,
    SecurityEvent,
    CirculatorySystem,
    NervousSystem,
    ImmuneSystem,
    SkeletalSystem,
    MuscularSystem,
    LymphaticSystem,
    RespiratorySystem,
    DigestiveSystem,
    EndocrineSystem,
    SecurityOrganism,
)


# =============================================================================
# Helper Functions
# =============================================================================

def create_test_event(
    event_id: str = "EVT-001",
    event_type: str = "test_event",
    severity: str = "MEDIUM",
    payload: Dict[str, Any] = None
) -> SecurityEvent:
    """Create a test security event."""
    return SecurityEvent(
        event_id=event_id,
        timestamp=time.time(),
        source_system=BiologicalSystem.DIGESTIVE,
        event_type=event_type,
        severity=severity,
        payload=payload or {"test": "data"}
    )


# =============================================================================
# BiologicalSystem Enum Tests
# =============================================================================

class TestBiologicalSystem:
    """Tests for BiologicalSystem enum."""
    
    def test_all_nine_systems_defined(self):
        """Verify all nine biological systems are defined."""
        systems = list(BiologicalSystem)
        assert len(systems) == 9
        
        expected = {
            "circulatory", "nervous", "immune", "skeletal",
            "muscular", "lymphatic", "respiratory", "digestive", "endocrine"
        }
        actual = {s.value for s in systems}
        assert actual == expected
    
    def test_system_values(self):
        """Test specific system values."""
        assert BiologicalSystem.CIRCULATORY.value == "circulatory"
        assert BiologicalSystem.NERVOUS.value == "nervous"
        assert BiologicalSystem.IMMUNE.value == "immune"


# =============================================================================
# SystemMetrics Tests
# =============================================================================

class TestSystemMetrics:
    """Tests for SystemMetrics dataclass."""
    
    def test_default_values(self):
        """Test default metric values."""
        metrics = SystemMetrics(system=BiologicalSystem.CIRCULATORY)
        
        assert metrics.system == BiologicalSystem.CIRCULATORY
        assert metrics.health == SystemHealth.HEALTHY
        assert metrics.throughput == 0.0
        assert metrics.latency_ms == 0.0
        assert metrics.error_rate == 0.0
        assert metrics.capacity_used == 0.0
    
    def test_custom_values(self):
        """Test custom metric values."""
        metrics = SystemMetrics(
            system=BiologicalSystem.NERVOUS,
            health=SystemHealth.DEGRADED,
            throughput=100.0,
            latency_ms=50.0
        )
        
        assert metrics.health == SystemHealth.DEGRADED
        assert metrics.throughput == 100.0


# =============================================================================
# SecurityEvent Tests
# =============================================================================

class TestSecurityEvent:
    """Tests for SecurityEvent dataclass."""
    
    def test_event_creation(self):
        """Test event creation."""
        event = create_test_event()
        
        assert event.event_id == "EVT-001"
        assert event.event_type == "test_event"
        assert event.severity == "MEDIUM"
        assert event.payload == {"test": "data"}
        assert event.enrichments == {}
        assert event.processing_trail == []
    
    def test_event_enrichment(self):
        """Test event enrichment."""
        event = create_test_event()
        event.enrichments["geo"] = {"country": "US"}
        
        assert "geo" in event.enrichments
        assert event.enrichments["geo"]["country"] == "US"


# =============================================================================
# CirculatorySystem Tests
# =============================================================================

class TestCirculatorySystem:
    """Tests for CirculatorySystem (Data Fabric)."""
    
    def test_initialization(self):
        """Test system initialization."""
        system = CirculatorySystem()
        
        assert system.system_type == BiologicalSystem.CIRCULATORY
        assert system.metrics.health == SystemHealth.HEALTHY
    
    def test_publish_event(self):
        """Test event publishing."""
        system = CirculatorySystem()
        event = create_test_event()
        
        result = system.publish(event)
        
        assert result is True
        assert "circulatory:" in event.processing_trail[0]
    
    def test_subscribe_and_pump(self):
        """Test subscriber notification on pump."""
        circulatory = CirculatorySystem()
        nervous = NervousSystem()
        
        circulatory.subscribe(nervous)
        event = create_test_event()
        circulatory.publish(event)
        
        processed = circulatory.pump()
        
        assert processed == 1
    
    def test_queue_overflow_detection(self):
        """Test queue overflow detection."""
        system = CirculatorySystem()
        system._max_queue_size = 5  # Small queue for testing
        
        # Fill the queue
        for i in range(6):
            event = create_test_event(event_id=f"EVT-{i:03d}")
            result = system.publish(event)
            if i < 5:
                assert result is True
            else:
                assert result is False  # Queue full
        
        assert system.metrics.health == SystemHealth.DEGRADED
    
    def test_diagnose_healthy(self):
        """Test diagnosis when healthy."""
        system = CirculatorySystem()
        findings = system.diagnose()
        
        assert findings == []  # No issues
    
    def test_diagnose_blockage(self):
        """Test diagnosis of blockage."""
        system = CirculatorySystem()
        system._max_queue_size = 10
        
        # Fill queue to >80%
        for i in range(9):
            event = create_test_event(event_id=f"EVT-{i:03d}")
            system._event_queue.append(event)
        
        findings = system.diagnose()
        
        assert len(findings) > 0
        assert findings[0].severity == DiagnosticSeverity.CRITICAL
        assert "blockage" in findings[0].diagnosis.lower()


# =============================================================================
# NervousSystem Tests
# =============================================================================

class TestNervousSystem:
    """Tests for NervousSystem (Central Analytics)."""
    
    def test_initialization(self):
        """Test system initialization."""
        system = NervousSystem()
        
        assert system.system_type == BiologicalSystem.NERVOUS
    
    def test_add_correlation_rule(self):
        """Test adding correlation rules."""
        system = NervousSystem()
        
        system.add_correlation_rule(
            rule_id="RULE-001",
            conditions=[lambda e: e.severity == "HIGH"],
            correlation_window=300.0
        )
        
        assert len(system._correlation_rules) == 1
    
    def test_process_with_correlation(self):
        """Test event processing with correlation."""
        system = NervousSystem()
        
        system.add_correlation_rule(
            rule_id="HIGH_SEVERITY",
            conditions=[lambda e: e.severity == "HIGH"]
        )
        
        event = create_test_event(severity="HIGH")
        result = system.process(event)
        
        assert "nervous:" in result.processing_trail[-1]
    
    def test_diagnose_no_rules(self):
        """Test diagnosis with no rules."""
        system = NervousSystem()
        findings = system.diagnose()
        
        assert len(findings) > 0
        assert findings[0].severity == DiagnosticSeverity.ERROR
        assert "no correlation rules" in findings[0].symptom.lower()


# =============================================================================
# ImmuneSystem Tests
# =============================================================================

class TestImmuneSystem:
    """Tests for ImmuneSystem (Threat Intelligence)."""
    
    def test_initialization(self):
        """Test system initialization."""
        system = ImmuneSystem()
        
        assert system.system_type == BiologicalSystem.IMMUNE
    
    def test_add_signature(self):
        """Test adding threat signatures."""
        system = ImmuneSystem()
        
        system.add_signature(
            signature_id="SIG-001",
            pattern="malicious_pattern",
            threat_type="malware",
            response_action="QUARANTINE"
        )
        
        assert "SIG-001" in system._threat_signatures
    
    def test_signature_matching(self):
        """Test signature matching."""
        system = ImmuneSystem()
        
        system.add_signature(
            signature_id="SIG-001",
            pattern="evil",
            threat_type="malware",
            response_action="QUARANTINE"
        )
        
        event = create_test_event(payload={"content": "evil_payload"})
        result = system.process(event)
        
        assert "threat_match" in result.enrichments
        assert "antibody_deployed" in result.enrichments
    
    def test_learn_pattern(self):
        """Test pattern learning."""
        system = ImmuneSystem()
        event = create_test_event()
        
        system.learn_pattern(event)
        
        assert len(system._learned_patterns) == 1
    
    def test_diagnose_no_signatures(self):
        """Test diagnosis with no signatures."""
        system = ImmuneSystem()
        findings = system.diagnose()
        
        assert len(findings) > 0
        assert "no threat signatures" in findings[0].symptom.lower()


# =============================================================================
# SkeletalSystem Tests
# =============================================================================

class TestSkeletalSystem:
    """Tests for SkeletalSystem (Governance)."""
    
    def test_initialization(self):
        """Test system initialization."""
        system = SkeletalSystem()
        
        assert system.system_type == BiologicalSystem.SKELETAL
    
    def test_add_policy(self):
        """Test adding policies."""
        system = SkeletalSystem()
        
        system.add_policy(
            policy_id="POL-001",
            name="Test Policy",
            rules=[lambda x: x.get("valid", False)],
            severity="HIGH"
        )
        
        assert "POL-001" in system._policies
    
    def test_policy_violation_detection(self):
        """Test policy violation detection."""
        system = SkeletalSystem()
        
        system.add_policy(
            policy_id="POL-001",
            name="Must be valid",
            rules=[lambda x: x.get("valid", False)],
            severity="HIGH"
        )
        
        event = create_test_event(payload={"valid": False})
        result = system.process(event)
        
        assert "policy_violations" in result.enrichments
        assert len(result.enrichments["policy_violations"]) > 0
    
    def test_set_baseline(self):
        """Test baseline setting."""
        system = SkeletalSystem()
        
        system.set_baseline(
            baseline_id="BASELINE-001",
            expected_state={"config_key": "expected_value"}
        )
        
        assert "BASELINE-001" in system._baselines
    
    def test_diagnose_no_policies(self):
        """Test diagnosis with no policies."""
        system = SkeletalSystem()
        findings = system.diagnose()
        
        assert len(findings) > 0
        assert findings[0].severity == DiagnosticSeverity.CRITICAL


# =============================================================================
# MuscularSystem Tests
# =============================================================================

class TestMuscularSystem:
    """Tests for MuscularSystem (Enforcement)."""
    
    def test_initialization(self):
        """Test system initialization."""
        system = MuscularSystem()
        
        assert system.system_type == BiologicalSystem.MUSCULAR
    
    def test_register_action(self):
        """Test action handler registration."""
        system = MuscularSystem()
        
        def test_handler(params):
            return True
        
        system.register_action("TEST_ACTION", test_handler)
        
        assert "TEST_ACTION" in system._action_handlers
    
    def test_queue_action(self):
        """Test action queuing."""
        system = MuscularSystem()
        
        action_id = system.queue_action(
            action_type="BLOCK_IP",
            target="192.168.1.1",
            parameters={}
        )
        
        assert action_id.startswith("ACT-")
        assert len(system._action_queue) == 1
    
    def test_execute_pending(self):
        """Test action execution."""
        system = MuscularSystem()
        
        executed = []
        def test_handler(params):
            executed.append(params)
            return True
        
        system.register_action("TEST_ACTION", test_handler)
        system.queue_action("TEST_ACTION", "target", {"key": "value"})
        
        results = system.execute_pending()
        
        assert results["completed"] == 1
        assert results["failed"] == 0
    
    def test_diagnose_no_handlers(self):
        """Test diagnosis with no handlers."""
        system = MuscularSystem()
        findings = system.diagnose()
        
        assert len(findings) > 0
        assert "no action handlers" in findings[0].symptom.lower()


# =============================================================================
# LymphaticSystem Tests
# =============================================================================

class TestLymphaticSystem:
    """Tests for LymphaticSystem (IR & Forensics)."""
    
    def test_initialization(self):
        """Test system initialization."""
        system = LymphaticSystem()
        
        assert system.system_type == BiologicalSystem.LYMPHATIC
    
    def test_open_incident(self):
        """Test incident opening."""
        system = LymphaticSystem()
        
        system.open_incident(
            incident_id="INC-001",
            severity="HIGH",
            description="Test incident"
        )
        
        assert "INC-001" in system._active_incidents
        assert system._active_incidents["INC-001"]["status"] == "open"
    
    def test_collect_evidence(self):
        """Test evidence collection."""
        system = LymphaticSystem()
        
        system.open_incident("INC-001", "HIGH", "Test")
        system.collect_evidence(
            incident_id="INC-001",
            evidence_type="log",
            data={"log_entry": "suspicious activity"}
        )
        
        assert len(system._evidence_store["INC-001"]) == 1
    
    def test_contain_incident(self):
        """Test incident containment."""
        system = LymphaticSystem()
        
        system.open_incident("INC-001", "HIGH", "Test")
        result = system.contain_incident("INC-001")
        
        assert result is True
        assert system._active_incidents["INC-001"]["containment_status"] == "contained"
    
    def test_close_incident(self):
        """Test incident closure."""
        system = LymphaticSystem()
        
        system.open_incident("INC-001", "HIGH", "Test")
        result = system.close_incident("INC-001", "Resolved")
        
        assert result is True
        assert system._active_incidents["INC-001"]["status"] == "closed"


# =============================================================================
# RespiratorySystem Tests
# =============================================================================

class TestRespiratorySystem:
    """Tests for RespiratorySystem (Traffic Analysis)."""
    
    def test_initialization(self):
        """Test system initialization."""
        system = RespiratorySystem()
        
        assert system.system_type == BiologicalSystem.RESPIRATORY
    
    def test_block_source(self):
        """Test source blocking."""
        system = RespiratorySystem()
        
        system.block_source("192.168.1.1", "Malicious activity")
        
        assert "192.168.1.1" in system._blocked_sources
    
    def test_process_blocked_source(self):
        """Test processing event from blocked source."""
        system = RespiratorySystem()
        
        system.block_source("192.168.1.1", "Malicious")
        
        event = create_test_event(payload={"source_ip": "192.168.1.1"})
        result = system.process(event)
        
        assert result.enrichments.get("blocked") is True
    
    def test_exfiltration_detection(self):
        """Test data exfiltration detection."""
        system = RespiratorySystem()
        
        # Large outbound transfer
        event = create_test_event(payload={
            "source_ip": "10.0.0.1",
            "bytes_out": 20_000_000  # 20 MB
        })
        result = system.process(event)
        
        assert result.enrichments.get("exfiltration_suspected") is True


# =============================================================================
# DigestiveSystem Tests
# =============================================================================

class TestDigestiveSystem:
    """Tests for DigestiveSystem (Data Processing)."""
    
    def test_initialization(self):
        """Test system initialization."""
        system = DigestiveSystem()
        
        assert system.system_type == BiologicalSystem.DIGESTIVE
    
    def test_register_parser(self):
        """Test parser registration."""
        system = DigestiveSystem()
        
        def json_parser(raw: str) -> Dict[str, Any]:
            return json.loads(raw)
        
        system.register_parser("json", json_parser)
        
        assert "json" in system._parsers
    
    def test_parse_raw_log(self):
        """Test raw log parsing."""
        system = DigestiveSystem()
        
        def simple_parser(raw: str) -> Dict[str, Any]:
            return {"parsed": raw}
        
        system.register_parser("simple", simple_parser)
        
        result, error = system.parse_raw_log("test data", "simple")
        
        assert error is None
        assert result == {"parsed": "test data"}
    
    def test_parse_unknown_format(self):
        """Test parsing unknown format."""
        system = DigestiveSystem()
        
        result, error = system.parse_raw_log("data", "unknown_format")
        
        assert result is None
        assert "no parser" in error.lower()
    
    def test_register_enricher(self):
        """Test enricher registration."""
        system = DigestiveSystem()
        
        def geo_enricher(data: Dict[str, Any]) -> Dict[str, Any]:
            return {"country": "US"}
        
        system.register_enricher("geo", geo_enricher)
        
        assert "geo" in system._enrichers
    
    def test_diagnose_no_parsers(self):
        """Test diagnosis with no parsers."""
        system = DigestiveSystem()
        findings = system.diagnose()
        
        assert len(findings) > 0
        assert any("no parsers" in f.symptom.lower() for f in findings)


# =============================================================================
# EndocrineSystem Tests
# =============================================================================

class TestEndocrineSystem:
    """Tests for EndocrineSystem (Orchestration)."""
    
    def test_initialization(self):
        """Test system initialization."""
        system = EndocrineSystem()
        
        assert system.system_type == BiologicalSystem.ENDOCRINE
    
    def test_set_configuration(self):
        """Test configuration setting."""
        system = EndocrineSystem()
        
        system.set_configuration("target1", "param1", "value1")
        
        assert len(system._pending_changes) == 1
        assert system._configuration_state["target1"]["param1"] == "value1"
    
    def test_propagate_changes(self):
        """Test configuration propagation."""
        system = EndocrineSystem()
        
        system.set_configuration("target1", "param1", "value1")
        results = system.propagate_changes()
        
        assert results["propagated"] == 1
        assert len(system._pending_changes) == 0
        assert len(system._applied_changes) == 1
    
    def test_process_critical_event(self):
        """Test processing critical event triggers orchestration."""
        system = EndocrineSystem()
        
        event = create_test_event()
        event.enrichments["threat_assessment"] = {"risk_level": "CRITICAL"}
        
        result = system.process(event)
        
        assert result.enrichments.get("orchestration_triggered") is True


# =============================================================================
# SecurityOrganism Integration Tests
# =============================================================================

class TestSecurityOrganism:
    """Integration tests for SecurityOrganism."""
    
    def test_initialization(self):
        """Test organism initialization."""
        organism = SecurityOrganism()
        
        assert organism.circulatory is not None
        assert organism.nervous is not None
        assert organism.immune is not None
        assert organism.skeletal is not None
        assert organism.muscular is not None
        assert organism.lymphatic is not None
        assert organism.respiratory is not None
        assert organism.digestive is not None
        assert organism.endocrine is not None
    
    def test_all_systems_wired(self):
        """Test all systems are wired together."""
        organism = SecurityOrganism()
        
        # All systems should be subscribed to circulatory
        assert len(organism.circulatory._subscribers) == 8  # All except circulatory itself
        
        # All systems should be registered with endocrine
        assert len(organism.endocrine._system_targets) == 9
    
    def test_ingest_event(self):
        """Test event ingestion."""
        organism = SecurityOrganism()
        event = create_test_event()
        
        organism.ingest_event(event)
        
        # Event should have been processed by digestive first, then published to circulatory
        assert any("digestive:" in trail for trail in event.processing_trail)
        assert any("circulatory:" in trail for trail in event.processing_trail)
    
    def test_pulse(self):
        """Test pulse cycle."""
        organism = SecurityOrganism()
        
        # Ingest some events
        for i in range(5):
            event = create_test_event(event_id=f"EVT-{i:03d}")
            organism.ingest_event(event)
        
        # Pulse
        results = organism.pulse()
        
        assert results["events_pumped"] == 5
    
    def test_diagnose_all_systems(self):
        """Test systemic diagnosis."""
        organism = SecurityOrganism()
        
        findings = organism.diagnose()
        
        # Should have findings from systems without configurations
        assert isinstance(findings, dict)
    
    def test_get_health_summary(self):
        """Test health summary."""
        organism = SecurityOrganism()
        
        summary = organism.get_health_summary()
        
        assert "overall_health" in summary
        assert "system_health" in summary
        assert len(summary["system_health"]) == 9
    
    def test_symptom_correlation(self):
        """Test symptom correlation across systems."""
        organism = SecurityOrganism()
        
        # Create mock findings
        findings = {
            "muscular": [
                DiagnosticFinding(
                    system=BiologicalSystem.MUSCULAR,
                    severity=DiagnosticSeverity.WARNING,
                    symptom="Authentication failed multiple times",
                    diagnosis="Test",
                    recommendation="Test"
                )
            ],
            "respiratory": [
                DiagnosticFinding(
                    system=BiologicalSystem.RESPIRATORY,
                    severity=DiagnosticSeverity.WARNING,
                    symptom="Unusual outbound traffic detected",
                    diagnosis="Test",
                    recommendation="Test"
                )
            ]
        }
        
        correlations = organism.correlate_symptoms(findings)
        
        # Should not correlate without exact keywords
        # This tests that the correlation logic runs
        assert isinstance(correlations, list)
    
    def test_full_workflow(self):
        """Test complete security workflow."""
        organism = SecurityOrganism()
        
        # Configure the organism
        organism.immune.add_signature(
            "SIG-001",
            "malware",
            "malware_detected",
            "QUARANTINE"
        )
        
        organism.skeletal.add_policy(
            "POL-001",
            "Security Policy",
            [lambda x: x.get("authorized", True)],
            "HIGH"
        )
        
        organism.muscular.register_action(
            "QUARANTINE",
            lambda params: True
        )
        
        # Ingest a threat event
        event = create_test_event(
            payload={"content": "malware", "authorized": False}
        )
        organism.ingest_event(event)
        
        # Run a pulse
        results = organism.pulse()
        
        assert results["events_pumped"] >= 1
        
        # Check health
        health = organism.get_health_summary()
        assert health["overall_health"] in ["healthy", "degraded", "critical"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
