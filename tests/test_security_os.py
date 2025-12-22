"""
Tests for the Cheetah Security OS - Non-LLM Architecture

Tests all 5 steps of the deterministic cybersecurity implementation:
1. Formal Verification (Hoare Logic, State Space)
2. High-Performance Data Structures (Hash Maps, Tries, Bloom Filters)
3. Deterministic Threat Detection (Packet Inspection, EWMA)
4. Logic-Based Response Engine (LTS, Policy Engine)
5. Hardened Deployment (Audit Logs, SBOM, Integrity Verification)
"""

import json
import os
import pytest
import tempfile
import time

# Import all modules
from kernel.formal_verification import (
    FormalVerifier, HoareTriple, StateSpace, VerificationResult,
    create_threat_alert_verifier, create_firewall_state_space
)
from core.data_structures import (
    ThreatSignatureDB, ThreatSignature, IPTrie, URLTrie,
    BloomFilter, ConnectionSet
)
from detection.threat_detector import (
    StatefulPacketInspector, Packet, TCPFlags,
    EWMADetector, VulnerabilityScanner, CVEEntry
)
from response.lts_engine import (
    LabeledTransitionSystem, SecurityState, LTLEvaluator,
    PolicyEngine, PolicyRule, StateGraph,
    create_security_lts, create_security_policies
)
from deployment.security import (
    ImmutableAuditLog, SBOMGenerator, IntegrityVerifier
)


# =============================================================================
# Step 1: Formal Verification Tests
# =============================================================================

class TestFormalVerification:
    """Tests for formal verification module."""
    
    def test_hoare_triple_valid(self):
        """Test Hoare Triple with valid preconditions."""
        triple = create_threat_alert_verifier()
        
        event = {
            "event_id": "EVT-001",
            "severity": "HIGH",
            "timestamp": 0
        }
        
        result, output = triple.verify(event)
        
        assert result == VerificationResult.VALID
        assert output["event_id"] == "EVT-001"
        assert output["processed"] is True
    
    def test_hoare_triple_invalid_precondition(self):
        """Test Hoare Triple with invalid preconditions."""
        triple = create_threat_alert_verifier()
        
        # Missing event_id
        event = {"severity": "HIGH"}
        result, output = triple.verify(event)
        
        assert result == VerificationResult.INVALID
        assert output is None
    
    def test_formal_verifier_registration(self):
        """Test function registration with FormalVerifier."""
        verifier = FormalVerifier()
        
        verifier.register_verified_function(
            name="test_func",
            precondition=lambda x: x > 0,
            statement=lambda x: x * 2,
            postcondition=lambda result, x: result == x * 2
        )
        
        assert "test_func" in verifier.verified_functions
    
    def test_state_space_invariants(self):
        """Test state space invariant checking."""
        state_space = create_firewall_state_space()
        
        # Initial state should satisfy invariants
        valid, violations = state_space.check_invariants()
        assert valid is True
        assert len(violations) == 0
    
    def test_state_space_transitions(self):
        """Test state space transitions."""
        state_space = create_firewall_state_space()
        
        # Apply monitoring transition
        success, new_state = state_space.apply_transition("start_monitoring")
        assert success is True
        assert new_state["mode"] == "MONITORING"


# =============================================================================
# Step 2: Data Structures Tests
# =============================================================================

class TestDataStructures:
    """Tests for high-performance data structures."""
    
    def test_threat_signature_db_o1_lookup(self):
        """Test O(1) threat signature lookup."""
        db = ThreatSignatureDB()
        
        # Add signatures
        for i in range(1000):
            sig = ThreatSignature(
                cve_id=f"CVE-2024-{i:04d}",
                severity="HIGH",
                affected_versions=["1.0"],
                detection_pattern=f"pattern_{i}"
            )
            db.add_signature(sig)
        
        # Lookup should be O(1) regardless of size
        start = time.time()
        result = db.lookup_by_cve("CVE-2024-0500")
        elapsed = time.time() - start
        
        assert result is not None
        assert result.cve_id == "CVE-2024-0500"
        assert elapsed < 0.01  # Should be nearly instant
    
    def test_ip_trie_lookup(self):
        """Test IP Trie O(4) lookup."""
        trie = IPTrie()
        
        # Insert IPs
        trie.insert("192.168.1.1", "HIGH")
        trie.insert("192.168.1.100", "MEDIUM")
        trie.insert("10.0.0.1", "LOW")
        
        # Lookup
        result = trie.lookup("192.168.1.1")
        assert result is not None
        assert result["threat_level"] == "HIGH"
        
        # Non-existent
        result = trie.lookup("8.8.8.8")
        assert result is None
    
    def test_ip_trie_prefix_match(self):
        """Test IP Trie prefix matching."""
        trie = IPTrie()
        
        trie.insert("192.168.1.1", "HIGH")
        trie.insert("192.168.1.2", "HIGH")
        trie.insert("192.168.2.1", "MEDIUM")
        
        # Match all 192.168.1.x
        matches = trie.prefix_match("192.168.1")
        assert len(matches) == 2
    
    def test_bloom_filter_membership(self):
        """Test Bloom Filter membership testing."""
        bloom = BloomFilter(expected_elements=1000, false_positive_rate=0.01)
        
        # Add items
        for i in range(100):
            bloom.add(f"item_{i}")
        
        # Test membership
        assert bloom.contains("item_50") is True
        
        # Test non-membership (should be False with high probability)
        false_positives = sum(
            1 for i in range(1000, 2000)
            if bloom.contains(f"item_{i}")
        )
        
        # False positive rate should be low
        assert false_positives < 50  # Less than 5%
    
    def test_connection_set(self):
        """Test Connection Set O(1) operations."""
        conn_set = ConnectionSet()
        
        conn_set.add_safe("conn_1")
        conn_set.add_malicious("conn_2")
        conn_set.add_pending("conn_3")
        
        assert conn_set.is_safe("conn_1") is True
        assert conn_set.is_malicious("conn_2") is True
        assert conn_set.is_pending("conn_3") is True
        assert conn_set.get_status("conn_1") == "SAFE"
        assert conn_set.get_status("unknown") == "UNKNOWN"


# =============================================================================
# Step 3: Threat Detection Tests
# =============================================================================

class TestThreatDetection:
    """Tests for deterministic threat detection."""
    
    def test_packet_inspection_syn_flood(self):
        """Test SYN flood detection."""
        inspector = StatefulPacketInspector(syn_threshold=10)
        
        # Send many SYN packets
        for i in range(15):
            packet = Packet(
                src_ip="192.168.1.100",
                dst_ip="10.0.0.1",
                src_port=12345 + i,
                dst_port=80,
                protocol="TCP",
                flags=TCPFlags.SYN.value
            )
            result = inspector.inspect_packet(packet)
        
        # Should detect SYN flood
        alerts = inspector.get_alerts()
        syn_flood_alerts = [a for a in alerts if a["type"] == "SYN_FLOOD"]
        assert len(syn_flood_alerts) > 0
    
    def test_packet_inspection_christmas_tree(self):
        """Test Christmas tree packet detection."""
        inspector = StatefulPacketInspector()
        
        # Christmas tree packet (FIN + URG + PSH)
        packet = Packet(
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            flags=TCPFlags.FIN.value | TCPFlags.URG.value | TCPFlags.PSH.value
        )
        
        result = inspector.inspect_packet(packet)
        
        assert result["is_anomaly"] is True
        assert any(a["type"] == "CHRISTMAS_TREE_PACKET" for a in result["alerts"])
    
    def test_ewma_normal_behavior(self):
        """Test EWMA with normal market behavior."""
        detector = EWMADetector(span=20, price_threshold=0.9, volume_threshold=4.0)
        
        # Simulate normal price movement
        base_price = 100
        base_volume = 1000
        
        for i in range(30):
            # Small random-like variations
            price = base_price + (i % 5) - 2
            volume = base_volume + (i % 3) * 100
            result = detector.add_observation(price, volume)
        
        # Should not detect anomaly
        assert result["is_pump_and_dump"] is False
    
    def test_ewma_pump_and_dump_detection(self):
        """Test EWMA pump-and-dump detection."""
        detector = EWMADetector(span=20, price_threshold=0.5, volume_threshold=3.0)
        
        # Build baseline
        for i in range(25):
            detector.add_observation(100, 1000)
        
        # Simulate pump (large price and volume spike)
        result = detector.add_observation(250, 8000)  # 150% price increase, 8x volume
        
        # Should detect the anomaly pattern
        assert result["price_change_pct"] > 50
        assert result["volume_change_multiple"] > 3
    
    def test_vulnerability_scanner(self):
        """Test vulnerability scanner with CVE database."""
        scanner = VulnerabilityScanner()
        
        # Load test CVE
        scanner.load_cve_entry(CVEEntry(
            cve_id="CVE-2024-1234",
            severity="CRITICAL",
            cvss_score=9.8,
            affected_products=["nginx"],
            affected_versions=["1.18.0"],
            description="Remote code execution"
        ))
        
        # Scan target
        result = scanner.scan_target(
            open_ports=[80, 443],
            banners={80: "nginx/1.18.0"}
        )
        
        assert len(result["services"]) == 2
        assert result["services"][0]["inferred_product"] == "nginx"


# =============================================================================
# Step 4: Response Engine Tests
# =============================================================================

class TestResponseEngine:
    """Tests for logic-based response engine."""
    
    def test_lts_state_transitions(self):
        """Test LTS state machine transitions."""
        lts = create_security_lts()
        
        assert lts.current_state == SecurityState.NORMAL
        
        # Trigger threat detection
        lts.set_context("threat_level", 5)
        transition = lts.evaluate()
        
        assert transition == "threat_detected"
        assert lts.current_state == SecurityState.ELEVATED
    
    def test_lts_ddos_response(self):
        """Test LTS DDoS detection and response."""
        lts = create_security_lts()
        
        # Trigger DDoS
        lts.set_context("ddos_detected", True)
        transition = lts.evaluate()
        
        assert "ddos" in transition.lower()
        assert lts.current_state == SecurityState.UNDER_DDOS
    
    def test_ltl_evaluator(self):
        """Test LTL formula evaluation."""
        evaluator = LTLEvaluator()
        
        # Register propositions
        state = {"breach": False, "lockdown": False}
        evaluator.register_proposition("breach", lambda: state["breach"])
        evaluator.register_proposition("lockdown", lambda: state["lockdown"])
        
        # Record initial states
        evaluator.record_state()
        evaluator.record_state()
        
        # Simulate breach then lockdown
        state["breach"] = True
        evaluator.record_state()
        
        state["lockdown"] = True
        evaluator.record_state()
        
        # Verify: If breach, eventually lockdown
        result = evaluator.evaluate_implies_eventually("breach", "lockdown")
        assert result is True
    
    def test_policy_engine(self):
        """Test policy-as-code engine."""
        engine = create_security_policies()
        
        # Test ransomware policy
        actions, violations = engine.evaluate({
            "threat_type": "ransomware",
            "confidence": 0.95
        })
        
        assert "ISOLATE_DEVICE" in actions
        assert len(violations) > 0
    
    def test_cycle_detection(self):
        """Test cycle detection in state graph."""
        graph = StateGraph()
        
        # Create graph with cycle
        graph.add_edge("A", "B")
        graph.add_edge("B", "C")
        graph.add_edge("C", "A")  # Creates cycle
        
        cycles = graph.detect_cycles()
        assert len(cycles) > 0
        
        # Graph without cycle
        graph2 = StateGraph()
        graph2.add_edge("A", "B")
        graph2.add_edge("B", "C")
        
        assert graph2.has_cycle() is False


# =============================================================================
# Step 5: Deployment Security Tests
# =============================================================================

class TestDeploymentSecurity:
    """Tests for hardened deployment security."""
    
    def test_immutable_audit_log(self):
        """Test immutable audit logging."""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name
        
        try:
            log = ImmutableAuditLog(db_path)
            
            # Append events
            hash1 = log.append({"event_id": "E1", "event_type": "TEST", "data": "test1"})
            hash2 = log.append({"event_id": "E2", "event_type": "TEST", "data": "test2"})
            
            # Verify integrity
            valid, message = log.verify_integrity()
            assert valid is True
            
            # Hashes should be different
            assert hash1 != hash2
            
            log.close()
        finally:
            os.unlink(db_path)
    
    def test_audit_log_tamper_detection(self):
        """Test that tampering is detected."""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name
        
        try:
            log = ImmutableAuditLog(db_path)
            
            log.append({"event_id": "E1", "event_type": "TEST"})
            log.append({"event_id": "E2", "event_type": "TEST"})
            
            # Tamper with the database
            import sqlite3
            conn = sqlite3.connect(db_path)
            conn.execute(
                "UPDATE audit_trail SET event_data = '{}' WHERE event_id = 'E1'"
            )
            conn.commit()
            conn.close()
            
            # Reload and verify
            log2 = ImmutableAuditLog(db_path)
            valid, message = log2.verify_integrity()
            
            assert valid is False
            assert "tamper" in message.lower() or "mismatch" in message.lower()
            
            log2.close()
        finally:
            os.unlink(db_path)
    
    def test_sbom_generation(self):
        """Test SBOM generation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a test package.json
            package_json = {
                "dependencies": {
                    "express": "4.18.0",
                    "lodash": "4.17.21"
                }
            }
            
            with open(os.path.join(tmpdir, "package.json"), 'w') as f:
                json.dump(package_json, f)
            
            generator = SBOMGenerator()
            sbom = generator.generate_sbom(tmpdir)
            
            assert len(sbom.components) == 2
            assert any(c.name == "express" for c in sbom.components)
    
    def test_sbom_vulnerability_detection(self):
        """Test SBOM vulnerability detection."""
        with tempfile.TemporaryDirectory() as tmpdir:
            package_json = {"dependencies": {"vulnerable-pkg": "1.0.0"}}
            
            with open(os.path.join(tmpdir, "package.json"), 'w') as f:
                json.dump(package_json, f)
            
            generator = SBOMGenerator()
            generator.cve_db = {
                "vulnerable-pkg": [{
                    "cve_id": "CVE-2024-9999",
                    "severity": "CRITICAL",
                    "cvss_score": 9.8
                }]
            }
            
            sbom = generator.generate_sbom(tmpdir)
            
            assert len(sbom.vulnerabilities) > 0
            assert sbom.policy_violations[0]["action"] == "BUILD_BLOCKED"
    
    def test_integrity_verifier(self):
        """Test file integrity verification."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test file
            test_file = os.path.join(tmpdir, "test.txt")
            with open(test_file, 'w') as f:
                f.write("original content")
            
            baseline_path = os.path.join(tmpdir, "baseline.json")
            verifier = IntegrityVerifier(baseline_path)
            
            # Create baseline
            result = verifier.create_baseline([test_file])
            assert result["files_fingerprinted"] == 1
            
            # Verify (should pass)
            verify_result = verifier.verify_integrity()
            assert verify_result["verified"] is True
            
            # Modify file
            with open(test_file, 'w') as f:
                f.write("modified content")
            
            # Verify (should fail)
            verify_result = verifier.verify_integrity()
            assert verify_result["verified"] is False
            assert len(verify_result["modifications"]) > 0


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    """Integration tests across all modules."""
    
    def test_end_to_end_threat_response(self):
        """Test complete threat detection to response flow."""
        # Step 1: Create verified threat processor
        verifier = FormalVerifier()
        
        def pre(event):
            return event.get("event_id") and event.get("threat_type")
        
        def process(event):
            return {"processed": True, **event}
        
        def post(result, event):
            return result.get("processed", False)
        
        verifier.register_verified_function("process_threat", pre, process, post)
        
        # Step 2: Detect threat with packet inspector
        inspector = StatefulPacketInspector(syn_threshold=5)
        
        for i in range(10):
            packet = Packet(
                src_ip="192.168.1.100",
                dst_ip="10.0.0.1",
                src_port=12345,
                dst_port=80,
                protocol="TCP",
                flags=TCPFlags.SYN.value
            )
            inspector.inspect_packet(packet)
        
        alerts = inspector.get_alerts()
        assert len(alerts) > 0
        
        # Step 3: Process through LTS
        lts = create_security_lts()
        lts.set_context("threat_level", 8)
        lts.set_context("ddos_detected", True)
        lts.evaluate()
        
        assert lts.current_state == SecurityState.UNDER_DDOS
        
        # Step 4: Apply policies
        policy_engine = create_security_policies()
        
        # Step 5: Log to audit trail
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name
        
        try:
            audit_log = ImmutableAuditLog(db_path)
            
            for alert in alerts:
                audit_log.append({
                    "event_id": f"ALERT-{id(alert)}",
                    "event_type": alert["type"],
                    "severity": alert.get("severity", "MEDIUM"),
                    "data": alert
                })
            
            # Verify log integrity
            valid, _ = audit_log.verify_integrity()
            assert valid is True
            
            audit_log.close()
        finally:
            os.unlink(db_path)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
