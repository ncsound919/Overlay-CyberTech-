"""
Circulatory Informatics Framework

This module implements a biological-to-cybersecurity mapping framework based on
the "Circulatory Informatics" model. It shifts security from a collection of
isolated tools to a holistic ecosystem where data flows like blood and responses
are coordinated like immune reactions.

The Nine Biological Systems Mapped to Cybersecurity:

1. Circulatory System: Secure Data Fabric & Event Streaming
2. Nervous System: Central Analytics Engine (SIEM/XDR)
3. Immune System (Adaptive): Threat Intelligence & Automated Response
4. Skeletal System: Security Policy & Governance
5. Muscular System: Enforcement & Remediation
6. Lymphatic System: Incident Response & Forensics
7. Respiratory System: Network Traffic Analysis & Access Control
8. Digestive System: Data Ingestion, Parsing & Enrichment
9. Endocrine System: Policy & Configuration Orchestration

This framework enables systemic diagnosis by analyzing interactions between
security components rather than reviewing isolated alerts.
"""

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple
import time
import json
import hashlib
from abc import ABC, abstractmethod


# =============================================================================
# Biological System Mapping Enums
# =============================================================================

class BiologicalSystem(Enum):
    """The nine biological systems mapped to cybersecurity contexts."""
    CIRCULATORY = "circulatory"     # Data Fabric & Event Streaming
    NERVOUS = "nervous"             # Central Analytics (SIEM/XDR)
    IMMUNE = "immune"               # Threat Intelligence & Response
    SKELETAL = "skeletal"           # Governance Framework
    MUSCULAR = "muscular"           # Enforcement & Remediation
    LYMPHATIC = "lymphatic"         # IR & Forensics
    RESPIRATORY = "respiratory"     # Traffic Analysis & Access Control
    DIGESTIVE = "digestive"         # Data Processing & Enrichment
    ENDOCRINE = "endocrine"         # Orchestration


class SystemHealth(Enum):
    """Health status indicators for each system."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    CRITICAL = "critical"
    FAILED = "failed"


class DiagnosticSeverity(Enum):
    """Severity levels for diagnostic findings."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


# =============================================================================
# Data Classes for System State
# =============================================================================

@dataclass
class SystemMetrics:
    """Metrics for a biological system component."""
    system: BiologicalSystem
    health: SystemHealth = SystemHealth.HEALTHY
    throughput: float = 0.0         # Events per second
    latency_ms: float = 0.0         # Average latency in milliseconds
    error_rate: float = 0.0         # Error rate (0.0 to 1.0)
    capacity_used: float = 0.0      # Capacity utilization (0.0 to 1.0)
    last_activity: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DiagnosticFinding:
    """A diagnostic finding from system analysis."""
    system: BiologicalSystem
    severity: DiagnosticSeverity
    symptom: str
    diagnosis: str
    recommendation: str
    timestamp: float = field(default_factory=time.time)
    related_symptoms: List[str] = field(default_factory=list)


@dataclass
class SecurityEvent:
    """A normalized security event flowing through the circulatory system."""
    event_id: str
    timestamp: float
    source_system: BiologicalSystem
    event_type: str
    severity: str
    payload: Dict[str, Any]
    enrichments: Dict[str, Any] = field(default_factory=dict)
    processing_trail: List[str] = field(default_factory=list)


# =============================================================================
# Base Class for Biological System Components
# =============================================================================

class BiologicalSystemComponent(ABC):
    """Abstract base class for biological system components."""
    
    def __init__(self, system_type: BiologicalSystem):
        self.system_type = system_type
        self.metrics = SystemMetrics(system=system_type)
        self._callbacks: List[Callable[[SecurityEvent], None]] = []
    
    @abstractmethod
    def process(self, event: SecurityEvent) -> Optional[SecurityEvent]:
        """Process a security event through this system."""
        pass
    
    @abstractmethod
    def diagnose(self) -> List[DiagnosticFinding]:
        """Perform self-diagnosis and return findings."""
        pass
    
    def get_health(self) -> SystemHealth:
        """Get the current health status of this system."""
        return self.metrics.health
    
    def update_metrics(self, **kwargs: Any) -> None:
        """Update system metrics."""
        for key, value in kwargs.items():
            if hasattr(self.metrics, key):
                setattr(self.metrics, key, value)
        self.metrics.last_activity = time.time()
    
    def register_callback(self, callback: Callable[[SecurityEvent], None]) -> None:
        """Register a callback for processed events."""
        self._callbacks.append(callback)
    
    def _emit_event(self, event: SecurityEvent) -> None:
        """Emit an event to all registered callbacks."""
        for callback in self._callbacks:
            try:
                callback(event)
            except Exception:
                pass  # Don't let callback errors affect event flow


# =============================================================================
# 1. Circulatory System: Secure Data Fabric & Event Streaming
# =============================================================================

class CirculatorySystem(BiologicalSystemComponent):
    """
    The Circulatory System: Secure Data Fabric & Event Streaming
    
    Acts as the "blood" of the digital organism, responsible for the
    continuous movement of normalized logs, alerts, and contextual data
    between all other components.
    
    Diagnostic Role: Ensures holistic analysis and traceability. A blockage
    here represents a failure in telemetry or log aggregation, starving
    the other systems of necessary information.
    
    Current Tech Analogy: Real-time event streaming (e.g., Kafka) and
    data normalization standards (e.g., STIX/TAXII).
    """
    
    def __init__(self):
        super().__init__(BiologicalSystem.CIRCULATORY)
        self._event_queue: Deque[SecurityEvent] = deque()
        self._subscribers: Dict[BiologicalSystem, BiologicalSystemComponent] = {}
        self._event_history: Deque[str] = deque(maxlen=10000)  # Event IDs for traceability
        self._max_queue_size = 10000
        self._total_events_processed = 0
        self._failed_deliveries = 0
    
    def subscribe(self, system: BiologicalSystemComponent) -> None:
        """Subscribe a system to receive events."""
        self._subscribers[system.system_type] = system
    
    def publish(self, event: SecurityEvent) -> bool:
        """
        Publish an event to the data fabric.
        
        Returns True if event was accepted, False if queue is full (blockage).
        """
        if len(self._event_queue) >= self._max_queue_size:
            self._failed_deliveries += 1
            self.metrics.health = SystemHealth.DEGRADED
            return False
        
        # Add processing trail entry
        event.processing_trail.append(f"circulatory:{time.time()}")
        self._event_queue.append(event)
        self._event_history.append(event.event_id)
        # Note: _event_history is a deque with maxlen, so it auto-prunes
        
        return True
    
    def process(self, event: SecurityEvent) -> Optional[SecurityEvent]:
        """Process and route an event through the circulatory system."""
        start_time = time.time()
        
        # Route to all subscribers
        for system_type, subscriber in self._subscribers.items():
            try:
                subscriber.process(event)
            except Exception:
                self._failed_deliveries += 1
        
        self._total_events_processed += 1
        latency = (time.time() - start_time) * 1000
        
        self.update_metrics(
            throughput=self._total_events_processed,
            latency_ms=latency,
            capacity_used=len(self._event_queue) / self._max_queue_size
        )
        
        return event
    
    def pump(self) -> int:
        """
        Process all queued events (like a heartbeat).
        
        Returns the number of events processed.
        """
        processed = 0
        while self._event_queue:
            event = self._event_queue.popleft()  # O(1) with deque
            self.process(event)
            processed += 1
        return processed
    
    def diagnose(self) -> List[DiagnosticFinding]:
        """Diagnose circulatory system health."""
        findings = []
        
        # Check for blockages (queue buildup)
        queue_fill = len(self._event_queue) / self._max_queue_size
        if queue_fill > 0.8:
            findings.append(DiagnosticFinding(
                system=self.system_type,
                severity=DiagnosticSeverity.CRITICAL,
                symptom="Event queue at >80% capacity",
                diagnosis="Data fabric blockage - events are not being processed fast enough",
                recommendation="Scale up event processing capacity or reduce event volume"
            ))
        elif queue_fill > 0.5:
            findings.append(DiagnosticFinding(
                system=self.system_type,
                severity=DiagnosticSeverity.WARNING,
                symptom="Event queue at >50% capacity",
                diagnosis="Potential data fabric congestion developing",
                recommendation="Monitor event processing throughput"
            ))
        
        # Check for delivery failures
        if self._failed_deliveries > 0:
            failure_rate = self._failed_deliveries / max(1, self._total_events_processed)
            if failure_rate > 0.1:
                findings.append(DiagnosticFinding(
                    system=self.system_type,
                    severity=DiagnosticSeverity.ERROR,
                    symptom=f"High event delivery failure rate: {failure_rate:.1%}",
                    diagnosis="Downstream systems not receiving events",
                    recommendation="Check subscriber system health"
                ))
        
        return findings


# =============================================================================
# 2. Nervous System: Central Analytics Engine (SIEM/XDR)
# =============================================================================

class NervousSystem(BiologicalSystemComponent):
    """
    The Nervous System: Central Command & Analytics Engine (SIEM/XDR)
    
    Serves as the "brain and spine," processing sensory input from the
    environment, making real-time decisions, and coordinating automated
    responses.
    
    Diagnostic Role: Provides "centralized consciousness" by correlating
    disparate events (symptoms) to form a coherent threat picture. Failure
    here results in an inability to distinguish signal from noise.
    """
    
    def __init__(self):
        super().__init__(BiologicalSystem.NERVOUS)
        self._correlation_rules: List[Dict[str, Any]] = []
        self._correlated_events: Dict[str, List[SecurityEvent]] = {}
        self._threat_assessments: List[Dict[str, Any]] = []
        self._signals_processed = 0
        self._noise_filtered = 0
    
    def add_correlation_rule(
        self,
        rule_id: str,
        conditions: List[Callable[[SecurityEvent], bool]],
        correlation_window: float = 300.0  # 5 minutes
    ) -> None:
        """Add a correlation rule for threat detection."""
        self._correlation_rules.append({
            "rule_id": rule_id,
            "conditions": conditions,
            "window": correlation_window
        })
    
    def process(self, event: SecurityEvent) -> Optional[SecurityEvent]:
        """Process and correlate security events."""
        event.processing_trail.append(f"nervous:{time.time()}")
        self._signals_processed += 1
        
        # Correlate with existing events
        correlations = self._correlate_event(event)
        
        if correlations:
            event.enrichments["correlations"] = correlations
            assessment = self._assess_threat(event, correlations)
            self._threat_assessments.append(assessment)
            event.enrichments["threat_assessment"] = assessment
        else:
            self._noise_filtered += 1
        
        self.update_metrics(
            throughput=self._signals_processed,
            error_rate=self._noise_filtered / max(1, self._signals_processed)
        )
        
        return event
    
    def _correlate_event(self, event: SecurityEvent) -> List[str]:
        """Find correlations with existing events."""
        correlations = []
        current_time = time.time()
        
        for rule in self._correlation_rules:
            rule_id = rule["rule_id"]
            window = rule["window"]
            
            # Check if event matches any rule conditions
            matches = all(cond(event) for cond in rule["conditions"])
            
            if matches:
                # Add to correlation group
                if rule_id not in self._correlated_events:
                    self._correlated_events[rule_id] = []
                
                # Clean old events outside window
                self._correlated_events[rule_id] = [
                    e for e in self._correlated_events[rule_id]
                    if current_time - e.timestamp < window
                ]
                
                self._correlated_events[rule_id].append(event)
                correlations.append(rule_id)
        
        return correlations
    
    def _assess_threat(
        self,
        event: SecurityEvent,
        correlations: List[str]
    ) -> Dict[str, Any]:
        """Assess threat level based on correlations."""
        # Count correlated events for each rule
        event_counts = {
            rule_id: len(self._correlated_events.get(rule_id, []))
            for rule_id in correlations
        }
        
        # Calculate threat score based on correlation density
        max_count = max(event_counts.values()) if event_counts else 0
        threat_score = min(10, max_count / 2)  # Scale to 0-10
        
        return {
            "threat_score": threat_score,
            "correlation_counts": event_counts,
            "assessment_time": time.time(),
            "risk_level": (
                "CRITICAL" if threat_score >= 8 else
                "HIGH" if threat_score >= 6 else
                "MEDIUM" if threat_score >= 4 else
                "LOW"
            )
        }
    
    def diagnose(self) -> List[DiagnosticFinding]:
        """Diagnose nervous system health."""
        findings = []
        
        # Check signal-to-noise ratio
        if self._signals_processed > 0:
            noise_ratio = self._noise_filtered / self._signals_processed
            if noise_ratio > 0.9:
                findings.append(DiagnosticFinding(
                    system=self.system_type,
                    severity=DiagnosticSeverity.WARNING,
                    symptom=f"High noise ratio: {noise_ratio:.1%} events uncorrelated",
                    diagnosis="Correlation rules may be too narrow or event quality is poor",
                    recommendation="Review correlation rules or improve event enrichment"
                ))
        
        # Check for correlation rule coverage
        if not self._correlation_rules:
            findings.append(DiagnosticFinding(
                system=self.system_type,
                severity=DiagnosticSeverity.ERROR,
                symptom="No correlation rules defined",
                diagnosis="Unable to correlate events - no threat detection logic",
                recommendation="Define correlation rules for threat detection"
            ))
        
        return findings


# =============================================================================
# 3. Immune System: Threat Intelligence & Automated Response
# =============================================================================

class ImmuneSystem(BiologicalSystemComponent):
    """
    The Immune System (Adaptive): Threat Intelligence & Automated Response
    
    Learns from interactions to identify and remember threats. Deploys
    "antibodies" such as blocks, patches, and isolations to neutralize
    known dangers.
    
    Diagnostic Role: Identifies both known signatures and novel anomalies,
    providing adaptive immunity. A failure here leaves the organization
    vulnerable to repeat attacks or zero-day exploits.
    """
    
    def __init__(self):
        super().__init__(BiologicalSystem.IMMUNE)
        self._threat_signatures: Dict[str, Dict[str, Any]] = {}
        self._learned_patterns: Dict[str, Dict[str, Any]] = {}
        self._active_antibodies: List[Dict[str, Any]] = []
        self._detection_history: List[Dict[str, Any]] = []
    
    def add_signature(
        self,
        signature_id: str,
        pattern: str,
        threat_type: str,
        response_action: str
    ) -> None:
        """Add a known threat signature."""
        self._threat_signatures[signature_id] = {
            "pattern": pattern,
            "threat_type": threat_type,
            "response_action": response_action,
            "created": time.time()
        }
    
    def learn_pattern(self, event: SecurityEvent) -> None:
        """Learn a new pattern from a confirmed threat."""
        pattern_hash = hashlib.sha256(
            json.dumps(event.payload, sort_keys=True).encode()
        ).hexdigest()[:16]
        
        self._learned_patterns[pattern_hash] = {
            "source_event": event.event_id,
            "pattern_type": event.event_type,
            "learned_at": time.time(),
            "match_count": 1
        }
    
    def process(self, event: SecurityEvent) -> Optional[SecurityEvent]:
        """Process event for threat detection and response."""
        event.processing_trail.append(f"immune:{time.time()}")
        
        # Check against known signatures
        matched_signature = self._match_signatures(event)
        if matched_signature:
            event.enrichments["threat_match"] = matched_signature
            antibody = self._deploy_antibody(matched_signature, event)
            event.enrichments["antibody_deployed"] = antibody
        
        # Check against learned patterns
        pattern_match = self._match_learned_patterns(event)
        if pattern_match:
            event.enrichments["pattern_match"] = pattern_match
            self._learned_patterns[pattern_match]["match_count"] += 1
        
        self._detection_history.append({
            "event_id": event.event_id,
            "matched_signature": matched_signature is not None,
            "matched_pattern": pattern_match is not None,
            "timestamp": time.time()
        })
        
        return event
    
    def _match_signatures(self, event: SecurityEvent) -> Optional[Dict[str, Any]]:
        """Match event against known threat signatures."""
        event_str = json.dumps(event.payload, sort_keys=True)
        
        for sig_id, signature in self._threat_signatures.items():
            if signature["pattern"] in event_str:
                return {
                    "signature_id": sig_id,
                    "threat_type": signature["threat_type"],
                    "response_action": signature["response_action"]
                }
        return None
    
    def _match_learned_patterns(self, event: SecurityEvent) -> Optional[str]:
        """Match event against learned patterns."""
        pattern_hash = hashlib.sha256(
            json.dumps(event.payload, sort_keys=True).encode()
        ).hexdigest()[:16]
        
        return pattern_hash if pattern_hash in self._learned_patterns else None
    
    def _deploy_antibody(
        self,
        threat_match: Dict[str, Any],
        event: SecurityEvent
    ) -> Dict[str, Any]:
        """Deploy an antibody (automated response) for a detected threat."""
        antibody = {
            "antibody_id": f"AB-{len(self._active_antibodies):06d}",
            "action": threat_match["response_action"],
            "target": event.payload.get("source", "unknown"),
            "deployed_at": time.time(),
            "triggered_by": event.event_id
        }
        self._active_antibodies.append(antibody)
        return antibody
    
    def diagnose(self) -> List[DiagnosticFinding]:
        """Diagnose immune system health."""
        findings = []
        
        # Check signature database
        if not self._threat_signatures:
            findings.append(DiagnosticFinding(
                system=self.system_type,
                severity=DiagnosticSeverity.ERROR,
                symptom="No threat signatures loaded",
                diagnosis="Immune system has no memory of known threats",
                recommendation="Load threat intelligence feeds"
            ))
        
        # Check for adaptive learning
        if not self._learned_patterns:
            findings.append(DiagnosticFinding(
                system=self.system_type,
                severity=DiagnosticSeverity.WARNING,
                symptom="No patterns learned from past incidents",
                diagnosis="Adaptive immunity not developing",
                recommendation="Enable pattern learning from confirmed threats"
            ))
        
        # Check detection effectiveness
        if len(self._detection_history) >= 100:
            recent = self._detection_history[-100:]
            detection_rate = sum(
                1 for d in recent if d["matched_signature"] or d["matched_pattern"]
            ) / 100
            
            if detection_rate < 0.1:
                findings.append(DiagnosticFinding(
                    system=self.system_type,
                    severity=DiagnosticSeverity.WARNING,
                    symptom=f"Low detection rate: {detection_rate:.1%}",
                    diagnosis="Most events not matching any known threats",
                    recommendation="Update threat signatures or review false negative rate"
                ))
        
        return findings


# =============================================================================
# 4. Skeletal System: Security Policy & Governance
# =============================================================================

class SkeletalSystem(BiologicalSystemComponent):
    """
    The Skeletal System: Security Policy & Governance
    
    Provides the rigid structure defining the "acceptable state" and posture
    of the organization. Supports the entire security apparatus by
    establishing the baseline.
    
    Diagnostic Role: Detects deviations from the healthy baseline
    (misconfigurations). If the skeletal system is weak, the organization
    suffers from poor posture management.
    """
    
    def __init__(self):
        super().__init__(BiologicalSystem.SKELETAL)
        self._policies: Dict[str, Dict[str, Any]] = {}
        self._baselines: Dict[str, Dict[str, Any]] = {}
        self._compliance_checks: List[Dict[str, Any]] = []
        self._violations: List[Dict[str, Any]] = []
    
    def add_policy(
        self,
        policy_id: str,
        name: str,
        rules: List[Callable[[Dict[str, Any]], bool]],
        severity: str = "MEDIUM"
    ) -> None:
        """Add a governance policy."""
        self._policies[policy_id] = {
            "name": name,
            "rules": rules,
            "severity": severity,
            "created": time.time()
        }
    
    def set_baseline(
        self,
        baseline_id: str,
        expected_state: Dict[str, Any]
    ) -> None:
        """Set an expected baseline state."""
        self._baselines[baseline_id] = {
            "expected": expected_state,
            "created": time.time()
        }
    
    def process(self, event: SecurityEvent) -> Optional[SecurityEvent]:
        """Check event against policies and baselines."""
        event.processing_trail.append(f"skeletal:{time.time()}")
        
        violations = self._check_policies(event)
        deviations = self._check_baselines(event)
        
        if violations:
            event.enrichments["policy_violations"] = violations
            self._violations.extend(violations)
        
        if deviations:
            event.enrichments["baseline_deviations"] = deviations
        
        return event
    
    def _check_policies(self, event: SecurityEvent) -> List[Dict[str, Any]]:
        """Check event against all policies."""
        violations = []
        
        for policy_id, policy in self._policies.items():
            for i, rule in enumerate(policy["rules"]):
                try:
                    if not rule(event.payload):
                        violations.append({
                            "policy_id": policy_id,
                            "policy_name": policy["name"],
                            "rule_index": i,
                            "severity": policy["severity"],
                            "event_id": event.event_id
                        })
                except Exception:
                    pass  # Rule evaluation failed - log separately
        
        return violations
    
    def _check_baselines(self, event: SecurityEvent) -> List[Dict[str, Any]]:
        """Check event payload against baselines."""
        deviations = []
        
        for baseline_id, baseline in self._baselines.items():
            expected = baseline["expected"]
            
            for key, expected_value in expected.items():
                actual_value = event.payload.get(key)
                if actual_value is not None and actual_value != expected_value:
                    deviations.append({
                        "baseline_id": baseline_id,
                        "field": key,
                        "expected": expected_value,
                        "actual": actual_value
                    })
        
        return deviations
    
    def diagnose(self) -> List[DiagnosticFinding]:
        """Diagnose skeletal system health."""
        findings = []
        
        # Check policy coverage
        if not self._policies:
            findings.append(DiagnosticFinding(
                system=self.system_type,
                severity=DiagnosticSeverity.CRITICAL,
                symptom="No security policies defined",
                diagnosis="No governance structure in place",
                recommendation="Define security policies immediately"
            ))
        
        # Check for baseline drift
        if not self._baselines:
            findings.append(DiagnosticFinding(
                system=self.system_type,
                severity=DiagnosticSeverity.WARNING,
                symptom="No baselines established",
                diagnosis="Cannot detect configuration drift without baselines",
                recommendation="Establish configuration baselines"
            ))
        
        # Check violation rate
        if self._violations:
            recent_violations = [
                v for v in self._violations
                if time.time() - v.get("timestamp", time.time()) < 3600
            ]
            if len(recent_violations) > 10:
                findings.append(DiagnosticFinding(
                    system=self.system_type,
                    severity=DiagnosticSeverity.ERROR,
                    symptom=f"{len(recent_violations)} policy violations in last hour",
                    diagnosis="Significant policy compliance issues",
                    recommendation="Review and remediate policy violations"
                ))
        
        return findings


# =============================================================================
# 5. Muscular System: Enforcement & Remediation
# =============================================================================

class MuscularSystem(BiologicalSystemComponent):
    """
    The Muscular System: Enforcement & Remediation
    
    Executes physical actions based on commands from the nervous system.
    Actions include applying patches, quarantining endpoints, and
    rotating credentials.
    
    Diagnostic Role: Its "strength" determines response capability.
    "Fatigue" in this system indicates an inability to remediate
    vulnerabilities quickly enough to prevent exploitation.
    """
    
    def __init__(self):
        super().__init__(BiologicalSystem.MUSCULAR)
        self._action_queue: List[Dict[str, Any]] = []
        self._completed_actions: List[Dict[str, Any]] = []
        self._failed_actions: List[Dict[str, Any]] = []
        self._action_handlers: Dict[str, Callable[[Dict[str, Any]], bool]] = {}
        self._max_concurrent_actions = 10
    
    def register_action(
        self,
        action_type: str,
        handler: Callable[[Dict[str, Any]], bool]
    ) -> None:
        """Register an action handler."""
        self._action_handlers[action_type] = handler
    
    def queue_action(
        self,
        action_type: str,
        target: str,
        parameters: Dict[str, Any]
    ) -> str:
        """Queue an enforcement action."""
        action_id = f"ACT-{len(self._action_queue):06d}"
        self._action_queue.append({
            "action_id": action_id,
            "action_type": action_type,
            "target": target,
            "parameters": parameters,
            "queued_at": time.time(),
            "status": "queued"
        })
        return action_id
    
    def process(self, event: SecurityEvent) -> Optional[SecurityEvent]:
        """Process events requiring enforcement actions."""
        event.processing_trail.append(f"muscular:{time.time()}")
        
        # Check if event requires automated action
        if "antibody_deployed" in event.enrichments:
            antibody = event.enrichments["antibody_deployed"]
            action_id = self.queue_action(
                action_type=antibody["action"],
                target=antibody["target"],
                parameters={"triggered_by": event.event_id}
            )
            event.enrichments["queued_action"] = action_id
        
        return event
    
    def execute_pending(self) -> Dict[str, int]:
        """Execute pending actions (muscle contraction)."""
        results = {"completed": 0, "failed": 0}
        
        actions_to_execute = self._action_queue[:self._max_concurrent_actions]
        self._action_queue = self._action_queue[self._max_concurrent_actions:]
        
        for action in actions_to_execute:
            action["started_at"] = time.time()
            handler = self._action_handlers.get(action["action_type"])
            
            if handler:
                try:
                    success = handler(action["parameters"])
                    if success:
                        action["status"] = "completed"
                        action["completed_at"] = time.time()
                        self._completed_actions.append(action)
                        results["completed"] += 1
                    else:
                        action["status"] = "failed"
                        self._failed_actions.append(action)
                        results["failed"] += 1
                except Exception as e:
                    action["status"] = "failed"
                    action["error"] = str(e)
                    self._failed_actions.append(action)
                    results["failed"] += 1
            else:
                action["status"] = "no_handler"
                self._failed_actions.append(action)
                results["failed"] += 1
        
        # Update metrics
        total = results["completed"] + results["failed"]
        if total > 0:
            self.update_metrics(
                error_rate=results["failed"] / total
            )
        
        return results
    
    def diagnose(self) -> List[DiagnosticFinding]:
        """Diagnose muscular system health."""
        findings = []
        
        # Check for action queue buildup (fatigue)
        if len(self._action_queue) > 50:
            findings.append(DiagnosticFinding(
                system=self.system_type,
                severity=DiagnosticSeverity.WARNING,
                symptom=f"{len(self._action_queue)} actions queued",
                diagnosis="Muscular fatigue - actions not being executed fast enough",
                recommendation="Increase action execution capacity"
            ))
        
        # Check failure rate
        if self._failed_actions:
            recent_failed = [
                a for a in self._failed_actions
                if time.time() - a.get("started_at", time.time()) < 3600
            ]
            if len(recent_failed) > 5:
                findings.append(DiagnosticFinding(
                    system=self.system_type,
                    severity=DiagnosticSeverity.ERROR,
                    symptom=f"{len(recent_failed)} failed actions in last hour",
                    diagnosis="Enforcement actions failing",
                    recommendation="Review action handlers and target availability"
                ))
        
        # Check handler coverage
        if not self._action_handlers:
            findings.append(DiagnosticFinding(
                system=self.system_type,
                severity=DiagnosticSeverity.CRITICAL,
                symptom="No action handlers registered",
                diagnosis="Unable to execute any enforcement actions",
                recommendation="Register action handlers for remediation"
            ))
        
        return findings


# =============================================================================
# 6. Lymphatic System: Incident Response & Forensics
# =============================================================================

class LymphaticSystem(BiologicalSystemComponent):
    """
    The Lymphatic System: Incident Response (IR) & Forensics
    
    Responsible for draining "infection" (malware or compromised accounts)
    and cleansing the system after an incident.
    
    Diagnostic Role: Managing post-breach cleanup and evidence collection.
    "Swelling" in this system indicates an active incident that requires
    containment and purging.
    """
    
    def __init__(self):
        super().__init__(BiologicalSystem.LYMPHATIC)
        self._active_incidents: Dict[str, Dict[str, Any]] = {}
        self._evidence_store: Dict[str, List[Dict[str, Any]]] = {}
        self._cleanup_tasks: List[Dict[str, Any]] = []
        self._containment_actions: List[Dict[str, Any]] = []
    
    def open_incident(
        self,
        incident_id: str,
        severity: str,
        description: str
    ) -> None:
        """Open a new incident for investigation."""
        self._active_incidents[incident_id] = {
            "incident_id": incident_id,
            "severity": severity,
            "description": description,
            "opened_at": time.time(),
            "status": "open",
            "evidence_count": 0,
            "containment_status": "pending"
        }
        self._evidence_store[incident_id] = []
    
    def collect_evidence(
        self,
        incident_id: str,
        evidence_type: str,
        data: Dict[str, Any]
    ) -> None:
        """Collect evidence for an incident."""
        if incident_id in self._evidence_store:
            self._evidence_store[incident_id].append({
                "type": evidence_type,
                "data": data,
                "collected_at": time.time(),
                "hash": hashlib.sha256(
                    json.dumps(data, sort_keys=True).encode()
                ).hexdigest()
            })
            self._active_incidents[incident_id]["evidence_count"] += 1
    
    def process(self, event: SecurityEvent) -> Optional[SecurityEvent]:
        """Process events for incident context."""
        event.processing_trail.append(f"lymphatic:{time.time()}")
        
        # Check if event relates to active incident
        for incident_id, incident in self._active_incidents.items():
            if incident["status"] == "open":
                # Collect as potential evidence
                self.collect_evidence(
                    incident_id,
                    "security_event",
                    {
                        "event_id": event.event_id,
                        "event_type": event.event_type,
                        "payload": event.payload
                    }
                )
                event.enrichments["related_incident"] = incident_id
        
        return event
    
    def contain_incident(self, incident_id: str) -> bool:
        """Mark incident as contained."""
        if incident_id in self._active_incidents:
            self._active_incidents[incident_id]["containment_status"] = "contained"
            self._active_incidents[incident_id]["contained_at"] = time.time()
            self._containment_actions.append({
                "incident_id": incident_id,
                "action": "contain",
                "timestamp": time.time()
            })
            return True
        return False
    
    def close_incident(self, incident_id: str, resolution: str) -> bool:
        """Close an incident."""
        if incident_id in self._active_incidents:
            self._active_incidents[incident_id]["status"] = "closed"
            self._active_incidents[incident_id]["resolution"] = resolution
            self._active_incidents[incident_id]["closed_at"] = time.time()
            return True
        return False
    
    def diagnose(self) -> List[DiagnosticFinding]:
        """Diagnose lymphatic system health."""
        findings = []
        
        # Check for swelling (too many active incidents)
        open_incidents = [
            i for i in self._active_incidents.values()
            if i["status"] == "open"
        ]
        
        if len(open_incidents) > 5:
            findings.append(DiagnosticFinding(
                system=self.system_type,
                severity=DiagnosticSeverity.CRITICAL,
                symptom=f"{len(open_incidents)} active incidents",
                diagnosis="System swelling - too many open incidents",
                recommendation="Prioritize incident containment and resolution"
            ))
        
        # Check for uncontained incidents
        uncontained = [
            i for i in open_incidents
            if i["containment_status"] == "pending" and
            time.time() - i["opened_at"] > 3600
        ]
        
        if uncontained:
            findings.append(DiagnosticFinding(
                system=self.system_type,
                severity=DiagnosticSeverity.ERROR,
                symptom=f"{len(uncontained)} incidents uncontained for >1 hour",
                diagnosis="Infection spreading - incidents not being contained",
                recommendation="Implement containment procedures immediately"
            ))
        
        return findings


# =============================================================================
# 7. Respiratory System: Network Traffic Analysis & Access Control
# =============================================================================

class RespiratorySystem(BiologicalSystemComponent):
    """
    The Respiratory System: Network Traffic Analysis (NTA) & Access Control
    
    Filters the "air" (network traffic) entering the system, allowing
    legitimate traffic while blocking "toxins" (malicious packets/requests).
    
    Diagnostic Role: Monitors the health of network "gas exchange."
    Irregularities here signal infiltration attempts or data exfiltration.
    """
    
    def __init__(self):
        super().__init__(BiologicalSystem.RESPIRATORY)
        self._traffic_stats: Dict[str, int] = {}
        self._blocked_sources: Dict[str, Dict[str, Any]] = {}
        self._allowed_patterns: List[str] = []
        self._blocked_patterns: List[str] = []
        self._exfiltration_alerts: List[Dict[str, Any]] = []
    
    def add_allowed_pattern(self, pattern: str) -> None:
        """Add an allowed traffic pattern."""
        self._allowed_patterns.append(pattern)
    
    def add_blocked_pattern(self, pattern: str) -> None:
        """Add a blocked traffic pattern."""
        self._blocked_patterns.append(pattern)
    
    def block_source(self, source: str, reason: str) -> None:
        """Block a traffic source."""
        self._blocked_sources[source] = {
            "blocked_at": time.time(),
            "reason": reason
        }
    
    def process(self, event: SecurityEvent) -> Optional[SecurityEvent]:
        """Analyze network traffic events."""
        event.processing_trail.append(f"respiratory:{time.time()}")
        
        # Track traffic statistics
        source = event.payload.get("source_ip", "unknown")
        self._traffic_stats[source] = self._traffic_stats.get(source, 0) + 1
        
        # Check if source is blocked
        if source in self._blocked_sources:
            event.enrichments["blocked"] = True
            event.enrichments["block_reason"] = self._blocked_sources[source]["reason"]
            return event
        
        # Check for exfiltration patterns
        if self._detect_exfiltration(event):
            self._exfiltration_alerts.append({
                "event_id": event.event_id,
                "source": source,
                "timestamp": time.time()
            })
            event.enrichments["exfiltration_suspected"] = True
        
        return event
    
    def _detect_exfiltration(self, event: SecurityEvent) -> bool:
        """Detect potential data exfiltration."""
        payload = event.payload
        
        # Check for large outbound transfers
        bytes_out = payload.get("bytes_out", 0)
        if bytes_out > 10_000_000:  # 10 MB
            return True
        
        # Check for unusual destination
        dest = payload.get("destination", "")
        if any(pattern in dest for pattern in self._blocked_patterns):
            return True
        
        return False
    
    def diagnose(self) -> List[DiagnosticFinding]:
        """Diagnose respiratory system health."""
        findings = []
        
        # Check for traffic anomalies
        if self._traffic_stats:
            max_traffic = max(self._traffic_stats.values())
            if max_traffic > 1000:  # High traffic from single source
                top_source = max(
                    self._traffic_stats,
                    key=self._traffic_stats.get
                )
                findings.append(DiagnosticFinding(
                    system=self.system_type,
                    severity=DiagnosticSeverity.WARNING,
                    symptom=f"High traffic volume from {top_source}: {max_traffic} events",
                    diagnosis="Potential flooding or scan activity",
                    recommendation="Investigate traffic source and consider blocking"
                ))
        
        # Check for exfiltration alerts
        if len(self._exfiltration_alerts) > 3:
            findings.append(DiagnosticFinding(
                system=self.system_type,
                severity=DiagnosticSeverity.CRITICAL,
                symptom=f"{len(self._exfiltration_alerts)} exfiltration alerts",
                diagnosis="Potential data exfiltration in progress",
                recommendation="Investigate outbound traffic immediately"
            ))
        
        return findings


# =============================================================================
# 8. Digestive System: Data Ingestion, Parsing & Enrichment
# =============================================================================

class DigestiveSystem(BiologicalSystemComponent):
    """
    The Digestive System: Data Ingestion, Parsing & Enrichment
    
    Breaks down raw, unstructured data (telemetry) into "usable nutrients"
    (enriched, tagged events) that the Nervous System can consume.
    
    Diagnostic Role: Converts raw data into actionable intelligence.
    "Indigestion" indicates parsing errors or log format incompatibilities
    that blind downstream analytics.
    """
    
    def __init__(self):
        super().__init__(BiologicalSystem.DIGESTIVE)
        self._parsers: Dict[str, Callable[[str], Dict[str, Any]]] = {}
        self._enrichers: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {}
        self._parse_errors: List[Dict[str, Any]] = []
        self._enrichment_errors: List[Dict[str, Any]] = []
    
    def register_parser(
        self,
        log_format: str,
        parser: Callable[[str], Dict[str, Any]]
    ) -> None:
        """Register a log parser."""
        self._parsers[log_format] = parser
    
    def register_enricher(
        self,
        enrichment_type: str,
        enricher: Callable[[Dict[str, Any]], Dict[str, Any]]
    ) -> None:
        """Register an enrichment function."""
        self._enrichers[enrichment_type] = enricher
    
    def parse_raw_log(
        self,
        raw_data: str,
        log_format: str
    ) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """Parse raw log data into structured format."""
        if log_format not in self._parsers:
            error = f"No parser for format: {log_format}"
            self._parse_errors.append({
                "format": log_format,
                "error": error,
                "timestamp": time.time()
            })
            return None, error
        
        try:
            parsed = self._parsers[log_format](raw_data)
            return parsed, None
        except Exception as e:
            error = str(e)
            self._parse_errors.append({
                "format": log_format,
                "error": error,
                "timestamp": time.time()
            })
            return None, error
    
    def enrich_event(self, event: SecurityEvent) -> SecurityEvent:
        """Apply all enrichers to an event."""
        for enrichment_type, enricher in self._enrichers.items():
            try:
                enrichment = enricher(event.payload)
                event.enrichments[enrichment_type] = enrichment
            except Exception as e:
                self._enrichment_errors.append({
                    "type": enrichment_type,
                    "error": str(e),
                    "event_id": event.event_id,
                    "timestamp": time.time()
                })
        return event
    
    def process(self, event: SecurityEvent) -> Optional[SecurityEvent]:
        """Process and enrich security events."""
        event.processing_trail.append(f"digestive:{time.time()}")
        
        # Apply enrichments
        event = self.enrich_event(event)
        
        # Update metrics
        error_count = len(self._parse_errors) + len(self._enrichment_errors)
        self.update_metrics(
            error_rate=error_count / max(1, self.metrics.throughput + error_count)
        )
        
        return event
    
    def diagnose(self) -> List[DiagnosticFinding]:
        """Diagnose digestive system health."""
        findings = []
        
        # Check for parsing errors (indigestion)
        recent_parse_errors = [
            e for e in self._parse_errors
            if time.time() - e["timestamp"] < 3600
        ]
        if len(recent_parse_errors) > 10:
            findings.append(DiagnosticFinding(
                system=self.system_type,
                severity=DiagnosticSeverity.ERROR,
                symptom=f"{len(recent_parse_errors)} parse errors in last hour",
                diagnosis="Indigestion - unable to process incoming data",
                recommendation="Review log formats and add appropriate parsers"
            ))
        
        # Check for enrichment coverage
        if not self._enrichers:
            findings.append(DiagnosticFinding(
                system=self.system_type,
                severity=DiagnosticSeverity.WARNING,
                symptom="No enrichers registered",
                diagnosis="Events not being enriched with context",
                recommendation="Register enrichers for geolocation, threat intel, etc."
            ))
        
        # Check parser coverage
        if not self._parsers:
            findings.append(DiagnosticFinding(
                system=self.system_type,
                severity=DiagnosticSeverity.CRITICAL,
                symptom="No parsers registered",
                diagnosis="Unable to process any log formats",
                recommendation="Register parsers for expected log formats"
            ))
        
        return findings


# =============================================================================
# 9. Endocrine System: Policy & Configuration Orchestration
# =============================================================================

class EndocrineSystem(BiologicalSystemComponent):
    """
    The Endocrine System: Policy & Configuration Orchestration
    
    Uses "hormonal" signals (API calls and configuration pushes) to regulate
    the long-term state across the entire body slowly.
    
    Diagnostic Role: Manages systemic balance. Unlike the fast-acting
    Nervous System, this system handles slow, system-wide changes;
    imbalances here cause widespread dysfunction across the environment.
    """
    
    def __init__(self):
        super().__init__(BiologicalSystem.ENDOCRINE)
        self._configuration_state: Dict[str, Dict[str, Any]] = {}
        self._pending_changes: List[Dict[str, Any]] = []
        self._applied_changes: List[Dict[str, Any]] = []
        self._system_targets: Dict[str, BiologicalSystemComponent] = {}
    
    def register_target(
        self,
        target_id: str,
        target: BiologicalSystemComponent
    ) -> None:
        """Register a target system for orchestration."""
        self._system_targets[target_id] = target
    
    def set_configuration(
        self,
        target_id: str,
        config_key: str,
        config_value: Any
    ) -> None:
        """Set a configuration value for a target."""
        if target_id not in self._configuration_state:
            self._configuration_state[target_id] = {}
        
        self._pending_changes.append({
            "target_id": target_id,
            "config_key": config_key,
            "old_value": self._configuration_state[target_id].get(config_key),
            "new_value": config_value,
            "queued_at": time.time()
        })
        
        self._configuration_state[target_id][config_key] = config_value
    
    def process(self, event: SecurityEvent) -> Optional[SecurityEvent]:
        """Process events that may trigger configuration changes."""
        event.processing_trail.append(f"endocrine:{time.time()}")
        
        # Check if event indicates need for systemic change
        if event.enrichments.get("threat_assessment", {}).get("risk_level") == "CRITICAL":
            # Trigger defensive posture change
            self.set_configuration(
                "global",
                "security_posture",
                "heightened"
            )
            event.enrichments["orchestration_triggered"] = True
        
        return event
    
    def propagate_changes(self) -> Dict[str, Any]:
        """Propagate pending configuration changes (hormone release)."""
        results = {"propagated": 0, "failed": 0}
        
        changes_to_apply = self._pending_changes.copy()
        self._pending_changes.clear()
        
        for change in changes_to_apply:
            
            # In a real implementation, this would call APIs or push configs
            # For now, we just track the changes
            change["applied_at"] = time.time()
            change["status"] = "applied"
            self._applied_changes.append(change)
            results["propagated"] += 1
        
        return results
    
    def diagnose(self) -> List[DiagnosticFinding]:
        """Diagnose endocrine system health."""
        findings = []
        
        # Check for configuration imbalances
        if len(self._pending_changes) > 20:
            findings.append(DiagnosticFinding(
                system=self.system_type,
                severity=DiagnosticSeverity.WARNING,
                symptom=f"{len(self._pending_changes)} configuration changes pending",
                diagnosis="Configuration drift - changes not being propagated",
                recommendation="Process pending configuration changes"
            ))
        
        # Check for orchestration coverage
        if not self._system_targets:
            findings.append(DiagnosticFinding(
                system=self.system_type,
                severity=DiagnosticSeverity.WARNING,
                symptom="No target systems registered",
                diagnosis="Endocrine system cannot orchestrate other systems",
                recommendation="Register target systems for orchestration"
            ))
        
        return findings


# =============================================================================
# Unified Security Organism
# =============================================================================

class SecurityOrganism:
    """
    The complete security organism integrating all biological systems.
    
    Provides holistic security through systemic interaction between
    all nine biological system components.
    """
    
    def __init__(self):
        # Initialize all biological systems
        self.circulatory = CirculatorySystem()
        self.nervous = NervousSystem()
        self.immune = ImmuneSystem()
        self.skeletal = SkeletalSystem()
        self.muscular = MuscularSystem()
        self.lymphatic = LymphaticSystem()
        self.respiratory = RespiratorySystem()
        self.digestive = DigestiveSystem()
        self.endocrine = EndocrineSystem()
        
        # Map systems for easy access
        self._systems: Dict[BiologicalSystem, BiologicalSystemComponent] = {
            BiologicalSystem.CIRCULATORY: self.circulatory,
            BiologicalSystem.NERVOUS: self.nervous,
            BiologicalSystem.IMMUNE: self.immune,
            BiologicalSystem.SKELETAL: self.skeletal,
            BiologicalSystem.MUSCULAR: self.muscular,
            BiologicalSystem.LYMPHATIC: self.lymphatic,
            BiologicalSystem.RESPIRATORY: self.respiratory,
            BiologicalSystem.DIGESTIVE: self.digestive,
            BiologicalSystem.ENDOCRINE: self.endocrine,
        }
        
        # Set up system interconnections
        self._wire_systems()
    
    def _wire_systems(self) -> None:
        """Wire up the interconnections between systems."""
        # Subscribe all systems to the circulatory system
        for system in self._systems.values():
            if system != self.circulatory:
                self.circulatory.subscribe(system)
        
        # Register target systems with endocrine
        for system_type, system in self._systems.items():
            self.endocrine.register_target(system_type.value, system)
    
    def ingest_event(self, event: SecurityEvent) -> None:
        """Ingest a security event into the organism."""
        # First, process through digestive system for enrichment
        event = self.digestive.process(event)
        
        # Then publish to circulatory system for distribution
        self.circulatory.publish(event)
    
    def pulse(self) -> Dict[str, Any]:
        """
        Perform one "heartbeat" cycle of the organism.
        
        This processes queued events, executes pending actions,
        and propagates configuration changes.
        """
        results = {
            "events_pumped": self.circulatory.pump(),
            "actions_executed": self.muscular.execute_pending(),
            "configs_propagated": self.endocrine.propagate_changes()
        }
        return results
    
    def diagnose(self) -> Dict[str, List[DiagnosticFinding]]:
        """
        Perform systemic diagnosis across all systems.
        
        This enables symptom correlation across systems.
        """
        findings = {}
        for system_type, system in self._systems.items():
            system_findings = system.diagnose()
            if system_findings:
                findings[system_type.value] = system_findings
        return findings
    
    def correlate_symptoms(
        self,
        findings: Dict[str, List[DiagnosticFinding]]
    ) -> List[Dict[str, Any]]:
        """
        Correlate symptoms across systems for integrated diagnosis.
        
        Examples:
        - A "muscle spasm" (failed login) combined with "respiratory distress"
          (unusual outbound traffic) diagnoses a compromised account.
        - The "Skeletal System" detects a bad config, which the "Endocrine System"
          attempts to correct via API. If that fails, the "Immune System" isolates
          the asset to prevent infection.
        """
        correlations = []
        
        # Check for compromised account pattern
        muscular_issues = findings.get("muscular", [])
        respiratory_issues = findings.get("respiratory", [])
        
        has_auth_failures = any(
            "failed" in f.symptom.lower() for f in muscular_issues
        )
        has_traffic_anomaly = any(
            "exfiltration" in f.symptom.lower() or "traffic" in f.symptom.lower()
            for f in respiratory_issues
        )
        
        if has_auth_failures and has_traffic_anomaly:
            correlations.append({
                "correlation_type": "compromised_account",
                "involved_systems": ["muscular", "respiratory"],
                "diagnosis": "Compromised account - authentication failures with unusual traffic",
                "recommended_action": "Investigate user account, reset credentials, block source IP"
            })
        
        # Check for configuration drift leading to vulnerability
        skeletal_issues = findings.get("skeletal", [])
        immune_issues = findings.get("immune", [])
        
        has_policy_violations = any(
            "violation" in f.symptom.lower() for f in skeletal_issues
        )
        has_detection_failures = any(
            "detection" in f.symptom.lower() for f in immune_issues
        )
        
        if has_policy_violations and has_detection_failures:
            correlations.append({
                "correlation_type": "policy_exposure",
                "involved_systems": ["skeletal", "immune"],
                "diagnosis": "Policy misconfigurations leading to detection gaps",
                "recommended_action": "Review and remediate policy violations, update detection rules"
            })
        
        return correlations
    
    def get_health_summary(self) -> Dict[str, Any]:
        """Get overall health summary of the organism."""
        health_status = {}
        overall_health = SystemHealth.HEALTHY
        
        for system_type, system in self._systems.items():
            health = system.get_health()
            health_status[system_type.value] = health.value
            
            if health == SystemHealth.CRITICAL:
                overall_health = SystemHealth.CRITICAL
            elif health == SystemHealth.DEGRADED and overall_health != SystemHealth.CRITICAL:
                overall_health = SystemHealth.DEGRADED
        
        return {
            "overall_health": overall_health.value,
            "system_health": health_status,
            "timestamp": time.time()
        }
