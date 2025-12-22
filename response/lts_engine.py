"""
Step 4: The Logic-Based Response Engine (LTS)

Implements Labeled Transition Systems (LTS) for deterministic, 
pre-calculated responses to security events:
- Finite State Machine modeling of security posture
- Linear Temporal Logic (LTL) formula evaluation
- Policy-as-Code implementation (Rego-style)
- Cycle detection for deadlock prevention

Unlike AI "agents" that make probabilistic decisions, this system
provides mathematically deterministic counter-transitions for
every possible attack state.
"""

from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import time


# =============================================================================
# Labeled Transition System (LTS)
# =============================================================================

class SecurityState(Enum):
    """Pre-defined security posture states."""
    NORMAL = "NORMAL"
    ELEVATED = "ELEVATED"
    UNDER_ATTACK = "UNDER_ATTACK"
    UNDER_DDOS = "UNDER_DDOS"
    BREACH_DETECTED = "BREACH_DETECTED"
    LOCKDOWN = "LOCKDOWN"
    RECOVERY = "RECOVERY"
    MAINTENANCE = "MAINTENANCE"


@dataclass
class Transition:
    """Represents a state transition in the LTS."""
    name: str
    source_state: SecurityState
    target_state: SecurityState
    trigger_condition: Callable[[Dict[str, Any]], bool]
    actions: List[Callable[[Dict[str, Any]], None]] = field(default_factory=list)
    priority: int = 0  # Higher priority transitions evaluated first


@dataclass
class LTSState:
    """Represents a state in the Labeled Transition System."""
    name: SecurityState
    entry_actions: List[Callable[[], None]] = field(default_factory=list)
    exit_actions: List[Callable[[], None]] = field(default_factory=list)
    invariants: List[Callable[[], bool]] = field(default_factory=list)


class LabeledTransitionSystem:
    """
    Finite State Machine for security posture management.
    
    Models the system as states with deterministic transitions,
    ensuring every attack has a pre-calculated response.
    """
    
    def __init__(self, initial_state: SecurityState = SecurityState.NORMAL):
        self.current_state = initial_state
        self.states: Dict[SecurityState, LTSState] = {}
        self.transitions: List[Transition] = []
        self.state_history: List[Tuple[SecurityState, float]] = [
            (initial_state, time.time())
        ]
        self.context: Dict[str, Any] = {}
        self._action_log: List[Dict[str, Any]] = []
        
        # Initialize default states
        for state in SecurityState:
            self.states[state] = LTSState(name=state)
    
    def add_transition(
        self,
        name: str,
        source: SecurityState,
        target: SecurityState,
        condition: Callable[[Dict[str, Any]], bool],
        actions: Optional[List[Callable[[Dict[str, Any]], None]]] = None,
        priority: int = 0
    ) -> None:
        """Add a transition to the LTS."""
        transition = Transition(
            name=name,
            source_state=source,
            target_state=target,
            trigger_condition=condition,
            actions=actions or [],
            priority=priority
        )
        self.transitions.append(transition)
        # Sort by priority (highest first)
        self.transitions.sort(key=lambda t: -t.priority)
    
    def set_context(self, key: str, value: Any) -> None:
        """Update context for transition evaluation."""
        self.context[key] = value
    
    def evaluate(self) -> Optional[str]:
        """
        Evaluate all transitions from current state.
        Returns name of triggered transition, if any.
        """
        for transition in self.transitions:
            if transition.source_state != self.current_state:
                continue
            
            if transition.trigger_condition(self.context):
                self._execute_transition(transition)
                return transition.name
        
        return None
    
    def _execute_transition(self, transition: Transition) -> None:
        """Execute a transition and update state."""
        # Execute exit actions of current state
        current_lts_state = self.states[self.current_state]
        for action in current_lts_state.exit_actions:
            action()
        
        # Execute transition actions
        for action in transition.actions:
            action(self.context)
            # Get action name robustly for logging
            action_name = getattr(action, '__name__', None)
            if not action_name or action_name == '<lambda>':
                action_name = getattr(action, 'action_name', None) or f"action_{id(action)}"
            self._action_log.append({
                "transition": transition.name,
                "action": action_name,
                "timestamp": time.time()
            })
        
        # Update state
        old_state = self.current_state
        self.current_state = transition.target_state
        self.state_history.append((self.current_state, time.time()))
        
        # Execute entry actions of new state
        new_lts_state = self.states[self.current_state]
        for action in new_lts_state.entry_actions:
            action()
    
    def get_available_transitions(self) -> List[str]:
        """Return names of transitions available from current state."""
        return [
            t.name for t in self.transitions
            if t.source_state == self.current_state
        ]
    
    def check_invariants(self) -> Tuple[bool, List[str]]:
        """Check all invariants of current state."""
        violations = []
        lts_state = self.states[self.current_state]
        
        for i, invariant in enumerate(lts_state.invariants):
            if not invariant():
                violations.append(f"Invariant {i} violated in state {self.current_state.value}")
        
        return len(violations) == 0, violations
    
    def get_state_report(self) -> Dict[str, Any]:
        """Generate state report."""
        return {
            "current_state": self.current_state.value,
            "state_history_length": len(self.state_history),
            "recent_history": [
                {"state": s.value, "timestamp": t}
                for s, t in self.state_history[-10:]
            ],
            "available_transitions": self.get_available_transitions(),
            "action_log_length": len(self._action_log)
        }


# =============================================================================
# Linear Temporal Logic (LTL) Evaluator
# =============================================================================

class LTLOperator(Enum):
    """LTL operators."""
    GLOBALLY = "G"      # □ - Always (in all future states)
    FINALLY = "F"       # ◇ - Eventually (in some future state)
    NEXT = "X"          # ○ - In the next state
    UNTIL = "U"         # U - Until
    IMPLIES = "=>"      # → - Implies
    AND = "∧"           # ∧ - And
    OR = "∨"            # ∨ - Or
    NOT = "¬"           # ¬ - Not


@dataclass
class LTLFormula:
    """Represents an LTL formula."""
    operator: Optional[LTLOperator]
    operands: List[Any]  # Can be LTLFormula or atomic propositions
    atomic: Optional[str] = None  # If this is an atomic proposition


class LTLEvaluator:
    """
    Evaluator for Linear Temporal Logic formulas.
    
    Used to specify and verify temporal properties like:
    - "If breach detected (F), system eventually locks down (G)"
    - Formalized as: □(F => ◇G)
    """
    
    def __init__(self):
        self.propositions: Dict[str, Callable[[], bool]] = {}
        self.trace: List[Dict[str, bool]] = []
    
    def register_proposition(
        self,
        name: str,
        evaluator: Callable[[], bool]
    ) -> None:
        """Register an atomic proposition."""
        self.propositions[name] = evaluator
    
    def record_state(self) -> None:
        """Record current state of all propositions."""
        state = {
            name: evaluator()
            for name, evaluator in self.propositions.items()
        }
        self.trace.append(state)
    
    def evaluate_globally(self, prop: str, horizon: int = -1) -> bool:
        """
        Evaluate □φ (globally φ) - φ holds in all states.
        
        Args:
            prop: Proposition name
            horizon: Number of states to check (-1 for all)
        """
        states_to_check = self.trace if horizon < 0 else self.trace[-horizon:]
        return all(state.get(prop, False) for state in states_to_check)
    
    def evaluate_finally(self, prop: str, horizon: int = -1) -> bool:
        """
        Evaluate ◇φ (finally φ) - φ holds in at least one state.
        
        Args:
            prop: Proposition name
            horizon: Number of states to check (-1 for all)
        """
        states_to_check = self.trace if horizon < 0 else self.trace[-horizon:]
        return any(state.get(prop, False) for state in states_to_check)
    
    def evaluate_implies_eventually(
        self,
        antecedent: str,
        consequent: str
    ) -> bool:
        """
        Evaluate □(P => ◇Q) - Globally, if P then eventually Q.
        
        This is used for properties like:
        "If breach detected, system eventually locks down"
        """
        antecedent_occurred = False
        consequent_followed = False
        
        for i, state in enumerate(self.trace):
            if state.get(antecedent, False):
                antecedent_occurred = True
                # Check if consequent holds in this or any future state
                for future_state in self.trace[i:]:
                    if future_state.get(consequent, False):
                        consequent_followed = True
                        break
                
                if not consequent_followed:
                    return False  # Found P without eventual Q
        
        return True  # Either P never occurred, or Q always followed
    
    def clear_trace(self) -> None:
        """Clear the recorded trace."""
        self.trace.clear()


# =============================================================================
# Policy-as-Code Engine (Rego-style)
# =============================================================================

@dataclass
class PolicyRule:
    """Represents a policy rule."""
    name: str
    description: str
    conditions: List[Callable[[Dict[str, Any]], bool]]
    action: str
    severity: str = "MEDIUM"
    enabled: bool = True


class PolicyEngine:
    """
    Policy-as-Code engine for security rules.
    
    Implements Rego-style declarative policy evaluation:
    - Rules are defined as conditions -> actions
    - Evaluation is deterministic and auditable
    - Policies are decoupled from application logic
    """
    
    def __init__(self):
        self.rules: Dict[str, PolicyRule] = {}
        self.evaluation_log: List[Dict[str, Any]] = []
    
    def add_rule(self, rule: PolicyRule) -> None:
        """Add a policy rule."""
        self.rules[rule.name] = rule
    
    def remove_rule(self, rule_name: str) -> bool:
        """Remove a policy rule. Returns True if removed."""
        if rule_name in self.rules:
            del self.rules[rule_name]
            return True
        return False
    
    def enable_rule(self, rule_name: str) -> None:
        """Enable a rule."""
        if rule_name in self.rules:
            self.rules[rule_name].enabled = True
    
    def disable_rule(self, rule_name: str) -> None:
        """Disable a rule."""
        if rule_name in self.rules:
            self.rules[rule_name].enabled = False
    
    def evaluate(
        self,
        input_data: Dict[str, Any]
    ) -> Tuple[List[str], List[Dict[str, Any]]]:
        """
        Evaluate all rules against input data.
        
        Returns:
            Tuple of (triggered_actions, violations)
        """
        triggered_actions = []
        violations = []
        
        for rule_name, rule in self.rules.items():
            if not rule.enabled:
                continue
            
            # Check if all conditions are met
            conditions_met = all(
                condition(input_data) for condition in rule.conditions
            )
            
            if conditions_met:
                triggered_actions.append(rule.action)
                violations.append({
                    "rule": rule_name,
                    "description": rule.description,
                    "action": rule.action,
                    "severity": rule.severity,
                    "timestamp": time.time()
                })
                
                self.evaluation_log.append({
                    "rule": rule_name,
                    "result": "triggered",
                    "action": rule.action,
                    "timestamp": time.time()
                })
        
        return triggered_actions, violations
    
    def get_rules_summary(self) -> Dict[str, Any]:
        """Return summary of all rules."""
        return {
            "total_rules": len(self.rules),
            "enabled_rules": sum(1 for r in self.rules.values() if r.enabled),
            "rules": [
                {
                    "name": r.name,
                    "description": r.description,
                    "action": r.action,
                    "severity": r.severity,
                    "enabled": r.enabled
                }
                for r in self.rules.values()
            ]
        }


# =============================================================================
# Cycle Detection for Deadlock Prevention
# =============================================================================

class StateGraph:
    """
    Graph structure for modeling state transitions.
    Used for cycle detection to prevent deadlocks.
    """
    
    def __init__(self):
        self.adjacency: Dict[str, Set[str]] = defaultdict(set)
        self.nodes: Set[str] = set()
    
    def add_node(self, node: str) -> None:
        """Add a node to the graph."""
        self.nodes.add(node)
    
    def add_edge(self, source: str, target: str) -> None:
        """Add a directed edge from source to target."""
        self.nodes.add(source)
        self.nodes.add(target)
        self.adjacency[source].add(target)
    
    def detect_cycles(self) -> List[List[str]]:
        """
        Detect all cycles in the graph using DFS.
        
        Returns:
            List of cycles found (each cycle is a list of nodes)
        """
        cycles = []
        visited = set()
        rec_stack = set()
        path = []
        
        def dfs(node: str) -> None:
            visited.add(node)
            rec_stack.add(node)
            path.append(node)
            
            for neighbor in self.adjacency.get(node, set()):
                if neighbor not in visited:
                    dfs(neighbor)
                elif neighbor in rec_stack:
                    # Found a cycle
                    cycle_start = path.index(neighbor)
                    cycle = path[cycle_start:] + [neighbor]
                    cycles.append(cycle)
            
            path.pop()
            rec_stack.remove(node)
        
        for node in self.nodes:
            if node not in visited:
                dfs(node)
        
        return cycles
    
    def has_cycle(self) -> bool:
        """Check if graph has any cycles. O(V + E)."""
        return len(self.detect_cycles()) > 0
    
    def is_reachable(self, source: str, target: str) -> bool:
        """Check if target is reachable from source using BFS."""
        if source not in self.nodes or target not in self.nodes:
            return False
        
        visited = set()
        queue = deque([source])
        
        while queue:
            current = queue.popleft()
            if current == target:
                return True
            
            visited.add(current)
            for neighbor in self.adjacency.get(current, set()):
                if neighbor not in visited:
                    queue.append(neighbor)
        
        return False


# =============================================================================
# Pre-built Security Response System
# =============================================================================

def create_security_lts() -> LabeledTransitionSystem:
    """
    Create a pre-configured LTS for security response.
    
    Implements deterministic responses for common attack scenarios.
    """
    lts = LabeledTransitionSystem(SecurityState.NORMAL)
    
    # Transition: Normal -> Elevated (threat detected)
    lts.add_transition(
        name="threat_detected",
        source=SecurityState.NORMAL,
        target=SecurityState.ELEVATED,
        condition=lambda ctx: ctx.get("threat_level", 0) > 3,
        priority=10
    )
    
    # Transition: Elevated -> Under Attack
    lts.add_transition(
        name="attack_confirmed",
        source=SecurityState.ELEVATED,
        target=SecurityState.UNDER_ATTACK,
        condition=lambda ctx: ctx.get("attack_confirmed", False),
        priority=20
    )
    
    # Transition: Any state -> DDoS detected
    for state in [SecurityState.NORMAL, SecurityState.ELEVATED]:
        lts.add_transition(
            name=f"ddos_from_{state.value.lower()}",
            source=state,
            target=SecurityState.UNDER_DDOS,
            condition=lambda ctx: ctx.get("ddos_detected", False),
            priority=30
        )
    
    # Transition: Under Attack -> Breach Detected
    lts.add_transition(
        name="breach_detected",
        source=SecurityState.UNDER_ATTACK,
        target=SecurityState.BREACH_DETECTED,
        condition=lambda ctx: ctx.get("breach_confirmed", False),
        priority=40
    )
    
    # Transition: Breach Detected -> Lockdown
    lts.add_transition(
        name="initiate_lockdown",
        source=SecurityState.BREACH_DETECTED,
        target=SecurityState.LOCKDOWN,
        condition=lambda ctx: True,  # Always transition to lockdown on breach
        priority=50
    )
    
    # Transition: Lockdown -> Recovery
    lts.add_transition(
        name="begin_recovery",
        source=SecurityState.LOCKDOWN,
        target=SecurityState.RECOVERY,
        condition=lambda ctx: ctx.get("threat_contained", False),
        priority=10
    )
    
    # Transition: Recovery -> Normal
    lts.add_transition(
        name="recovery_complete",
        source=SecurityState.RECOVERY,
        target=SecurityState.NORMAL,
        condition=lambda ctx: ctx.get("recovery_verified", False),
        priority=10
    )
    
    # Transition: DDoS -> Normal (attack mitigated)
    lts.add_transition(
        name="ddos_mitigated",
        source=SecurityState.UNDER_DDOS,
        target=SecurityState.NORMAL,
        condition=lambda ctx: ctx.get("ddos_mitigated", False),
        priority=10
    )
    
    return lts


def create_security_policies() -> PolicyEngine:
    """
    Create pre-configured security policies.
    
    Implements Rego-style rules for common security scenarios.
    """
    engine = PolicyEngine()
    
    # Rule: Ransomware detected -> Isolate device
    engine.add_rule(PolicyRule(
        name="ransomware_isolation",
        description="If ransomware signature detected, isolate device immediately",
        conditions=[
            lambda data: data.get("threat_type") == "ransomware",
            lambda data: data.get("confidence", 0) > 0.85
        ],
        action="ISOLATE_DEVICE",
        severity="CRITICAL"
    ))
    
    # Rule: Critical CVE -> Block build
    engine.add_rule(PolicyRule(
        name="critical_cve_block",
        description="Block builds with critical vulnerabilities",
        conditions=[
            lambda data: data.get("vulnerability_severity") == "CRITICAL"
        ],
        action="BLOCK_BUILD",
        severity="CRITICAL"
    ))
    
    # Rule: Suspicious login -> MFA required
    engine.add_rule(PolicyRule(
        name="suspicious_login_mfa",
        description="Require MFA for suspicious login attempts",
        conditions=[
            lambda data: data.get("login_risk_score", 0) > 7,
            lambda data: data.get("new_location", False)
        ],
        action="REQUIRE_MFA",
        severity="HIGH"
    ))
    
    # Rule: Data exfiltration -> Alert
    engine.add_rule(PolicyRule(
        name="data_exfil_alert",
        description="Alert on potential data exfiltration",
        conditions=[
            lambda data: data.get("data_transfer_mb", 0) > 100,
            lambda data: data.get("destination_external", False)
        ],
        action="ALERT_SOC",
        severity="HIGH"
    ))
    
    # Rule: Brute force -> Block IP
    engine.add_rule(PolicyRule(
        name="brute_force_block",
        description="Block IP after failed login attempts",
        conditions=[
            lambda data: data.get("failed_logins", 0) > 5,
            lambda data: data.get("time_window_minutes", 60) < 10
        ],
        action="BLOCK_IP",
        severity="MEDIUM"
    ))
    
    return engine
