"""
Intrusion Detection and Response Module

Provides advanced capabilities for detecting, freezing, and benchmarking
malicious actors (spies/intruders) on the system:
- Process behavior analysis
- Network activity monitoring  
- File access tracking
- Keylogger detection
- Remote access detection
- Intruder action logging for system strengthening

This module operates deterministically without AI/ML dependencies,
using behavioral heuristics and signature-based detection.
"""

import hashlib
import os
import subprocess
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional, Set

from core.platform_support import (
    get_platform, PlatformType,
    ProcessManager, ProcessInfo, NetworkMonitor, NetworkConnection
)


# =============================================================================
# Threat Classification
# =============================================================================

class ThreatLevel:
    """Threat level classifications."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ThreatType:
    """Types of detected threats."""
    KEYLOGGER = "keylogger"
    SPYWARE = "spyware"
    RAT = "remote_access_trojan"
    DATA_EXFILTRATION = "data_exfiltration"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    SUSPICIOUS_PROCESS = "suspicious_process"
    NETWORK_INTRUSION = "network_intrusion"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PERSISTENCE_MECHANISM = "persistence_mechanism"
    SCREEN_CAPTURE = "screen_capture"


# =============================================================================
# Intruder Profile
# =============================================================================

@dataclass
class IntruderProfile:
    """Profile of a detected intruder/spy."""
    intruder_id: str
    first_detected: float
    last_activity: float
    threat_level: str
    threat_types: List[str] = field(default_factory=list)
    associated_pids: List[int] = field(default_factory=list)
    associated_ips: List[str] = field(default_factory=list)
    associated_files: List[str] = field(default_factory=list)
    actions_logged: List[Dict[str, Any]] = field(default_factory=list)
    is_frozen: bool = False
    total_actions: int = 0
    risk_score: float = 0.0


@dataclass
class IntrusionEvent:
    """Represents a detected intrusion event."""
    event_id: str
    timestamp: float
    event_type: str
    threat_level: str
    source: str  # process, network, file, etc.
    source_id: str  # PID, IP, file path
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    related_intruder_id: Optional[str] = None
    action_taken: str = "logged"


# =============================================================================
# Behavioral Detection Signatures
# =============================================================================

class BehaviorSignatures:
    """
    Behavioral signatures for detecting malicious activity.
    
    These signatures are based on common malware behaviors
    and don't require AI/ML inference.
    """
    
    # Suspicious process names/patterns
    SUSPICIOUS_PROCESS_NAMES = {
        'keylog', 'keygrab', 'hookkey', 'capturekey',
        'spy', 'stealth', 'hidden', 'backdoor',
        'rat', 'remote', 'screencap', 'screenshot',
        'meterpreter', 'cobaltstrike', 'mimikatz',
        'powersploit', 'empire', 'netcat', 'ncat',
        'psexec', 'procdump', 'lazagne'
    }
    
    # Suspicious parent-child process relationships
    SUSPICIOUS_PROCESS_CHAINS = [
        ('cmd.exe', 'powershell.exe'),
        ('explorer.exe', 'cmd.exe'),
        ('winword.exe', 'cmd.exe'),
        ('excel.exe', 'powershell.exe'),
        ('outlook.exe', 'cmd.exe'),
        ('svchost.exe', 'cmd.exe'),  # Unusual if not legitimate
    ]
    
    # Suspicious file locations
    SUSPICIOUS_PATHS = {
        PlatformType.WINDOWS: [
            r'\AppData\Local\Temp',
            r'\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup',
            r'\Windows\Temp',
            r'\Users\Public',
            r'\ProgramData',
        ],
        PlatformType.LINUX: [
            '/tmp',
            '/var/tmp',
            '/dev/shm',
            '/home/*/.config/autostart',
            '/etc/cron.d',
        ]
    }
    
    # Known malicious file extensions
    SUSPICIOUS_EXTENSIONS = {
        '.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1',
        '.vbs', '.js', '.hta', '.wsf', '.lnk'
    }
    
    # Suspicious network ports (backdoors, RATs)
    SUSPICIOUS_PORTS = {
        4444,   # Metasploit default
        5555,   # Common backdoor
        6666,   # Common backdoor
        7777,   # Common backdoor
        8888,   # Common backdoor
        31337,  # Elite/back orifice
        12345,  # NetBus
        27374,  # SubSeven
        1337,   # Leet
        3389,   # RDP (suspicious if unexpected)
        5900,   # VNC
        5938,   # TeamViewer
        22,     # SSH (monitor for unexpected connections)
    }
    
    # Suspicious system calls / API patterns
    SUSPICIOUS_API_PATTERNS = [
        'keybd_event',
        'GetAsyncKeyState',
        'SetWindowsHookEx',
        'GetClipboardData',
        'BitBlt',  # Screen capture
        'CreateRemoteThread',
        'WriteProcessMemory',
        'VirtualAllocEx',
    ]


# =============================================================================
# Intrusion Detector
# =============================================================================

class IntrusionDetector:
    """
    Core intrusion detection engine.
    
    Monitors system activity and detects suspicious behavior
    indicative of spying or unauthorized access.
    """
    
    def __init__(self):
        self._platform = get_platform()
        self._process_manager = ProcessManager()
        self._network_monitor = NetworkMonitor()
        
        # Detection state
        self._known_processes: Dict[int, ProcessInfo] = {}
        self._process_history: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
        self._network_history: Deque[NetworkConnection] = deque(maxlen=1000)
        self._file_access_history: Deque[Dict[str, Any]] = deque(maxlen=1000)
        
        # Intruder tracking
        self._intruders: Dict[str, IntruderProfile] = {}
        self._events: List[IntrusionEvent] = []
        self._event_counter = 0
        
        # Thresholds
        self._api_call_threshold = 100  # Calls per minute
        self._network_threshold = 50   # Connections per minute
        self._file_access_threshold = 100  # Accesses per minute
    
    def scan_system(self) -> Dict[str, Any]:
        """
        Perform a comprehensive system scan for intrusions.
        
        Returns:
            Scan results with detected threats
        """
        start_time = time.time()
        
        threats = []
        
        # Scan processes
        process_threats = self._scan_processes()
        threats.extend(process_threats)
        
        # Scan network connections
        network_threats = self._scan_network()
        threats.extend(network_threats)
        
        # Scan for persistence mechanisms
        persistence_threats = self._scan_persistence()
        threats.extend(persistence_threats)
        
        # Analyze collected data
        analysis = self._analyze_threats(threats)
        
        duration = time.time() - start_time
        
        return {
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": round(duration, 2),
            "threats_detected": len(threats),
            "threats": threats,
            "intruders_identified": len(self._intruders),
            "intruder_profiles": list(self._intruders.values()),
            "risk_assessment": analysis,
            "recommendations": self._generate_recommendations(threats)
        }
    
    def _scan_processes(self) -> List[IntrusionEvent]:
        """Scan running processes for suspicious activity."""
        threats = []
        processes = self._process_manager.list_processes()
        
        for proc in processes:
            threat = self._analyze_process(proc)
            if threat:
                threats.append(threat)
            
            # Update known processes
            self._known_processes[proc.pid] = proc
        
        return threats
    
    def _analyze_process(self, proc: ProcessInfo) -> Optional[IntrusionEvent]:
        """Analyze a single process for suspicious indicators."""
        suspicion_score = 0.0
        indicators = []
        
        # Check process name against signatures
        proc_name_lower = proc.name.lower()
        for suspicious_name in BehaviorSignatures.SUSPICIOUS_PROCESS_NAMES:
            if suspicious_name in proc_name_lower:
                suspicion_score += 3.0
                indicators.append(f"suspicious_name_pattern: {suspicious_name}")
        
        # Check process path
        if proc.path:
            path_lower = proc.path.lower()
            suspicious_paths = BehaviorSignatures.SUSPICIOUS_PATHS.get(
                self._platform, []
            )
            for sus_path in suspicious_paths:
                if sus_path.lower() in path_lower:
                    suspicion_score += 1.5
                    indicators.append(f"suspicious_location: {sus_path}")
            
            # Check file extension
            for ext in BehaviorSignatures.SUSPICIOUS_EXTENSIONS:
                if proc.path.lower().endswith(ext):
                    # Executable in unusual location
                    if any(s in path_lower for s in ['temp', 'tmp', 'public', 'appdata']):
                        suspicion_score += 2.0
                        indicators.append(f"executable_in_suspicious_location")
        
        # Check command line for suspicious patterns
        if proc.command_line:
            cmd_lower = proc.command_line.lower()
            
            # Encoded PowerShell commands
            if '-encodedcommand' in cmd_lower or '-enc ' in cmd_lower:
                suspicion_score += 4.0
                indicators.append("encoded_powershell_command")
            
            # Hidden window execution
            if '-windowstyle hidden' in cmd_lower or '-w hidden' in cmd_lower:
                suspicion_score += 3.0
                indicators.append("hidden_window_execution")
            
            # Download cradles
            if ('downloadstring' in cmd_lower or 'downloadfile' in cmd_lower or
                'webclient' in cmd_lower or 'invoke-webrequest' in cmd_lower):
                suspicion_score += 4.0
                indicators.append("download_cradle_detected")
            
            # Base64 patterns (potential encoded commands)
            if 'base64' in cmd_lower or len(proc.command_line) > 500:
                suspicion_score += 1.5
                indicators.append("potential_encoded_payload")
        
        # Check parent process relationships
        if proc.parent_pid:
            parent = self._known_processes.get(proc.parent_pid)
            if parent:
                for parent_name, child_name in BehaviorSignatures.SUSPICIOUS_PROCESS_CHAINS:
                    if (parent.name.lower() == parent_name.lower() and
                        proc.name.lower() == child_name.lower()):
                        suspicion_score += 2.5
                        indicators.append(f"suspicious_parent_child: {parent_name}->{child_name}")
        
        # Generate threat event if suspicious
        if suspicion_score >= 3.0:
            threat_level = (
                ThreatLevel.CRITICAL if suspicion_score >= 8.0 else
                ThreatLevel.HIGH if suspicion_score >= 5.0 else
                ThreatLevel.MEDIUM
            )
            
            event = IntrusionEvent(
                event_id=self._generate_event_id(),
                timestamp=time.time(),
                event_type=ThreatType.SUSPICIOUS_PROCESS,
                threat_level=threat_level,
                source="process",
                source_id=str(proc.pid),
                description=f"Suspicious process detected: {proc.name}",
                evidence={
                    "process_name": proc.name,
                    "pid": proc.pid,
                    "path": proc.path,
                    "command_line": proc.command_line,
                    "suspicion_score": suspicion_score,
                    "indicators": indicators
                }
            )
            
            self._events.append(event)
            self._create_or_update_intruder(event, proc)
            
            return event
        
        return None
    
    def _scan_network(self) -> List[IntrusionEvent]:
        """Scan network connections for suspicious activity."""
        threats = []
        connections = self._network_monitor.list_connections()
        
        for conn in connections:
            # Check for suspicious ports
            if (conn.remote_port in BehaviorSignatures.SUSPICIOUS_PORTS or
                conn.local_port in BehaviorSignatures.SUSPICIOUS_PORTS):
                
                event = IntrusionEvent(
                    event_id=self._generate_event_id(),
                    timestamp=time.time(),
                    event_type=ThreatType.NETWORK_INTRUSION,
                    threat_level=ThreatLevel.HIGH,
                    source="network",
                    source_id=f"{conn.remote_address}:{conn.remote_port}",
                    description=f"Suspicious network connection on port {conn.remote_port}",
                    evidence={
                        "local_address": conn.local_address,
                        "local_port": conn.local_port,
                        "remote_address": conn.remote_address,
                        "remote_port": conn.remote_port,
                        "state": conn.state,
                        "pid": conn.pid,
                        "protocol": conn.protocol
                    }
                )
                
                threats.append(event)
                self._events.append(event)
            
            # Check for data exfiltration patterns
            if conn.state == "ESTABLISHED" and conn.remote_port in [80, 443, 8080]:
                # High volume connections to external IPs
                if not self._is_internal_ip(conn.remote_address):
                    # Track for volume analysis
                    self._network_history.append(conn)
        
        # Analyze network patterns
        pattern_threats = self._analyze_network_patterns()
        threats.extend(pattern_threats)
        
        return threats
    
    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP is internal/private."""
        # Handle the 172.16.0.0/12 range correctly (172.16.x.x - 172.31.x.x)
        if ip.startswith('172.'):
            try:
                second_octet = int(ip.split('.')[1])
                if 16 <= second_octet <= 31:
                    return True
            except (ValueError, IndexError):
                # Malformed 172.* IP; treat as external/non-internal.
                return False
        
        return (
            ip.startswith('127.') or
            ip.startswith('10.') or
            ip.startswith('192.168.') or
            ip == '0.0.0.0' or
            ip == '::1'
        )
    
    def _analyze_network_patterns(self) -> List[IntrusionEvent]:
        """Analyze network connection patterns for anomalies."""
        threats = []
        
        # Count connections per remote IP
        ip_counts: Dict[str, int] = defaultdict(int)
        for conn in self._network_history:
            ip_counts[conn.remote_address] += 1
        
        # Detect beaconing behavior (regular connections to same IP)
        for ip, count in ip_counts.items():
            if count > 50 and not self._is_internal_ip(ip):
                event = IntrusionEvent(
                    event_id=self._generate_event_id(),
                    timestamp=time.time(),
                    event_type=ThreatType.DATA_EXFILTRATION,
                    threat_level=ThreatLevel.HIGH,
                    source="network_pattern",
                    source_id=ip,
                    description=f"Potential data exfiltration or beaconing to {ip}",
                    evidence={
                        "remote_ip": ip,
                        "connection_count": count,
                        "pattern": "high_frequency_external_connection"
                    }
                )
                threats.append(event)
                self._events.append(event)
        
        return threats
    
    def _scan_persistence(self) -> List[IntrusionEvent]:
        """Scan for persistence mechanisms."""
        threats = []
        
        if self._platform == PlatformType.WINDOWS:
            threats.extend(self._scan_windows_persistence())
        elif self._platform == PlatformType.LINUX:
            threats.extend(self._scan_linux_persistence())
        
        return threats
    
    def _scan_windows_persistence(self) -> List[IntrusionEvent]:
        """Scan Windows persistence mechanisms."""
        threats = []
        
        # Check scheduled tasks
        try:
            result = subprocess.run(
                ['schtasks', '/query', '/fo', 'csv', '/v'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    line_lower = line.lower()
                    for pattern in BehaviorSignatures.SUSPICIOUS_PROCESS_NAMES:
                        if pattern in line_lower:
                            event = IntrusionEvent(
                                event_id=self._generate_event_id(),
                                timestamp=time.time(),
                                event_type=ThreatType.PERSISTENCE_MECHANISM,
                                threat_level=ThreatLevel.HIGH,
                                source="scheduled_task",
                                source_id=line[:50],
                                description=f"Suspicious scheduled task detected",
                                evidence={
                                    "task_info": line[:200],
                                    "matched_pattern": pattern
                                }
                            )
                            threats.append(event)
                            self._events.append(event)
                            break
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            # `schtasks` may be unavailable or inaccessible (e.g. missing command,
            # permissions, or timeout); in that case we skip scheduled-task scanning.
            pass
        
        return threats
    
    def _scan_linux_persistence(self) -> List[IntrusionEvent]:
        """Scan Linux persistence mechanisms."""
        threats = []
        
        # Check cron jobs
        cron_dirs = ['/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly',
                     '/var/spool/cron/crontabs']
        
        for cron_dir in cron_dirs:
            if os.path.exists(cron_dir):
                try:
                    for item in os.listdir(cron_dir):
                        item_path = os.path.join(cron_dir, item)
                        if os.path.isfile(item_path):
                            try:
                                with open(item_path, 'r') as f:
                                    content = f.read().lower()
                                
                                for pattern in BehaviorSignatures.SUSPICIOUS_PROCESS_NAMES:
                                    if pattern in content:
                                        event = IntrusionEvent(
                                            event_id=self._generate_event_id(),
                                            timestamp=time.time(),
                                            event_type=ThreatType.PERSISTENCE_MECHANISM,
                                            threat_level=ThreatLevel.HIGH,
                                            source="cron_job",
                                            source_id=item_path,
                                            description=f"Suspicious cron job detected",
                                            evidence={
                                                "cron_file": item_path,
                                                "matched_pattern": pattern
                                            }
                                        )
                                        threats.append(event)
                                        self._events.append(event)
                                        break
                            except (PermissionError, OSError):
                                continue
                except (PermissionError, OSError):
                    continue
        
        return threats
    
    def _analyze_threats(self, threats: List[IntrusionEvent]) -> Dict[str, Any]:
        """Analyze collected threats and provide risk assessment."""
        if not threats:
            return {
                "overall_risk": "LOW",
                "risk_score": 0.0,
                "threat_summary": {}
            }
        
        # Count threats by type
        threat_counts: Dict[str, int] = defaultdict(int)
        severity_scores = {
            ThreatLevel.CRITICAL: 10,
            ThreatLevel.HIGH: 7,
            ThreatLevel.MEDIUM: 4,
            ThreatLevel.LOW: 1,
            ThreatLevel.INFO: 0
        }
        
        total_score = 0
        for threat in threats:
            threat_counts[threat.event_type] += 1
            total_score += severity_scores.get(threat.threat_level, 0)
        
        # Calculate overall risk
        avg_score = total_score / len(threats) if threats else 0
        
        if avg_score >= 8 or any(t.threat_level == ThreatLevel.CRITICAL for t in threats):
            overall_risk = "CRITICAL"
        elif avg_score >= 5:
            overall_risk = "HIGH"
        elif avg_score >= 3:
            overall_risk = "MEDIUM"
        else:
            overall_risk = "LOW"
        
        return {
            "overall_risk": overall_risk,
            "risk_score": round(avg_score, 2),
            "threat_summary": dict(threat_counts),
            "critical_threats": len([t for t in threats if t.threat_level == ThreatLevel.CRITICAL]),
            "high_threats": len([t for t in threats if t.threat_level == ThreatLevel.HIGH])
        }
    
    def _generate_recommendations(self, threats: List[IntrusionEvent]) -> List[str]:
        """Generate security recommendations based on detected threats."""
        recommendations = []
        
        threat_types = {t.event_type for t in threats}
        
        if ThreatType.SUSPICIOUS_PROCESS in threat_types:
            recommendations.append(
                "Investigate suspicious processes and terminate if confirmed malicious"
            )
            recommendations.append(
                "Review process execution policies and application whitelisting"
            )
        
        if ThreatType.NETWORK_INTRUSION in threat_types:
            recommendations.append(
                "Review firewall rules and block suspicious IP addresses"
            )
            recommendations.append(
                "Enable network monitoring and intrusion detection systems"
            )
        
        if ThreatType.PERSISTENCE_MECHANISM in threat_types:
            recommendations.append(
                "Review and clean startup entries, scheduled tasks, and cron jobs"
            )
            recommendations.append(
                "Implement integrity monitoring for critical system files"
            )
        
        if ThreatType.DATA_EXFILTRATION in threat_types:
            recommendations.append(
                "Implement data loss prevention (DLP) measures"
            )
            recommendations.append(
                "Review outbound network traffic and implement egress filtering"
            )
        
        if not recommendations:
            recommendations.append("Continue monitoring system for suspicious activity")
        
        return recommendations
    
    def _create_or_update_intruder(
        self,
        event: IntrusionEvent,
        proc: Optional[ProcessInfo] = None
    ) -> str:
        """Create or update intruder profile based on event."""
        # Generate intruder ID based on characteristics
        intruder_id = self._generate_intruder_id(event, proc)
        
        if intruder_id in self._intruders:
            intruder = self._intruders[intruder_id]
            intruder.last_activity = time.time()
            intruder.total_actions += 1
            
            if event.event_type not in intruder.threat_types:
                intruder.threat_types.append(event.event_type)
            
            if proc and proc.pid not in intruder.associated_pids:
                intruder.associated_pids.append(proc.pid)
            
            intruder.actions_logged.append({
                "event_id": event.event_id,
                "timestamp": event.timestamp,
                "type": event.event_type,
                "description": event.description
            })
        else:
            intruder = IntruderProfile(
                intruder_id=intruder_id,
                first_detected=time.time(),
                last_activity=time.time(),
                threat_level=event.threat_level,
                threat_types=[event.event_type],
                associated_pids=[proc.pid] if proc else [],
                total_actions=1,
                actions_logged=[{
                    "event_id": event.event_id,
                    "timestamp": event.timestamp,
                    "type": event.event_type,
                    "description": event.description
                }]
            )
            self._intruders[intruder_id] = intruder
        
        event.related_intruder_id = intruder_id
        return intruder_id
    
    def _generate_intruder_id(
        self,
        event: IntrusionEvent,
        proc: Optional[ProcessInfo] = None
    ) -> str:
        """Generate unique intruder ID based on characteristics."""
        components = [event.event_type]
        
        if proc:
            components.append(proc.name)
            if proc.path:
                components.append(proc.path)
        
        if event.source_id:
            components.append(event.source_id)
        
        combined = ":".join(components)
        return hashlib.sha256(combined.encode()).hexdigest()[:16]
    
    def _generate_event_id(self) -> str:
        """Generate unique event ID."""
        self._event_counter += 1
        return f"EVT-{int(time.time())}-{self._event_counter:06d}"
    
    def get_intruder(self, intruder_id: str) -> Optional[IntruderProfile]:
        """Get intruder profile by ID."""
        return self._intruders.get(intruder_id)
    
    def get_all_intruders(self) -> List[IntruderProfile]:
        """Get all detected intruder profiles."""
        return list(self._intruders.values())
    
    def get_events(
        self,
        threat_level: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 100
    ) -> List[IntrusionEvent]:
        """Get intrusion events with optional filtering."""
        events = self._events
        
        if threat_level:
            events = [e for e in events if e.threat_level == threat_level]
        
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        
        return events[-limit:]


# =============================================================================
# Intruder Response System
# =============================================================================

class IntruderResponse:
    """
    Response system for handling detected intruders.
    
    Provides capabilities to:
    - Freeze malicious processes
    - Block network connections
    - Log actions for analysis
    - Quarantine suspicious files
    """
    
    def __init__(self, detector: IntrusionDetector):
        self._detector = detector
        self._process_manager = ProcessManager()
        self._platform = get_platform()
        self._frozen_intruders: Set[str] = set()
        self._blocked_ips: Set[str] = set()
        self._response_log: List[Dict[str, Any]] = []
    
    def freeze_intruder(self, intruder_id: str) -> Dict[str, Any]:
        """
        Freeze all processes associated with an intruder.
        
        Args:
            intruder_id: ID of intruder to freeze
            
        Returns:
            Result of freeze operation
        """
        intruder = self._detector.get_intruder(intruder_id)
        
        if not intruder:
            return {
                "success": False,
                "error": f"Intruder {intruder_id} not found"
            }
        
        frozen_pids = []
        errors = []
        
        for pid in intruder.associated_pids:
            if self._process_manager.freeze_process(pid):
                frozen_pids.append(pid)
            else:
                errors.append(f"Failed to freeze PID {pid}")
        
        intruder.is_frozen = True
        self._frozen_intruders.add(intruder_id)
        
        self._log_response("freeze_intruder", {
            "intruder_id": intruder_id,
            "frozen_pids": frozen_pids,
            "errors": errors
        })
        
        return {
            "success": len(errors) == 0,
            "intruder_id": intruder_id,
            "frozen_pids": frozen_pids,
            "errors": errors
        }
    
    def unfreeze_intruder(self, intruder_id: str) -> Dict[str, Any]:
        """
        Unfreeze all processes associated with an intruder.
        
        Args:
            intruder_id: ID of intruder to unfreeze
            
        Returns:
            Result of unfreeze operation
        """
        intruder = self._detector.get_intruder(intruder_id)
        
        if not intruder:
            return {
                "success": False,
                "error": f"Intruder {intruder_id} not found"
            }
        
        unfrozen_pids = []
        errors = []
        
        for pid in intruder.associated_pids:
            if self._process_manager.unfreeze_process(pid):
                unfrozen_pids.append(pid)
            else:
                errors.append(f"Failed to unfreeze PID {pid}")
        
        intruder.is_frozen = False
        self._frozen_intruders.discard(intruder_id)
        
        self._log_response("unfreeze_intruder", {
            "intruder_id": intruder_id,
            "unfrozen_pids": unfrozen_pids,
            "errors": errors
        })
        
        return {
            "success": len(errors) == 0,
            "intruder_id": intruder_id,
            "unfrozen_pids": unfrozen_pids,
            "errors": errors
        }
    
    def terminate_intruder(self, intruder_id: str, force: bool = False) -> Dict[str, Any]:
        """
        Terminate all processes associated with an intruder.
        
        Args:
            intruder_id: ID of intruder to terminate
            force: If True, force termination
            
        Returns:
            Result of termination operation
        """
        intruder = self._detector.get_intruder(intruder_id)
        
        if not intruder:
            return {
                "success": False,
                "error": f"Intruder {intruder_id} not found"
            }
        
        terminated_pids = []
        errors = []
        
        for pid in intruder.associated_pids:
            if self._process_manager.terminate_process(pid, force=force):
                terminated_pids.append(pid)
            else:
                errors.append(f"Failed to terminate PID {pid}")
        
        self._log_response("terminate_intruder", {
            "intruder_id": intruder_id,
            "terminated_pids": terminated_pids,
            "force": force,
            "errors": errors
        })
        
        return {
            "success": len(errors) == 0,
            "intruder_id": intruder_id,
            "terminated_pids": terminated_pids,
            "errors": errors
        }
    
    def block_network(self, ip_address: str) -> Dict[str, Any]:
        """
        Block network connections to/from an IP address.
        
        Args:
            ip_address: IP address to block
            
        Returns:
            Result of block operation
        """
        if self._platform == PlatformType.WINDOWS:
            result = self._block_ip_windows(ip_address)
        elif self._platform == PlatformType.LINUX:
            result = self._block_ip_linux(ip_address)
        else:
            result = {
                "success": False,
                "error": "Platform not supported for network blocking"
            }
        
        if result.get("success"):
            self._blocked_ips.add(ip_address)
        
        self._log_response("block_network", {
            "ip_address": ip_address,
            "result": result
        })
        
        return result
    
    def _block_ip_windows(self, ip: str) -> Dict[str, Any]:
        """Block IP using Windows Firewall."""
        # Validate IP address format to prevent command injection
        import re
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        if not ip_pattern.match(ip):
            return {
                "success": False,
                "error": "Invalid IP address format"
            }
        
        # Validate each octet is in valid range
        try:
            octets = [int(x) for x in ip.split('.')]
            if not all(0 <= o <= 255 for o in octets):
                return {
                    "success": False,
                    "error": "Invalid IP address range"
                }
        except ValueError:
            return {
                "success": False,
                "error": "Invalid IP address format"
            }
        
        try:
            # Create firewall rule to block IP
            rule_name = f"Block_{ip.replace('.', '_')}"
            
            result = subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={rule_name}',
                'dir=out',
                'action=block',
                f'remoteip={ip}'
            ], capture_output=True, text=True, timeout=30)
            
            return {
                "success": result.returncode == 0,
                "ip_address": ip,
                "rule_name": rule_name,
                "output": result.stdout
            }
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def _block_ip_linux(self, ip: str) -> Dict[str, Any]:
        """Block IP using iptables."""
        # Validate IP address format to prevent command injection
        import re
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        if not ip_pattern.match(ip):
            return {
                "success": False,
                "error": "Invalid IP address format"
            }
        
        # Validate each octet is in valid range
        try:
            octets = [int(x) for x in ip.split('.')]
            if not all(0 <= o <= 255 for o in octets):
                return {
                    "success": False,
                    "error": "Invalid IP address range"
                }
        except ValueError:
            return {
                "success": False,
                "error": "Invalid IP address format"
            }
        
        try:
            result = subprocess.run([
                'iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'DROP'
            ], capture_output=True, text=True, timeout=30)
            
            return {
                "success": result.returncode == 0,
                "ip_address": ip,
                "output": result.stdout
            }
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def _log_response(self, action: str, details: Dict[str, Any]) -> None:
        """Log a response action."""
        self._response_log.append({
            "timestamp": time.time(),
            "action": action,
            "details": details
        })
    
    def get_response_log(self) -> List[Dict[str, Any]]:
        """Get the response action log."""
        return self._response_log.copy()


# =============================================================================
# Action Benchmark System
# =============================================================================

class ActionBenchmark:
    """
    Benchmark and analyze intruder actions for system strengthening.
    
    Records and analyzes:
    - Attack patterns
    - Exploitation techniques
    - Evasion methods
    - Target assets
    
    Generates actionable recommendations to strengthen system defenses.
    """
    
    def __init__(self, detector: IntrusionDetector):
        self._detector = detector
        self._attack_patterns: Dict[str, int] = defaultdict(int)
        self._targeted_assets: Dict[str, int] = defaultdict(int)
        self._techniques_used: Dict[str, List[str]] = defaultdict(list)
        self._timeline: List[Dict[str, Any]] = []
    
    def analyze_intruder(self, intruder_id: str) -> Dict[str, Any]:
        """
        Analyze an intruder's actions for benchmarking.
        
        Args:
            intruder_id: ID of intruder to analyze
            
        Returns:
            Analysis results with recommendations
        """
        intruder = self._detector.get_intruder(intruder_id)
        
        if not intruder:
            return {
                "success": False,
                "error": f"Intruder {intruder_id} not found"
            }
        
        # Analyze attack patterns
        for action in intruder.actions_logged:
            self._attack_patterns[action["type"]] += 1
            
            self._timeline.append({
                "intruder_id": intruder_id,
                "timestamp": action["timestamp"],
                "action_type": action["type"],
                "description": action["description"]
            })
        
        # Calculate dwell time
        dwell_time = intruder.last_activity - intruder.first_detected
        
        # Determine attack sophistication
        sophistication = self._calculate_sophistication(intruder)
        
        # Generate strengthening recommendations
        recommendations = self._generate_strengthening_recommendations(intruder)
        
        return {
            "success": True,
            "intruder_id": intruder_id,
            "analysis": {
                "dwell_time_seconds": dwell_time,
                "total_actions": intruder.total_actions,
                "threat_types": intruder.threat_types,
                "sophistication_level": sophistication,
                "associated_processes": len(intruder.associated_pids),
                "associated_ips": len(intruder.associated_ips)
            },
            "attack_timeline": [
                a for a in self._timeline if a["intruder_id"] == intruder_id
            ],
            "strengthening_recommendations": recommendations
        }
    
    def _calculate_sophistication(self, intruder: IntruderProfile) -> str:
        """Calculate attack sophistication level."""
        score = 0
        
        # Multiple threat types indicate sophisticated attack
        score += len(intruder.threat_types) * 2
        
        # Long dwell time may indicate stealth capabilities
        dwell_hours = (intruder.last_activity - intruder.first_detected) / 3600
        if dwell_hours > 24:
            score += 3
        elif dwell_hours > 1:
            score += 1
        
        # Multiple associated resources indicate lateral movement
        if len(intruder.associated_pids) > 3:
            score += 2
        if len(intruder.associated_ips) > 1:
            score += 2
        
        # Certain threat types indicate higher sophistication
        sophisticated_types = {
            ThreatType.PRIVILEGE_ESCALATION,
            ThreatType.PERSISTENCE_MECHANISM,
            ThreatType.DATA_EXFILTRATION
        }
        for threat_type in intruder.threat_types:
            if threat_type in sophisticated_types:
                score += 3
        
        if score >= 10:
            return "ADVANCED"
        elif score >= 5:
            return "INTERMEDIATE"
        else:
            return "BASIC"
    
    def _generate_strengthening_recommendations(
        self,
        intruder: IntruderProfile
    ) -> List[Dict[str, Any]]:
        """Generate system strengthening recommendations based on intruder analysis."""
        recommendations = []
        
        for threat_type in intruder.threat_types:
            if threat_type == ThreatType.SUSPICIOUS_PROCESS:
                recommendations.append({
                    "category": "process_control",
                    "priority": "HIGH",
                    "recommendation": "Implement application whitelisting",
                    "details": "Only allow approved executables to run. Use Windows AppLocker or Linux AppArmor.",
                    "implementation": [
                        "Create baseline of approved applications",
                        "Configure application control policies",
                        "Enable audit mode before enforcement",
                        "Monitor for policy violations"
                    ]
                })
            
            elif threat_type == ThreatType.NETWORK_INTRUSION:
                recommendations.append({
                    "category": "network_security",
                    "priority": "HIGH",
                    "recommendation": "Strengthen network segmentation and monitoring",
                    "details": "Implement network segmentation and deploy IDS/IPS systems.",
                    "implementation": [
                        "Segment network into security zones",
                        "Deploy network-based IDS/IPS",
                        "Implement egress filtering",
                        "Enable network flow logging"
                    ]
                })
            
            elif threat_type == ThreatType.PERSISTENCE_MECHANISM:
                recommendations.append({
                    "category": "persistence_prevention",
                    "priority": "CRITICAL",
                    "recommendation": "Monitor and protect persistence locations",
                    "details": "Monitor startup locations, scheduled tasks, and services for unauthorized changes.",
                    "implementation": [
                        "Implement file integrity monitoring",
                        "Audit startup registry keys",
                        "Review scheduled tasks regularly",
                        "Monitor service installations"
                    ]
                })
            
            elif threat_type == ThreatType.DATA_EXFILTRATION:
                recommendations.append({
                    "category": "data_protection",
                    "priority": "CRITICAL",
                    "recommendation": "Implement data loss prevention (DLP)",
                    "details": "Monitor and control data flows to prevent unauthorized data transfer.",
                    "implementation": [
                        "Classify sensitive data",
                        "Deploy DLP solution",
                        "Monitor large data transfers",
                        "Implement encryption for data at rest"
                    ]
                })
            
            elif threat_type == ThreatType.KEYLOGGER:
                recommendations.append({
                    "category": "input_protection",
                    "priority": "HIGH",
                    "recommendation": "Implement keyboard input protection",
                    "details": "Use secure input methods and monitor for API hooks.",
                    "implementation": [
                        "Use virtual keyboards for sensitive input",
                        "Monitor for suspicious API hooks",
                        "Implement anti-keylogger software",
                        "Use hardware security modules for credentials"
                    ]
                })
        
        # General recommendations
        recommendations.append({
            "category": "general",
            "priority": "MEDIUM",
            "recommendation": "Implement defense in depth",
            "details": "Layer security controls to prevent single points of failure.",
            "implementation": [
                "Enable endpoint detection and response (EDR)",
                "Implement least privilege access",
                "Enable audit logging",
                "Regular security assessments"
            ]
        })
        
        return recommendations
    
    def get_attack_statistics(self) -> Dict[str, Any]:
        """Get overall attack statistics."""
        return {
            "attack_pattern_frequency": dict(self._attack_patterns),
            "targeted_assets": dict(self._targeted_assets),
            "total_events_recorded": len(self._timeline),
            "unique_techniques": {
                k: len(set(v)) for k, v in self._techniques_used.items()
            }
        }
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive benchmark report."""
        all_intruders = self._detector.get_all_intruders()
        
        analyses = []
        for intruder in all_intruders:
            analysis = self.analyze_intruder(intruder.intruder_id)
            if analysis.get("success"):
                analyses.append(analysis)
        
        # Aggregate recommendations
        all_recommendations: Dict[str, Dict[str, Any]] = {}
        for analysis in analyses:
            for rec in analysis.get("strengthening_recommendations", []):
                key = f"{rec['category']}:{rec['recommendation']}"
                if key not in all_recommendations:
                    all_recommendations[key] = rec
        
        return {
            "report_time": datetime.now(timezone.utc).isoformat(),
            "total_intruders_analyzed": len(analyses),
            "attack_statistics": self.get_attack_statistics(),
            "intruder_analyses": analyses,
            "consolidated_recommendations": list(all_recommendations.values())
        }
