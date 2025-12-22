"""
Tests for Platform Support, System Cleaner, and Intrusion Detection modules.

Tests the new Windows-compatible and cross-platform features:
- Platform detection and support
- Process management
- System cleaning (CCleaner-like capabilities)
- Intrusion detection and response
- Action benchmarking for system strengthening
"""

import os
import pytest
import tempfile
import time

# Import new modules
from core.platform_support import (
    get_platform, is_windows, is_admin, PlatformType,
    ProcessManager, ProcessInfo, NetworkMonitor, NetworkConnection,
    ServiceManager, get_system_info, SystemInfo
)
from core.system_cleaner import (
    SystemCleaner, CleanupConfig, CleanupResult,
    RegistryCleaner
)
from detection.intrusion_detector import (
    IntrusionDetector, IntrusionEvent, IntruderProfile,
    IntruderResponse, ActionBenchmark,
    ThreatLevel, ThreatType, BehaviorSignatures
)


# =============================================================================
# Platform Support Tests
# =============================================================================

class TestPlatformSupport:
    """Tests for platform support module."""
    
    def test_get_platform(self):
        """Test platform detection."""
        platform = get_platform()
        assert platform in [
            PlatformType.WINDOWS,
            PlatformType.LINUX,
            PlatformType.MACOS,
            PlatformType.UNKNOWN
        ]
    
    def test_is_windows(self):
        """Test Windows detection."""
        result = is_windows()
        assert isinstance(result, bool)
        
        # Verify consistency
        if get_platform() == PlatformType.WINDOWS:
            assert result is True
        else:
            assert result is False
    
    def test_is_admin(self):
        """Test admin/root privilege detection."""
        result = is_admin()
        assert isinstance(result, bool)
    
    def test_get_system_info(self):
        """Test system information gathering."""
        info = get_system_info()
        
        assert isinstance(info, SystemInfo)
        assert info.platform is not None
        assert info.hostname is not None
        assert info.cpu_count >= 1
    
    def test_process_manager_list_processes(self):
        """Test process listing."""
        pm = ProcessManager()
        processes = pm.list_processes()
        
        assert isinstance(processes, list)
        # Should have at least one process running
        assert len(processes) > 0
        
        # Check first process structure
        if processes:
            proc = processes[0]
            assert isinstance(proc, ProcessInfo)
            assert proc.pid > 0
            assert proc.name is not None
    
    def test_process_manager_get_process_info(self):
        """Test getting specific process info."""
        pm = ProcessManager()
        
        # Get current process info
        current_pid = os.getpid()
        info = pm.get_process_info(current_pid)
        
        # May or may not find it depending on platform
        if info:
            assert info.pid == current_pid
    
    def test_process_manager_frozen_list(self):
        """Test frozen process tracking."""
        pm = ProcessManager()
        
        # Initially empty
        assert len(pm.get_frozen_processes()) == 0
    
    def test_network_monitor_list_connections(self):
        """Test network connection listing."""
        nm = NetworkMonitor()
        connections = nm.list_connections()
        
        assert isinstance(connections, list)
        # Connections may be empty in test environment
        for conn in connections:
            assert isinstance(conn, NetworkConnection)
    
    def test_network_monitor_suspicious_connections(self):
        """Test suspicious connection detection."""
        nm = NetworkMonitor()
        suspicious = nm.get_suspicious_connections()
        
        assert isinstance(suspicious, list)
    
    def test_service_manager_list_services(self):
        """Test service listing."""
        sm = ServiceManager()
        services = sm.list_services()
        
        assert isinstance(services, list)
        # Services should be found on most systems
        # May be empty in restricted test environments


# =============================================================================
# System Cleaner Tests
# =============================================================================

class TestSystemCleaner:
    """Tests for system cleaner module."""
    
    def test_cleanup_config_defaults(self):
        """Test cleanup configuration defaults."""
        config = CleanupConfig()
        
        assert config.clean_temp_files is True
        assert config.clean_browser_cache is True
        assert config.clean_browser_history is False  # More invasive, off by default
        assert config.dry_run is False
        assert config.secure_delete is False
    
    def test_system_cleaner_initialization(self):
        """Test system cleaner initialization."""
        cleaner = SystemCleaner()
        
        assert cleaner.config is not None
        assert cleaner._platform in [
            PlatformType.WINDOWS,
            PlatformType.LINUX,
            PlatformType.MACOS,
            PlatformType.UNKNOWN
        ]
    
    def test_cleanup_dry_run(self):
        """Test cleanup in dry run mode."""
        config = CleanupConfig(
            clean_temp_files=True,
            clean_browser_cache=False,
            clean_thumbnails=False,
            clean_recycle_bin=False,
            dry_run=True
        )
        cleaner = SystemCleaner(config)
        
        result = cleaner.run_full_cleanup()
        
        assert result["dry_run"] is True
        assert isinstance(result["total_bytes_freed"], int)
        assert isinstance(result["total_files_deleted"], int)
    
    def test_cleanup_temp_files_dry_run(self):
        """Test temp files cleanup in dry run mode."""
        config = CleanupConfig(dry_run=True)
        cleaner = SystemCleaner(config)
        
        result = cleaner.clean_temp_files()
        
        assert isinstance(result, CleanupResult)
        assert result.category == "temp_files"
        assert isinstance(result.files_deleted, int)
        assert isinstance(result.bytes_freed, int)
    
    def test_cleanup_preview(self):
        """Test cleanup preview functionality."""
        cleaner = SystemCleaner()
        
        preview = cleaner.get_cleanup_preview()
        
        assert preview["is_preview"] is True
        assert isinstance(preview["total_bytes_freed"], int)
    
    def test_disk_usage_analysis(self):
        """Test disk usage analysis."""
        cleaner = SystemCleaner()
        
        # Analyze a known directory
        temp_dir = tempfile.gettempdir()
        analysis = cleaner.analyze_disk_usage(temp_dir)
        
        assert "total_gb" in analysis
        assert "used_gb" in analysis
        assert "free_gb" in analysis
        assert "percent_used" in analysis
    
    def test_cleanup_with_temp_file(self):
        """Test actual cleanup with a temp file."""
        # Create temp file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".tmp") as f:
            f.write(b"test data for cleanup")
            temp_file = f.name
        
        try:
            # Create cleaner with config targeting temp files
            config = CleanupConfig(
                clean_temp_files=True,
                clean_browser_cache=False,
                clean_thumbnails=False,
                clean_recycle_bin=False,
                dry_run=False
            )
            cleaner = SystemCleaner(config)
            
            # File should exist
            assert os.path.exists(temp_file)
            
            # Run cleanup
            result = cleaner.run_full_cleanup()
            
            assert result["success"] is True or len(result["results_by_category"]) > 0
            
        finally:
            # Clean up if file still exists
            if os.path.exists(temp_file):
                os.unlink(temp_file)
    
    def test_cleanup_result_structure(self):
        """Test cleanup result structure."""
        result = CleanupResult(category="test")
        
        assert result.category == "test"
        assert result.files_deleted == 0
        assert result.bytes_freed == 0
        assert isinstance(result.errors, list)
        assert isinstance(result.items_cleaned, list)
        assert result.success is True
    
    def test_registry_cleaner_availability(self):
        """Test registry cleaner availability check."""
        cleaner = RegistryCleaner()
        
        # Should be available on Windows only
        if get_platform() == PlatformType.WINDOWS:
            assert cleaner.is_available() is True
        else:
            assert cleaner.is_available() is False
    
    def test_registry_cleaner_scan_non_windows(self):
        """Test registry scan on non-Windows platforms."""
        cleaner = RegistryCleaner()
        
        if not cleaner.is_available():
            issues = cleaner.scan_registry()
            assert issues == []


# =============================================================================
# Intrusion Detector Tests
# =============================================================================

class TestIntrusionDetector:
    """Tests for intrusion detection module."""
    
    def test_behavior_signatures(self):
        """Test behavior signatures are defined."""
        assert len(BehaviorSignatures.SUSPICIOUS_PROCESS_NAMES) > 0
        assert len(BehaviorSignatures.SUSPICIOUS_PROCESS_CHAINS) > 0
        assert len(BehaviorSignatures.SUSPICIOUS_PORTS) > 0
    
    def test_threat_level_values(self):
        """Test threat level constants."""
        assert ThreatLevel.CRITICAL == "CRITICAL"
        assert ThreatLevel.HIGH == "HIGH"
        assert ThreatLevel.MEDIUM == "MEDIUM"
        assert ThreatLevel.LOW == "LOW"
        assert ThreatLevel.INFO == "INFO"
    
    def test_threat_type_values(self):
        """Test threat type constants."""
        assert ThreatType.KEYLOGGER == "keylogger"
        assert ThreatType.SPYWARE == "spyware"
        assert ThreatType.RAT == "remote_access_trojan"
        assert ThreatType.DATA_EXFILTRATION == "data_exfiltration"
    
    def test_intrusion_detector_initialization(self):
        """Test intrusion detector initialization."""
        detector = IntrusionDetector()
        
        assert detector._platform in [
            PlatformType.WINDOWS,
            PlatformType.LINUX,
            PlatformType.MACOS,
            PlatformType.UNKNOWN
        ]
        assert len(detector._intruders) == 0
        assert len(detector._events) == 0
    
    def test_intrusion_detector_scan_system(self):
        """Test system scan functionality."""
        detector = IntrusionDetector()
        
        result = detector.scan_system()
        
        assert "scan_time" in result
        assert "duration_seconds" in result
        assert "threats_detected" in result
        assert isinstance(result["threats"], list)
        assert "risk_assessment" in result
        assert "recommendations" in result
    
    def test_intrusion_detector_get_events(self):
        """Test event retrieval."""
        detector = IntrusionDetector()
        
        events = detector.get_events()
        assert isinstance(events, list)
        
        # Test with filters
        events_filtered = detector.get_events(
            threat_level=ThreatLevel.HIGH,
            limit=10
        )
        assert isinstance(events_filtered, list)
    
    def test_intrusion_detector_get_intruders(self):
        """Test intruder retrieval."""
        detector = IntrusionDetector()
        
        intruders = detector.get_all_intruders()
        assert isinstance(intruders, list)
    
    def test_intrusion_event_structure(self):
        """Test intrusion event data structure."""
        event = IntrusionEvent(
            event_id="EVT-001",
            timestamp=time.time(),
            event_type=ThreatType.SUSPICIOUS_PROCESS,
            threat_level=ThreatLevel.HIGH,
            source="process",
            source_id="12345",
            description="Test event"
        )
        
        assert event.event_id == "EVT-001"
        assert event.event_type == ThreatType.SUSPICIOUS_PROCESS
        assert event.threat_level == ThreatLevel.HIGH
        assert event.source == "process"
        assert event.source_id == "12345"
    
    def test_intruder_profile_structure(self):
        """Test intruder profile data structure."""
        profile = IntruderProfile(
            intruder_id="INT-001",
            first_detected=time.time(),
            last_activity=time.time(),
            threat_level=ThreatLevel.HIGH,
            threat_types=[ThreatType.SUSPICIOUS_PROCESS],
            associated_pids=[1234, 5678]
        )
        
        assert profile.intruder_id == "INT-001"
        assert profile.threat_level == ThreatLevel.HIGH
        assert len(profile.threat_types) == 1
        assert len(profile.associated_pids) == 2
        assert profile.is_frozen is False


# =============================================================================
# Intruder Response Tests
# =============================================================================

class TestIntruderResponse:
    """Tests for intruder response module."""
    
    def test_intruder_response_initialization(self):
        """Test intruder response initialization."""
        detector = IntrusionDetector()
        response = IntruderResponse(detector)
        
        assert response._detector == detector
        assert len(response._frozen_intruders) == 0
        assert len(response._blocked_ips) == 0
    
    def test_freeze_nonexistent_intruder(self):
        """Test freezing non-existent intruder."""
        detector = IntrusionDetector()
        response = IntruderResponse(detector)
        
        result = response.freeze_intruder("nonexistent")
        
        assert result["success"] is False
        assert "not found" in result["error"]
    
    def test_unfreeze_nonexistent_intruder(self):
        """Test unfreezing non-existent intruder."""
        detector = IntrusionDetector()
        response = IntruderResponse(detector)
        
        result = response.unfreeze_intruder("nonexistent")
        
        assert result["success"] is False
        assert "not found" in result["error"]
    
    def test_terminate_nonexistent_intruder(self):
        """Test terminating non-existent intruder."""
        detector = IntrusionDetector()
        response = IntruderResponse(detector)
        
        result = response.terminate_intruder("nonexistent")
        
        assert result["success"] is False
        assert "not found" in result["error"]
    
    def test_response_log(self):
        """Test response action logging."""
        detector = IntrusionDetector()
        response = IntruderResponse(detector)
        
        # Attempt an action (will fail but should log)
        response.freeze_intruder("test-id")
        
        log = response.get_response_log()
        assert isinstance(log, list)
        # Log should be empty since intruder doesn't exist
        assert len(log) == 0


# =============================================================================
# Action Benchmark Tests
# =============================================================================

class TestActionBenchmark:
    """Tests for action benchmark module."""
    
    def test_action_benchmark_initialization(self):
        """Test action benchmark initialization."""
        detector = IntrusionDetector()
        benchmark = ActionBenchmark(detector)
        
        assert benchmark._detector == detector
        assert len(benchmark._attack_patterns) == 0
        assert len(benchmark._timeline) == 0
    
    def test_analyze_nonexistent_intruder(self):
        """Test analyzing non-existent intruder."""
        detector = IntrusionDetector()
        benchmark = ActionBenchmark(detector)
        
        result = benchmark.analyze_intruder("nonexistent")
        
        assert result["success"] is False
        assert "not found" in result["error"]
    
    def test_get_attack_statistics(self):
        """Test attack statistics retrieval."""
        detector = IntrusionDetector()
        benchmark = ActionBenchmark(detector)
        
        stats = benchmark.get_attack_statistics()
        
        assert "attack_pattern_frequency" in stats
        assert "targeted_assets" in stats
        assert "total_events_recorded" in stats
    
    def test_generate_report(self):
        """Test report generation."""
        detector = IntrusionDetector()
        benchmark = ActionBenchmark(detector)
        
        report = benchmark.generate_report()
        
        assert "report_time" in report
        assert "total_intruders_analyzed" in report
        assert "attack_statistics" in report
        assert "consolidated_recommendations" in report


# =============================================================================
# Integration Tests
# =============================================================================

class TestNewModulesIntegration:
    """Integration tests for new modules."""
    
    def test_full_security_workflow(self):
        """Test complete security workflow with new modules."""
        # Step 1: Scan system for intrusions
        detector = IntrusionDetector()
        scan_result = detector.scan_system()
        
        assert scan_result is not None
        assert "threats_detected" in scan_result
        
        # Step 2: Prepare response system
        response = IntruderResponse(detector)
        assert response is not None
        
        # Step 3: Prepare benchmark system
        benchmark = ActionBenchmark(detector)
        
        # Step 4: Generate report
        report = benchmark.generate_report()
        
        assert report is not None
        assert "consolidated_recommendations" in report
    
    def test_cleaner_and_platform_integration(self):
        """Test cleaner with platform support."""
        platform = get_platform()
        info = get_system_info()
        assert isinstance(info, SystemInfo)
        
        # Create cleaner
        config = CleanupConfig(dry_run=True)
        cleaner = SystemCleaner(config)
        
        # Preview what would be cleaned
        preview = cleaner.get_cleanup_preview()
        
        assert preview is not None
        assert preview["dry_run"] is True
        
        # Analyze disk usage
        if platform in [PlatformType.WINDOWS, PlatformType.LINUX, PlatformType.MACOS]:
            home = os.path.expanduser("~")
            if os.path.exists(home):
                usage = cleaner.analyze_disk_usage(home)
                assert usage["total_gb"] > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
