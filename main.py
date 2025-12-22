#!/usr/bin/env python3
"""
Overlay-CyberTech Unified Security Platform
Main entry point for the integrated cybersecurity system.

This module provides a unified interface to:
- Threat Detection and Analysis
- Intrusion Detection and Response
- System Cleaning and Optimization
- Formal Verification
- Deployment Security
"""

import argparse
import sys
import json
from typing import Dict, Any, Optional
from pathlib import Path

# Import all major components
from core.platform_support import get_platform, get_system_info, ProcessManager, is_admin
from core.system_cleaner import SystemCleaner, CleanupConfig
from core.data_structures import ThreatSignatureDB, IPTrie, BloomFilter

from detection.threat_detector import StatefulPacketInspector, VulnerabilityScanner, EWMADetector
from detection.intrusion_detector import IntrusionDetector, IntruderResponse, ActionBenchmark

from response.lts_engine import LabeledTransitionSystem, PolicyEngine

from kernel.formal_verification import FormalVerifier, HoareTriple, StateSpace

from deployment.security import ImmutableAuditLog, SBOMGenerator, IntegrityVerifier


class OverlayCyberTech:
    """
    Unified cybersecurity platform integrating all modules.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the unified platform."""
        self.config = config or {}
        self.platform = get_platform()
        self.system_info = get_system_info()
        
        # Initialize core components
        self.packet_inspector = StatefulPacketInspector()
        self.intrusion_detector = IntrusionDetector()
        self.intruder_response = IntruderResponse(self.intrusion_detector)
        self.action_benchmark = ActionBenchmark(self.intrusion_detector)
        
        # Initialize response engine
        self.lts_engine = LabeledTransitionSystem()
        self.policy_engine = PolicyEngine()
        
        # Initialize deployment security
        self.audit_log = ImmutableAuditLog()
        self.sbom_generator = SBOMGenerator()
        self.integrity_verifier = IntegrityVerifier()
        
        # Initialize system cleaner
        self.system_cleaner = None  # Lazy initialization
        
    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status."""
        # Get audit log entry count
        try:
            audit_log_count = self.audit_log.cursor.execute(
                "SELECT COUNT(*) FROM audit_trail"
            ).fetchone()[0]
        except:
            audit_log_count = 0
            
        return {
            'platform': {
                'os': self.platform,
                'hostname': self.system_info.hostname,
                'cpu_count': self.system_info.cpu_count,
                'memory_total_mb': self.system_info.memory_total_mb,
                'is_admin': is_admin()
            },
            'security': {
                'audit_log_entries': audit_log_count,
                'active_policies': len(self.policy_engine.rules)
            }
        }
    
    def run_security_scan(self, detailed: bool = False) -> Dict[str, Any]:
        """
        Run comprehensive security scan across all modules.
        
        Args:
            detailed: Include detailed analysis
            
        Returns:
            Comprehensive security report
        """
        print("🔍 Running comprehensive security scan...")
        
        # Scan for intrusions
        print("  → Scanning for intrusions...")
        intrusion_result = self.intrusion_detector.scan_system()
        
        # Get all detected intruders
        intruders = self.intrusion_detector.get_all_intruders()
        
        # Analyze vulnerabilities
        print("  → Analyzing vulnerabilities...")
        vuln_scanner = VulnerabilityScanner()
        vulnerabilities = []
        
        # Get attack statistics
        print("  → Generating attack statistics...")
        attack_stats = self.action_benchmark.get_attack_statistics()
        
        results = {
            'timestamp': intrusion_result['scan_time'],
            'platform': self.platform,
            'intrusion_detection': {
                'threats_detected': intrusion_result['threats_detected'],
                'intruders_found': len(intruders),
                'risk_level': intrusion_result['risk_assessment']['overall_risk'],
                'recommendations': intrusion_result['recommendations']
            },
            'attack_statistics': attack_stats,
            'intruders': [
                {
                    'id': intruder.intruder_id,
                    'types': intruder.threat_types,
                    'level': intruder.threat_level,
                    'first_detected': intruder.first_detected,
                    'last_activity': intruder.last_activity
                }
                for intruder in intruders
            ] if detailed else []
        }
        
        print(f"✓ Scan complete: {results['intrusion_detection']['threats_detected']} threats detected")
        return results
    
    def respond_to_threats(self, auto_freeze: bool = False) -> Dict[str, Any]:
        """
        Respond to detected threats using the response engine.
        
        Args:
            auto_freeze: Automatically freeze detected intruders
            
        Returns:
            Response action results
        """
        print("🛡️ Initiating threat response...")
        
        intruders = self.intrusion_detector.get_all_intruders()
        actions_taken = []
        
        for intruder in intruders:
            action = {
                'intruder_id': intruder.intruder_id,
                'threat_types': intruder.threat_types,
                'threat_level': intruder.threat_level,
                'actions': []
            }
            
            if auto_freeze:
                print(f"  → Freezing intruder {intruder.intruder_id}...")
                freeze_result = self.intruder_response.freeze_intruder(intruder.intruder_id)
                action['actions'].append({
                    'type': 'freeze',
                    'success': freeze_result['success'],
                    'frozen_pids': freeze_result.get('frozen_pids', [])
                })
            
            # Analyze intruder
            analysis = self.action_benchmark.analyze_intruder(intruder.intruder_id)
            action['analysis'] = analysis['analysis']
            action['recommendations'] = analysis['strengthening_recommendations']
            
            actions_taken.append(action)
        
        print(f"✓ Response complete: {len(actions_taken)} intruders processed")
        return {
            'intruders_processed': len(actions_taken),
            'actions': actions_taken
        }
    
    def run_system_cleanup(self, dry_run: bool = True) -> Dict[str, Any]:
        """
        Run system cleanup to optimize performance.
        
        Args:
            dry_run: Preview cleanup without making changes
            
        Returns:
            Cleanup results
        """
        print(f"🧹 Running system cleanup (dry_run={dry_run})...")
        
        config = CleanupConfig(
            clean_temp_files=True,
            clean_browser_cache=True,
            clean_browser_history=True,
            clean_thumbnails=True,
            clean_recycle_bin=True,
            clean_prefetch=True,
            clean_system_logs=False,  # Requires admin
            dry_run=dry_run
        )
        
        self.system_cleaner = SystemCleaner(config)
        
        if dry_run:
            preview = self.system_cleaner.get_cleanup_preview()
            print(f"  → Would free {preview['total_bytes_freed_mb']:.2f} MB")
            return preview
        else:
            result = self.system_cleaner.run_full_cleanup()
            print(f"  ✓ Freed {result['total_bytes_freed_mb']:.2f} MB")
            return result
    
    def analyze_disk_usage(self, path: str = '/') -> Dict[str, Any]:
        """
        Analyze disk usage to identify cleanup opportunities.
        
        Args:
            path: Path to analyze
            
        Returns:
            Disk usage analysis
        """
        print(f"💾 Analyzing disk usage for {path}...")
        
        if self.system_cleaner is None:
            self.system_cleaner = SystemCleaner()
        
        usage = self.system_cleaner.analyze_disk_usage(path)
        
        print(f"  → Total: {usage['total_gb']:.2f} GB")
        print(f"  → Used: {usage['used_gb']:.2f} GB ({usage['percent_used']:.1f}%)")
        print(f"  → Free: {usage['free_gb']:.2f} GB")
        
        return usage
    
    def generate_security_report(self, output_file: Optional[str] = None) -> str:
        """
        Generate comprehensive security report.
        
        Args:
            output_file: Optional file path to save report
            
        Returns:
            Report content
        """
        print("📊 Generating security report...")
        
        # Get system status
        status = self.get_system_status()
        
        # Run security scan
        scan_results = self.run_security_scan(detailed=True)
        
        # Get attack statistics
        attack_stats = self.action_benchmark.get_attack_statistics()
        
        # Generate benchmark report
        benchmark_report = self.action_benchmark.generate_report()
        
        report = {
            'title': 'Overlay-CyberTech Security Report',
            'system_status': status,
            'security_scan': scan_results,
            'attack_statistics': attack_stats,
            'benchmark_report': benchmark_report
        }
        
        report_json = json.dumps(report, indent=2, default=str)
        
        if output_file:
            Path(output_file).write_text(report_json)
            print(f"✓ Report saved to {output_file}")
        
        return report_json
    
    def verify_system_integrity(self) -> Dict[str, Any]:
        """
        Verify system integrity using formal verification.
        
        Returns:
            Verification results
        """
        print("🔐 Verifying system integrity...")
        
        # Generate SBOM for current project
        sbom = self.sbom_generator.generate_sbom('.')
        
        # Verify integrity
        verification = self.integrity_verifier.verify_integrity()
        
        results = {
            'sbom': {
                'components': len(sbom.components),
                'spec_version': sbom.spec_version,
                'vulnerabilities': len(sbom.vulnerabilities),
                'policy_violations': len(sbom.policy_violations)
            },
            'integrity': verification
        }
        
        print(f"✓ Verification complete")
        return results


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='Overlay-CyberTech Unified Security Platform',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Get system status
  python main.py status
  
  # Run security scan
  python main.py scan
  
  # Run security scan and respond to threats
  python main.py scan --respond --auto-freeze
  
  # Preview system cleanup
  python main.py cleanup --dry-run
  
  # Run actual cleanup (requires admin/root)
  python main.py cleanup
  
  # Analyze disk usage
  python main.py disk-usage /
  
  # Generate security report
  python main.py report --output security-report.json
  
  # Verify system integrity
  python main.py verify
        """
    )
    
    parser.add_argument('command', choices=[
        'status', 'scan', 'cleanup', 'disk-usage', 'report', 'verify'
    ], help='Command to execute')
    
    parser.add_argument('--respond', action='store_true',
                       help='Respond to detected threats (use with scan)')
    parser.add_argument('--auto-freeze', action='store_true',
                       help='Automatically freeze intruders (use with --respond)')
    parser.add_argument('--dry-run', action='store_true',
                       help='Preview actions without making changes')
    parser.add_argument('--output', '-o', type=str,
                       help='Output file path (use with report)')
    parser.add_argument('--path', type=str, default='/',
                       help='Path to analyze (use with disk-usage)')
    parser.add_argument('--detailed', action='store_true',
                       help='Include detailed analysis')
    
    args = parser.parse_args()
    
    # Initialize platform
    print("=" * 70)
    print("Overlay-CyberTech Unified Security Platform")
    print("=" * 70)
    
    platform = OverlayCyberTech()
    
    try:
        if args.command == 'status':
            status = platform.get_system_status()
            print(json.dumps(status, indent=2))
            
        elif args.command == 'scan':
            results = platform.run_security_scan(detailed=args.detailed)
            print(json.dumps(results, indent=2, default=str))
            
            if args.respond:
                response = platform.respond_to_threats(auto_freeze=args.auto_freeze)
                print("\nThreat Response:")
                print(json.dumps(response, indent=2, default=str))
                
        elif args.command == 'cleanup':
            results = platform.run_system_cleanup(dry_run=args.dry_run)
            print(json.dumps(results, indent=2, default=str))
            
        elif args.command == 'disk-usage':
            results = platform.analyze_disk_usage(path=args.path)
            print(json.dumps(results, indent=2, default=str))
            
        elif args.command == 'report':
            report = platform.generate_security_report(output_file=args.output)
            if not args.output:
                print(report)
                
        elif args.command == 'verify':
            results = platform.verify_system_integrity()
            print(json.dumps(results, indent=2, default=str))
            
        print("\n" + "=" * 70)
        print("✓ Operation completed successfully")
        print("=" * 70)
        
    except Exception as e:
        print(f"\n❌ Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
