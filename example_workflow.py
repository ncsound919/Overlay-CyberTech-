#!/usr/bin/env python3
"""
Integration Example: Complete Security Workflow

This example demonstrates how all Overlay-CyberTech modules work together
to provide comprehensive security coverage:

1. System Status Check
2. Security Scan
3. Threat Response
4. System Cleanup
5. Integrity Verification
"""

import json
import tempfile
from pathlib import Path

# Import the unified platform
from main import OverlayCyberTech


def main():
    """Run complete security workflow."""
    print("=" * 80)
    print("Overlay-CyberTech: Complete Security Workflow Example")
    print("=" * 80)
    print()
    
    # Initialize the unified platform
    print("Step 1: Initializing platform...")
    platform = OverlayCyberTech()
    print("✓ Platform initialized")
    print()
    
    # Step 1: Check system status
    print("Step 2: Checking system status...")
    status = platform.get_system_status()
    print(f"  Platform: {status['platform']['os']}")
    print(f"  Hostname: {status['platform']['hostname']}")
    print(f"  CPUs: {status['platform']['cpu_count']}")
    print(f"  Memory: {status['platform']['memory_total_mb']:.2f} MB")
    print(f"  Admin: {status['platform']['is_admin']}")
    print()
    
    # Step 2: Run security scan
    print("Step 3: Running security scan...")
    scan_results = platform.run_security_scan(detailed=False)
    print(f"  Threats detected: {scan_results['intrusion_detection']['threats_detected']}")
    print(f"  Intruders found: {scan_results['intrusion_detection']['intruders_found']}")
    print(f"  Risk level: {scan_results['intrusion_detection']['risk_level']}")
    print()
    
    if scan_results['intrusion_detection']['threats_detected'] > 0:
        print("  Recommendations:")
        for rec in scan_results['intrusion_detection']['recommendations'][:3]:
            print(f"    • {rec}")
        print()
    
    # Step 3: Respond to threats (if any)
    if scan_results['intrusion_detection']['intruders_found'] > 0:
        print("Step 4: Responding to threats...")
        print("  (Would freeze intruders in production mode)")
        # Uncomment for actual response:
        # response = platform.respond_to_threats(auto_freeze=True)
        # print(f"  Intruders processed: {response['intruders_processed']}")
        print()
    
    # Step 4: Preview system cleanup
    print("Step 5: Previewing system cleanup...")
    cleanup_preview = platform.run_system_cleanup(dry_run=True)
    print(f"  Would free: {cleanup_preview['total_bytes_freed_mb']:.2f} MB")
    print(f"  Files that would be deleted: {cleanup_preview['total_files_deleted']}")
    print()
    
    # Show cleanup breakdown
    print("  Breakdown by category:")
    for category in cleanup_preview['results_by_category'][:5]:
        if category['bytes_freed_mb'] > 0:
            print(f"    • {category['category']}: {category['bytes_freed_mb']:.2f} MB")
    print()
    
    # Step 5: Analyze disk usage
    print("Step 6: Analyzing disk usage...")
    temp_dir = Path(tempfile.gettempdir())
    disk_usage = platform.analyze_disk_usage(str(temp_dir))
    print(f"  Total: {disk_usage['total_gb']:.2f} GB")
    print(f"  Used: {disk_usage['used_gb']:.2f} GB ({disk_usage['percent_used']:.1f}%)")
    print(f"  Free: {disk_usage['free_gb']:.2f} GB")
    print()
    
    # Step 6: Verify system integrity
    print("Step 7: Verifying system integrity...")
    verification = platform.verify_system_integrity()
    print(f"  SBOM components: {verification['sbom']['components']}")
    print(f"  Vulnerabilities: {verification['sbom']['vulnerabilities']}")
    print(f"  Policy violations: {verification['sbom']['policy_violations']}")
    print(f"  Integrity verified: {verification['integrity']['verified']}")
    print()
    
    # Step 7: Generate comprehensive report
    print("Step 8: Generating security report...")
    report = platform.generate_security_report(output_file='security-report.json')
    print("  ✓ Report saved to security-report.json")
    print()
    
    # Summary
    print("=" * 80)
    print("Workflow Summary:")
    print("=" * 80)
    print(f"✓ System Status: {status['platform']['os']} on {status['platform']['hostname']}")
    print(f"✓ Security Scan: {scan_results['intrusion_detection']['threats_detected']} threats, "
          f"{scan_results['intrusion_detection']['intruders_found']} intruders")
    print(f"✓ Cleanup Preview: {cleanup_preview['total_bytes_freed_mb']:.2f} MB can be freed")
    print(f"✓ Disk Usage: {disk_usage['percent_used']:.1f}% used")
    print(f"✓ Integrity: {verification['sbom']['components']} components verified")
    print(f"✓ Report: Generated and saved")
    print()
    print("All security checks completed successfully!")
    print("=" * 80)


if __name__ == '__main__':
    main()
