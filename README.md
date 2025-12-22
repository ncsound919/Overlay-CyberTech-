# Overlay-CyberTech-

Advanced Cyber Security Software with Windows Support

## Overview

Overlay-CyberTech is a comprehensive, deterministic cybersecurity framework designed for cross-platform operation (Windows, Linux, macOS). Similar to solutions like Avast, it provides real-time protection against threats while incorporating advanced system optimization capabilities comparable to CCleaner.

## Features

### Core Security Architecture
- **Formal Verification** - Mathematical proofs for software correctness using Hoare Logic
- **High-Performance Data Structures** - O(1) threat signature lookup with Hash Maps, Tries, and Bloom Filters
- **Deterministic Threat Detection** - Stateful packet inspection, EWMA-based anomaly detection
- **Logic-Based Response Engine** - Labeled Transition Systems for pre-calculated security responses
- **Hardened Deployment** - Immutable audit logs, SBOM generation, integrity verification

### Windows Platform Support
- Cross-platform detection (Windows, Linux, macOS)
- Process management and monitoring
- Windows Registry access and monitoring
- Windows Service management
- Network connection monitoring
- Administrator privilege detection

### System Cleaning (CCleaner-like Capabilities)
- **Temporary Files Cleanup** - System and user temp directories
- **Browser Cache Cleaning** - Chrome, Firefox, Edge, Opera support
- **Browser History Cleaning** - SQLite database clearing
- **Thumbnail Cache Cleanup** - Windows Explorer, GNOME, macOS thumbnails
- **Recycle Bin/Trash Emptying** - Cross-platform trash management
- **Windows Prefetch Cleaning** - Prefetch file management
- **System Log Cleanup** - Log file truncation and removal
- **Registry Cleaning** (Windows) - Invalid entries, orphaned startup entries
- **Disk Usage Analysis** - Large file/directory identification
- **Secure Deletion** - Multi-pass overwriting for sensitive data

### Intrusion Detection and Response
- **Process Behavior Analysis** - Suspicious process detection using behavioral signatures
- **Network Activity Monitoring** - Backdoor port detection, beaconing detection
- **Persistence Mechanism Scanning** - Scheduled tasks, cron jobs, startup entries
- **Intruder Profiling** - Threat classification and tracking
- **Freeze Capability** - Suspend malicious processes for analysis
- **Terminate Capability** - Safe process termination
- **Network Blocking** - IP blocking via firewall rules
- **Action Benchmarking** - Log and analyze intruder actions for system strengthening

## Installation

```bash
# Clone the repository
git clone https://github.com/ncsound919/Overlay-CyberTech-.git
cd Overlay-CyberTech-

# Install dependencies
pip install -r requirements.txt
```

## Usage

### System Scan for Intrusions

```python
from detection.intrusion_detector import IntrusionDetector, IntruderResponse

# Initialize detector
detector = IntrusionDetector()

# Scan system for threats
result = detector.scan_system()
print(f"Threats detected: {result['threats_detected']}")
print(f"Risk level: {result['risk_assessment']['overall_risk']}")

# View recommendations
for rec in result['recommendations']:
    print(f"- {rec}")
```

### Freeze and Analyze Intruders

```python
from detection.intrusion_detector import IntrusionDetector, IntruderResponse, ActionBenchmark

detector = IntrusionDetector()
response = IntruderResponse(detector)
benchmark = ActionBenchmark(detector)

# Scan and detect
scan_result = detector.scan_system()

# For each detected intruder
for intruder in detector.get_all_intruders():
    # Freeze the intruder
    freeze_result = response.freeze_intruder(intruder.intruder_id)
    print(f"Frozen PIDs: {freeze_result['frozen_pids']}")
    
    # Analyze and benchmark
    analysis = benchmark.analyze_intruder(intruder.intruder_id)
    print(f"Sophistication: {analysis['analysis']['sophistication_level']}")
    
    # Get strengthening recommendations
    for rec in analysis['strengthening_recommendations']:
        print(f"[{rec['priority']}] {rec['recommendation']}")
```

### System Cleaning

```python
from core.system_cleaner import SystemCleaner, CleanupConfig

# Configure cleanup
config = CleanupConfig(
    clean_temp_files=True,
    clean_browser_cache=True,
    clean_thumbnails=True,
    clean_recycle_bin=True,
    dry_run=True  # Set to False for actual cleanup
)

cleaner = SystemCleaner(config)

# Preview what would be cleaned
preview = cleaner.get_cleanup_preview()
print(f"Would free: {preview['total_bytes_freed_mb']} MB")

# Run actual cleanup (set dry_run=False first)
# result = cleaner.run_full_cleanup()
```

### Disk Usage Analysis

```python
from core.system_cleaner import SystemCleaner

cleaner = SystemCleaner()

# Analyze disk usage
usage = cleaner.analyze_disk_usage('/')
print(f"Disk usage: {usage['percent_used']}%")
print(f"Free space: {usage['free_gb']} GB")

# Show largest files
for file_info in usage['largest_files'][:10]:
    print(f"  {file_info['path']}: {file_info['size_mb']} MB")
```

### Platform Information

```python
from core.platform_support import get_platform, get_system_info, ProcessManager

# Get platform
platform = get_platform()
print(f"Running on: {platform}")

# Get system info
info = get_system_info()
print(f"Hostname: {info.hostname}")
print(f"CPUs: {info.cpu_count}")
print(f"Memory: {info.memory_total_mb} MB")

# List processes
pm = ProcessManager()
processes = pm.list_processes()
print(f"Running processes: {len(processes)}")
```

## Architecture

```
Overlay-CyberTech-/
├── core/
│   ├── data_structures.py     # High-performance data structures
│   ├── platform_support.py    # Cross-platform support (Windows/Linux/macOS)
│   └── system_cleaner.py      # CCleaner-like capabilities
├── detection/
│   ├── threat_detector.py     # Threat detection engine
│   └── intrusion_detector.py  # Intrusion detection and response
├── response/
│   └── lts_engine.py          # Logic-based response engine
├── kernel/
│   └── formal_verification.py # Formal verification
├── deployment/
│   └── security.py            # Deployment security
└── tests/
    ├── test_security_os.py    # Core tests
    └── test_new_modules.py    # Platform/cleaner/intrusion tests
```

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific test module
pytest tests/test_new_modules.py -v

# Run with coverage
pytest tests/ --cov=. --cov-report=html
```

## Security Note

This software requires appropriate permissions for full functionality:
- **Windows**: Administrator privileges for process management, registry access, and firewall rules
- **Linux/macOS**: Root privileges for process signals, iptables rules, and system log access

Always run security scans and cleanup operations in accordance with your organization's security policies.

## License

See LICENSE file for details.
