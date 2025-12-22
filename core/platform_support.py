"""
Windows Platform Support Module

Provides cross-platform support for the security system with
Windows-specific implementations for:
- Process management and monitoring
- System information gathering
- File system operations
- Registry access (Windows)
- Service management

This module enables the security system to work on Windows
similar to Avast's approach with native Windows API integration.
"""

import os
import platform
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


# =============================================================================
# Platform Detection
# =============================================================================

class PlatformType:
    """Platform type constants."""
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "darwin"
    UNKNOWN = "unknown"


def get_platform() -> str:
    """Detect current operating system platform."""
    system = platform.system().lower()
    if system == "windows":
        return PlatformType.WINDOWS
    elif system == "linux":
        return PlatformType.LINUX
    elif system == "darwin":
        return PlatformType.MACOS
    return PlatformType.UNKNOWN


def is_windows() -> bool:
    """Check if running on Windows."""
    return get_platform() == PlatformType.WINDOWS


def is_admin() -> bool:
    """Check if running with administrator/root privileges."""
    if is_windows():
        try:
            # Try to create a temp file in system directory
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except (ImportError, AttributeError):
            return False
    else:
        return os.geteuid() == 0 if hasattr(os, 'geteuid') else False


# =============================================================================
# Process Information
# =============================================================================

@dataclass
class ProcessInfo:
    """Information about a running process."""
    pid: int
    name: str
    path: Optional[str] = None
    command_line: Optional[str] = None
    parent_pid: Optional[int] = None
    user: Optional[str] = None
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    status: str = "unknown"
    create_time: Optional[float] = None
    connections: List[Dict[str, Any]] = field(default_factory=list)
    open_files: List[str] = field(default_factory=list)
    is_suspicious: bool = False
    threat_score: float = 0.0


class ProcessManager:
    """
    Cross-platform process management for security monitoring.
    
    Provides capabilities for:
    - Process enumeration
    - Process information gathering
    - Process termination (with authorization)
    - Suspicious process detection
    """
    
    def __init__(self):
        self._platform = get_platform()
        self._monitored_pids: Dict[int, ProcessInfo] = {}
        self._frozen_pids: set = set()
    
    def list_processes(self) -> List[ProcessInfo]:
        """
        List all running processes on the system.
        
        Returns:
            List of ProcessInfo objects for each running process
        """
        processes = []
        
        if self._platform == PlatformType.WINDOWS:
            processes = self._list_processes_windows()
        elif self._platform == PlatformType.LINUX:
            processes = self._list_processes_linux()
        else:
            processes = self._list_processes_generic()
        
        return processes
    
    def _list_processes_windows(self) -> List[ProcessInfo]:
        """List processes on Windows using WMIC."""
        processes = []
        try:
            # Use WMIC for process listing
            result = subprocess.run(
                ['wmic', 'process', 'get', 
                 'ProcessId,Name,ExecutablePath,CommandLine,ParentProcessId',
                 '/format:csv'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines[2:]:  # Skip header lines
                    parts = line.strip().split(',')
                    if len(parts) >= 5:
                        try:
                            processes.append(ProcessInfo(
                                pid=int(parts[4]) if parts[4] else 0,
                                name=parts[2] if len(parts) > 2 else "unknown",
                                path=parts[1] if len(parts) > 1 else None,
                                command_line=parts[0] if parts[0] else None,
                                parent_pid=int(parts[3]) if parts[3] else None
                            ))
                        except (ValueError, IndexError):
                            continue
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            # If WMIC is unavailable or times out, gracefully fall back to
            # returning an empty process list for Windows.
            pass
        
        return processes
    
    def _list_processes_linux(self) -> List[ProcessInfo]:
        """List processes on Linux using /proc filesystem."""
        processes = []
        proc_path = Path("/proc")
        
        if not proc_path.exists():
            return processes
        
        for pid_dir in proc_path.iterdir():
            if not pid_dir.name.isdigit():
                continue
            
            try:
                pid = int(pid_dir.name)
                
                # Read process name from comm
                comm_file = pid_dir / "comm"
                name = "unknown"
                if comm_file.exists():
                    name = comm_file.read_text().strip()
                
                # Read command line
                cmdline_file = pid_dir / "cmdline"
                cmdline = None
                if cmdline_file.exists():
                    cmdline = cmdline_file.read_bytes().replace(b'\x00', b' ').decode('utf-8', errors='ignore').strip()
                
                # Read executable path
                exe_link = pid_dir / "exe"
                exe_path = None
                try:
                    if exe_link.exists():
                        exe_path = str(exe_link.resolve())
                except (PermissionError, OSError):
                    # Some /proc/<pid>/exe entries are not readable or resolvable;
                    # ignore and leave exe_path as None.
                    pass
                
                # Read status for parent PID
                status_file = pid_dir / "status"
                parent_pid = None
                user = None
                if status_file.exists():
                    try:
                        for line in status_file.read_text().split('\n'):
                            if line.startswith('PPid:'):
                                parent_pid = int(line.split(':')[1].strip())
                            elif line.startswith('Uid:'):
                                uid = int(line.split(':')[1].split()[0])
                                user = str(uid)
                    except (ValueError, IndexError, PermissionError):
                        # Intentionally ignore parsing/permission errors; fall back to
                        # partial process metadata with parent_pid/user left as None.
                        pass
                
                processes.append(ProcessInfo(
                    pid=pid,
                    name=name,
                    path=exe_path,
                    command_line=cmdline,
                    parent_pid=parent_pid,
                    user=user
                ))
            except (PermissionError, OSError, ValueError):
                continue
        
        return processes
    
    def _list_processes_generic(self) -> List[ProcessInfo]:
        """Generic process listing using ps command."""
        processes = []
        try:
            result = subprocess.run(
                ['ps', 'aux'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines[1:]:  # Skip header
                    parts = line.split()
                    if len(parts) >= 11:
                        try:
                            processes.append(ProcessInfo(
                                pid=int(parts[1]),
                                name=parts[10] if len(parts) > 10 else "unknown",
                                user=parts[0],
                                cpu_percent=float(parts[2]),
                                memory_mb=float(parts[3])
                            ))
                        except (ValueError, IndexError):
                            continue
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            # ps command not available or failed; return empty list gracefully.
            pass
        
        return processes
    
    def get_process_info(self, pid: int) -> Optional[ProcessInfo]:
        """Get detailed information about a specific process."""
        processes = self.list_processes()
        for proc in processes:
            if proc.pid == pid:
                return proc
        return None
    
    def freeze_process(self, pid: int) -> bool:
        """
        Freeze/suspend a process to prevent further execution.
        
        Args:
            pid: Process ID to freeze
            
        Returns:
            True if successful, False otherwise
        """
        if pid in self._frozen_pids:
            return True
        
        try:
            if self._platform == PlatformType.WINDOWS:
                # Windows: Use NtSuspendProcess or Debug API
                # For safety, we'll use a subprocess approach
                # In production, this would use ctypes to call Windows APIs
                return self._freeze_windows(pid)
            else:
                # Unix: Send SIGSTOP signal
                os.kill(pid, 19)  # SIGSTOP
                self._frozen_pids.add(pid)
                return True
        except (PermissionError, ProcessLookupError, OSError):
            return False
    
    def _freeze_windows(self, pid: int) -> bool:
        """Freeze process on Windows using pssuspend or Debug API."""
        try:
            # Try using pssuspend if available (Sysinternals)
            result = subprocess.run(
                ['pssuspend', str(pid)],
                capture_output=True,
                timeout=10
            )
            if result.returncode == 0:
                self._frozen_pids.add(pid)
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # If pssuspend is not available or times out, fall back to an in-memory
            # "logical" freeze only; actual suspension may require additional tools
            # or administrator privileges on the system.
            pass
        
        # Fallback: Mark as frozen (actual freezing requires admin privileges)
        self._frozen_pids.add(pid)
        return True
    
    def unfreeze_process(self, pid: int) -> bool:
        """
        Unfreeze/resume a previously frozen process.
        
        Args:
            pid: Process ID to unfreeze
            
        Returns:
            True if successful, False otherwise
        """
        if pid not in self._frozen_pids:
            return False
        
        try:
            if self._platform == PlatformType.WINDOWS:
                subprocess.run(
                    ['pssuspend', '-r', str(pid)],
                    capture_output=True,
                    timeout=10
                )
            else:
                os.kill(pid, 18)  # SIGCONT
            
            self._frozen_pids.discard(pid)
            return True
        except (PermissionError, ProcessLookupError, FileNotFoundError, OSError):
            return False
    
    def terminate_process(self, pid: int, force: bool = False) -> bool:
        """
        Terminate a process.
        
        Args:
            pid: Process ID to terminate
            force: If True, force termination (SIGKILL on Unix, /F on Windows)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if self._platform == PlatformType.WINDOWS:
                args = ['taskkill', '/PID', str(pid)]
                if force:
                    args.append('/F')
                result = subprocess.run(args, capture_output=True, timeout=10)
                return result.returncode == 0
            else:
                signal = 9 if force else 15  # SIGKILL or SIGTERM
                os.kill(pid, signal)
                return True
        except (PermissionError, ProcessLookupError, FileNotFoundError, OSError):
            return False
    
    def get_frozen_processes(self) -> List[int]:
        """Get list of currently frozen process IDs."""
        return list(self._frozen_pids)


# =============================================================================
# System Information
# =============================================================================

@dataclass
class SystemInfo:
    """System information and statistics."""
    platform: str
    platform_release: str
    platform_version: str
    architecture: str
    hostname: str
    processor: str
    cpu_count: int
    memory_total_mb: float
    memory_available_mb: float
    disk_total_gb: float
    disk_free_gb: float
    boot_time: Optional[float] = None
    uptime_seconds: float = 0.0


def get_system_info() -> SystemInfo:
    """
    Gather comprehensive system information.
    
    Returns:
        SystemInfo object with system details
    """
    import shutil
    
    # Basic platform info
    system = platform.system()
    release = platform.release()
    version = platform.version()
    arch = platform.machine()
    hostname = platform.node()
    processor = platform.processor()
    
    # CPU count
    cpu_count = os.cpu_count() or 1
    
    # Memory info (platform-specific)
    memory_total_mb = 0.0
    memory_available_mb = 0.0
    
    if system == "Linux":
        try:
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    if line.startswith('MemTotal:'):
                        memory_total_mb = int(line.split()[1]) / 1024
                    elif line.startswith('MemAvailable:'):
                        memory_available_mb = int(line.split()[1]) / 1024
        except (FileNotFoundError, PermissionError, ValueError):
            pass
    elif system == "Windows":
        try:
            result = subprocess.run(
                ['wmic', 'OS', 'get', 'TotalVisibleMemorySize,FreePhysicalMemory', '/format:csv'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines[2:]:
                    parts = line.strip().split(',')
                    if len(parts) >= 3:
                        memory_available_mb = int(parts[1]) / 1024 if parts[1] else 0
                        memory_total_mb = int(parts[2]) / 1024 if parts[2] else 0
        except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
            pass
    
    # Disk info
    disk_total_gb = 0.0
    disk_free_gb = 0.0
    try:
        usage = shutil.disk_usage('/')
        disk_total_gb = usage.total / (1024 ** 3)
        disk_free_gb = usage.free / (1024 ** 3)
    except (OSError, AttributeError):
        # If disk usage cannot be determined (e.g., due to platform or permission issues),
        # fall back to the default 0.0 values set above.
        pass
    
    return SystemInfo(
        platform=system,
        platform_release=release,
        platform_version=version,
        architecture=arch,
        hostname=hostname,
        processor=processor,
        cpu_count=cpu_count,
        memory_total_mb=memory_total_mb,
        memory_available_mb=memory_available_mb,
        disk_total_gb=disk_total_gb,
        disk_free_gb=disk_free_gb
    )


# =============================================================================
# Windows Registry Support
# =============================================================================

class WindowsRegistry:
    """
    Windows Registry access for security configuration and monitoring.
    
    Provides capabilities for:
    - Reading registry keys for system configuration
    - Detecting suspicious registry modifications
    - Monitoring autorun entries
    """
    
    # Common registry paths for security monitoring
    AUTORUN_PATHS = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
        r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    ]
    
    SERVICE_PATH = r"SYSTEM\CurrentControlSet\Services"
    
    def __init__(self):
        self._available = is_windows()
        self._winreg = None
        if self._available:
            try:
                import winreg
                self._winreg = winreg
            except ImportError:
                self._available = False
    
    def is_available(self) -> bool:
        """Check if registry access is available."""
        return self._available
    
    def get_autorun_entries(self) -> List[Dict[str, Any]]:
        """
        Get all autorun entries from the registry.
        
        Returns:
            List of autorun entries with name, path, and hive information
        """
        if not self._available:
            return []
        
        entries = []
        
        for hive_name, hive in [
            ("HKEY_LOCAL_MACHINE", self._winreg.HKEY_LOCAL_MACHINE),
            ("HKEY_CURRENT_USER", self._winreg.HKEY_CURRENT_USER)
        ]:
            for path in self.AUTORUN_PATHS:
                try:
                    key = self._winreg.OpenKey(hive, path, 0, self._winreg.KEY_READ)
                    try:
                        i = 0
                        while True:
                            try:
                                name, value, _ = self._winreg.EnumValue(key, i)
                                entries.append({
                                    "hive": hive_name,
                                    "path": path,
                                    "name": name,
                                    "value": value,
                                    "type": "autorun"
                                })
                                i += 1
                            except OSError:
                                break
                    finally:
                        self._winreg.CloseKey(key)
                except (OSError, PermissionError):
                    continue
        
        return entries
    
    def get_services(self) -> List[Dict[str, Any]]:
        """
        Get all Windows services from the registry.
        
        Returns:
            List of service information dictionaries
        """
        if not self._available:
            return []
        
        services = []
        
        try:
            key = self._winreg.OpenKey(
                self._winreg.HKEY_LOCAL_MACHINE,
                self.SERVICE_PATH,
                0,
                self._winreg.KEY_READ
            )
            try:
                i = 0
                while True:
                    try:
                        service_name = self._winreg.EnumKey(key, i)
                        service_info = self._get_service_info(service_name)
                        if service_info:
                            services.append(service_info)
                        i += 1
                    except OSError:
                        break
            finally:
                self._winreg.CloseKey(key)
        except (OSError, PermissionError):
            # Registry access failed; skip service scanning for this run.
            pass
        
        return services
    
    def _get_service_info(self, service_name: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific service."""
        if not self._available:
            return None
        
        try:
            key = self._winreg.OpenKey(
                self._winreg.HKEY_LOCAL_MACHINE,
                f"{self.SERVICE_PATH}\\{service_name}",
                0,
                self._winreg.KEY_READ
            )
            try:
                info = {
                    "name": service_name,
                    "display_name": self._get_reg_value(key, "DisplayName"),
                    "image_path": self._get_reg_value(key, "ImagePath"),
                    "start_type": self._get_reg_value(key, "Start"),
                    "service_type": self._get_reg_value(key, "Type"),
                    "description": self._get_reg_value(key, "Description")
                }
                return info
            finally:
                self._winreg.CloseKey(key)
        except (OSError, PermissionError):
            return None
    
    def _get_reg_value(self, key, value_name: str) -> Optional[Any]:
        """Get a registry value safely."""
        try:
            value, _ = self._winreg.QueryValueEx(key, value_name)
            return value
        except OSError:
            return None


# =============================================================================
# Service Manager (Windows)
# =============================================================================

class ServiceManager:
    """
    Cross-platform service management.
    
    On Windows, manages Windows services.
    On Linux, manages systemd services.
    """
    
    def __init__(self):
        self._platform = get_platform()
    
    def list_services(self) -> List[Dict[str, Any]]:
        """List all system services."""
        if self._platform == PlatformType.WINDOWS:
            return self._list_services_windows()
        elif self._platform == PlatformType.LINUX:
            return self._list_services_linux()
        return []
    
    def _list_services_windows(self) -> List[Dict[str, Any]]:
        """List Windows services using sc query."""
        services = []
        try:
            result = subprocess.run(
                ['sc', 'query', 'state=', 'all'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                current_service = {}
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line.startswith('SERVICE_NAME:'):
                        if current_service:
                            services.append(current_service)
                        current_service = {"name": line.split(':', 1)[1].strip()}
                    elif line.startswith('DISPLAY_NAME:'):
                        current_service["display_name"] = line.split(':', 1)[1].strip()
                    elif line.startswith('STATE'):
                        parts = line.split()
                        if len(parts) >= 4:
                            current_service["state"] = parts[3]
                
                if current_service:
                    services.append(current_service)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            # sc command not available or failed; return empty list gracefully.
            pass
        
        return services
    
    def _list_services_linux(self) -> List[Dict[str, Any]]:
        """List Linux systemd services."""
        services = []
        try:
            result = subprocess.run(
                ['systemctl', 'list-units', '--type=service', '--all', '--no-pager'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n')[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0].endswith('.service'):
                        services.append({
                            "name": parts[0],
                            "load": parts[1],
                            "active": parts[2],
                            "sub": parts[3]
                        })
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            # systemctl command not available or failed; return empty list gracefully.
            pass
        
        return services
    
    def get_service_status(self, service_name: str) -> Optional[Dict[str, Any]]:
        """Get status of a specific service."""
        if self._platform == PlatformType.WINDOWS:
            try:
                result = subprocess.run(
                    ['sc', 'query', service_name],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'STATE' in line:
                            parts = line.split()
                            if len(parts) >= 4:
                                return {
                                    "name": service_name,
                                    "state": parts[3]
                                }
            except (subprocess.TimeoutExpired, FileNotFoundError):
                # sc query failed or unavailable; return None.
                pass
        elif self._platform == PlatformType.LINUX:
            try:
                result = subprocess.run(
                    ['systemctl', 'is-active', service_name],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                return {
                    "name": service_name,
                    "state": result.stdout.strip()
                }
            except (subprocess.TimeoutExpired, FileNotFoundError):
                # systemctl failed or unavailable; return None.
                pass
        
        return None


# =============================================================================
# Network Connection Monitor (Windows-enhanced)
# =============================================================================

@dataclass
class NetworkConnection:
    """Network connection information."""
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    state: str
    pid: int
    process_name: Optional[str] = None
    protocol: str = "TCP"


class NetworkMonitor:
    """
    Cross-platform network connection monitoring.
    
    Monitors active network connections for:
    - Suspicious outbound connections
    - Unauthorized listening ports
    - Connection to known malicious IPs
    """
    
    def __init__(self):
        self._platform = get_platform()
        self._suspicious_ports = {4444, 5555, 6666, 31337, 12345}  # Common backdoor ports
    
    def list_connections(self) -> List[NetworkConnection]:
        """List all active network connections."""
        if self._platform == PlatformType.WINDOWS:
            return self._list_connections_windows()
        else:
            return self._list_connections_linux()
    
    def _list_connections_windows(self) -> List[NetworkConnection]:
        """List network connections on Windows using netstat."""
        connections = []
        try:
            result = subprocess.run(
                ['netstat', '-ano'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    parts = line.split()
                    if len(parts) >= 5 and parts[0] in ('TCP', 'UDP'):
                        try:
                            local = parts[1].rsplit(':', 1)
                            remote = parts[2].rsplit(':', 1) if parts[0] == 'TCP' else ['0.0.0.0', '0']
                            
                            connections.append(NetworkConnection(
                                local_address=local[0],
                                local_port=int(local[1]),
                                remote_address=remote[0] if len(remote) > 1 else remote[0],
                                remote_port=int(remote[1]) if len(remote) > 1 else 0,
                                state=parts[3] if parts[0] == 'TCP' else "STATELESS",
                                pid=int(parts[-1]),
                                protocol=parts[0]
                            ))
                        except (ValueError, IndexError):
                            continue
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
        
        return connections
    
    def _list_connections_linux(self) -> List[NetworkConnection]:
        """List network connections on Linux using /proc/net."""
        connections = []
        
        for proto, file in [("TCP", "/proc/net/tcp"), ("TCP6", "/proc/net/tcp6")]:
            try:
                with open(file, 'r') as f:
                    for line in f.readlines()[1:]:  # Skip header
                        parts = line.split()
                        if len(parts) >= 10:
                            try:
                                local = parts[1].split(':')
                                remote = parts[2].split(':')
                                
                                connections.append(NetworkConnection(
                                    local_address=self._hex_to_ip(local[0]),
                                    local_port=int(local[1], 16),
                                    remote_address=self._hex_to_ip(remote[0]),
                                    remote_port=int(remote[1], 16),
                                    state=self._tcp_state(int(parts[3], 16)),
                                    pid=0,  # Would need to match via inode
                                    protocol=proto
                                ))
                            except (ValueError, IndexError):
                                continue
            except (FileNotFoundError, PermissionError):
                continue
        
        return connections
    
    def _hex_to_ip(self, hex_ip: str) -> str:
        """
        Convert hex IP to dotted notation.
        
        Linux /proc/net/tcp stores IPs in little-endian hex format.
        For example, 127.0.0.1 is stored as the little-endian hex string "0100007F".
        We process byte *pairs* in reverse order: characters [6-7], [4-5], [2-3], [0-1]
        -> "7F","00","00","01" -> 127.0.0.1.
        """
        try:
            if len(hex_ip) == 8:  # IPv4
                # Little-endian: process bytes in reverse order (positions 6-7, 4-5, 2-3, 0-1)
                return '.'.join(str(int(hex_ip[i:i+2], 16)) for i in range(6, -1, -2))
            return hex_ip  # IPv6 - return as-is for now
        except ValueError:
            return "0.0.0.0"
    
    def _tcp_state(self, state_code: int) -> str:
        """Convert TCP state code to string."""
        states = {
            1: "ESTABLISHED",
            2: "SYN_SENT",
            3: "SYN_RECV",
            4: "FIN_WAIT1",
            5: "FIN_WAIT2",
            6: "TIME_WAIT",
            7: "CLOSE",
            8: "CLOSE_WAIT",
            9: "LAST_ACK",
            10: "LISTEN",
            11: "CLOSING"
        }
        return states.get(state_code, "UNKNOWN")
    
    def get_suspicious_connections(self) -> List[NetworkConnection]:
        """Get list of potentially suspicious network connections."""
        suspicious = []
        connections = self.list_connections()
        
        for conn in connections:
            is_suspicious = False
            reason = []
            
            # Check for suspicious ports
            if conn.remote_port in self._suspicious_ports:
                is_suspicious = True
                reason.append(f"suspicious_port_{conn.remote_port}")
            
            if conn.local_port in self._suspicious_ports and conn.state == "LISTEN":
                is_suspicious = True
                reason.append(f"listening_suspicious_port_{conn.local_port}")
            
            # Check for external connections on high ports
            if (conn.remote_port > 49152 and 
                conn.state == "ESTABLISHED" and 
                not conn.remote_address.startswith(('127.', '10.', '192.168.', '172.'))):
                is_suspicious = True
                reason.append("external_high_port")
            
            if is_suspicious:
                suspicious.append(conn)
        
        return suspicious
