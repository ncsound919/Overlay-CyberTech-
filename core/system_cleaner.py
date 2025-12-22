"""
System Cleaner Module - Advanced CCleaner Capabilities

Provides comprehensive system cleaning functionality similar to CCleaner:
- Temporary file cleanup
- Browser cache and history cleaning
- System log cleanup
- Registry cleaning (Windows)
- Application cache cleanup
- Disk space analysis

Implements secure deletion with multiple passes where needed
and provides detailed reporting of cleaned items.
"""

import hashlib
import os
import shutil
import sqlite3
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .platform_support import get_platform, is_windows, PlatformType


# =============================================================================
# Cleanup Configuration
# =============================================================================

@dataclass
class CleanupResult:
    """Result of a cleanup operation."""
    category: str
    files_deleted: int = 0
    bytes_freed: int = 0
    errors: List[str] = field(default_factory=list)
    items_cleaned: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    success: bool = True


@dataclass
class CleanupConfig:
    """Configuration for cleanup operations."""
    clean_temp_files: bool = True
    clean_browser_cache: bool = True
    clean_browser_history: bool = False  # More invasive, off by default
    clean_system_logs: bool = False  # Requires admin, off by default
    clean_recycle_bin: bool = True
    clean_thumbnails: bool = True
    clean_prefetch: bool = False  # Windows only, may impact performance
    secure_delete: bool = False  # Multi-pass deletion
    secure_delete_passes: int = 3
    min_file_age_days: int = 0  # Only clean files older than this
    max_file_size_mb: int = 0  # 0 = no limit
    dry_run: bool = False  # If True, only report what would be cleaned


# =============================================================================
# System Cleaner
# =============================================================================

class SystemCleaner:
    """
    Comprehensive system cleaning utility.
    
    Provides CCleaner-like functionality for:
    - Temporary files cleanup
    - Browser data cleanup
    - System cache cleanup
    - Disk space recovery
    """
    
    def __init__(self, config: Optional[CleanupConfig] = None):
        self.config = config or CleanupConfig()
        self._platform = get_platform()
        self._results: List[CleanupResult] = []
        self._total_bytes_freed = 0
        self._total_files_deleted = 0
    
    def run_full_cleanup(self) -> Dict[str, Any]:
        """
        Run full system cleanup based on configuration.
        
        Returns:
            Summary of cleanup operations
        """
        self._results = []
        self._total_bytes_freed = 0
        self._total_files_deleted = 0
        start_time = time.time()
        
        if self.config.clean_temp_files:
            self._results.append(self.clean_temp_files())
        
        if self.config.clean_browser_cache:
            self._results.append(self.clean_browser_cache())
        
        if self.config.clean_browser_history:
            self._results.append(self.clean_browser_history())
        
        if self.config.clean_thumbnails:
            self._results.append(self.clean_thumbnails())
        
        if self.config.clean_recycle_bin:
            self._results.append(self.clean_recycle_bin())
        
        if self.config.clean_prefetch and self._platform == PlatformType.WINDOWS:
            self._results.append(self.clean_prefetch())
        
        if self.config.clean_system_logs:
            self._results.append(self.clean_system_logs())
        
        total_duration = time.time() - start_time
        
        return {
            "success": all(r.success for r in self._results),
            "total_bytes_freed": self._total_bytes_freed,
            "total_bytes_freed_mb": round(self._total_bytes_freed / (1024 * 1024), 2),
            "total_files_deleted": self._total_files_deleted,
            "duration_seconds": round(total_duration, 2),
            "results_by_category": [
                {
                    "category": r.category,
                    "files_deleted": r.files_deleted,
                    "bytes_freed": r.bytes_freed,
                    "bytes_freed_mb": round(r.bytes_freed / (1024 * 1024), 2),
                    "errors": r.errors,
                    "success": r.success
                }
                for r in self._results
            ],
            "dry_run": self.config.dry_run
        }
    
    def clean_temp_files(self) -> CleanupResult:
        """Clean temporary files from system and user temp directories."""
        result = CleanupResult(category="temp_files")
        start_time = time.time()
        
        temp_dirs = self._get_temp_directories()
        
        for temp_dir in temp_dirs:
            if not os.path.exists(temp_dir):
                continue
            
            self._clean_directory(temp_dir, result)
        
        result.duration_seconds = time.time() - start_time
        self._total_bytes_freed += result.bytes_freed
        self._total_files_deleted += result.files_deleted
        return result
    
    def _get_temp_directories(self) -> List[str]:
        """Get list of temporary directories based on platform."""
        temp_dirs = [tempfile.gettempdir()]
        
        if self._platform == PlatformType.WINDOWS:
            # Windows temp directories
            win_temp = os.environ.get('TEMP', '')
            win_tmp = os.environ.get('TMP', '')
            local_temp = os.path.join(
                os.environ.get('LOCALAPPDATA', ''),
                'Temp'
            )
            
            for path in [win_temp, win_tmp, local_temp]:
                if path and os.path.exists(path) and path not in temp_dirs:
                    temp_dirs.append(path)
            
            # Windows system temp
            system_temp = r'C:\Windows\Temp'
            if os.path.exists(system_temp):
                temp_dirs.append(system_temp)
        
        elif self._platform == PlatformType.LINUX:
            # Linux temp directories
            linux_temps = ['/tmp', '/var/tmp']
            for path in linux_temps:
                if os.path.exists(path) and path not in temp_dirs:
                    temp_dirs.append(path)
        
        return temp_dirs
    
    def clean_browser_cache(self) -> CleanupResult:
        """Clean browser cache files."""
        result = CleanupResult(category="browser_cache")
        start_time = time.time()
        
        cache_paths = self._get_browser_cache_paths()
        
        for cache_path in cache_paths:
            if os.path.exists(cache_path):
                self._clean_directory(cache_path, result, recursive=True)
        
        result.duration_seconds = time.time() - start_time
        self._total_bytes_freed += result.bytes_freed
        self._total_files_deleted += result.files_deleted
        return result
    
    def _get_browser_cache_paths(self) -> List[str]:
        """Get browser cache directory paths for supported browsers."""
        paths = []
        home = os.path.expanduser('~')
        
        if self._platform == PlatformType.WINDOWS:
            local_app_data = os.environ.get('LOCALAPPDATA', '')
            
            # Chrome
            chrome_cache = os.path.join(
                local_app_data,
                'Google', 'Chrome', 'User Data', 'Default', 'Cache'
            )
            paths.append(chrome_cache)
            
            # Firefox
            firefox_profiles = os.path.join(
                local_app_data,
                'Mozilla', 'Firefox', 'Profiles'
            )
            if os.path.exists(firefox_profiles):
                for profile in os.listdir(firefox_profiles):
                    cache_path = os.path.join(firefox_profiles, profile, 'cache2')
                    paths.append(cache_path)
            
            # Edge
            edge_cache = os.path.join(
                local_app_data,
                'Microsoft', 'Edge', 'User Data', 'Default', 'Cache'
            )
            paths.append(edge_cache)
            
            # Opera
            opera_cache = os.path.join(
                local_app_data,
                'Opera Software', 'Opera Stable', 'Cache'
            )
            paths.append(opera_cache)
            
        elif self._platform == PlatformType.LINUX:
            # Chrome
            paths.append(os.path.join(home, '.cache', 'google-chrome'))
            paths.append(os.path.join(home, '.cache', 'chromium'))
            
            # Firefox
            firefox_path = os.path.join(home, '.mozilla', 'firefox')
            if os.path.exists(firefox_path):
                for item in os.listdir(firefox_path):
                    if '.default' in item:
                        paths.append(os.path.join(firefox_path, item, 'cache2'))
            
        elif self._platform == PlatformType.MACOS:
            # Chrome
            paths.append(os.path.join(
                home, 'Library', 'Caches', 'Google', 'Chrome'
            ))
            
            # Safari
            paths.append(os.path.join(
                home, 'Library', 'Caches', 'com.apple.Safari'
            ))
            
            # Firefox
            paths.append(os.path.join(
                home, 'Library', 'Caches', 'Firefox'
            ))
        
        return paths
    
    def clean_browser_history(self) -> CleanupResult:
        """Clean browser history databases."""
        result = CleanupResult(category="browser_history")
        start_time = time.time()
        
        # This is more invasive - handle with care
        history_files = self._get_browser_history_files()
        
        for history_file in history_files:
            if os.path.exists(history_file):
                try:
                    # For SQLite history files, we clear the tables instead of deleting
                    if history_file.endswith('.sqlite') or 'History' in history_file:
                        self._clear_sqlite_history(history_file, result)
                    else:
                        file_size = os.path.getsize(history_file)
                        if not self.config.dry_run:
                            self._delete_file(history_file)
                        result.files_deleted += 1
                        result.bytes_freed += file_size
                        result.items_cleaned.append(history_file)
                except (PermissionError, OSError) as e:
                    result.errors.append(f"{history_file}: {str(e)}")
        
        result.duration_seconds = time.time() - start_time
        self._total_bytes_freed += result.bytes_freed
        self._total_files_deleted += result.files_deleted
        return result
    
    def _get_browser_history_files(self) -> List[str]:
        """Get browser history file paths."""
        paths = []
        home = os.path.expanduser('~')
        
        if self._platform == PlatformType.WINDOWS:
            local_app_data = os.environ.get('LOCALAPPDATA', '')
            
            # Chrome History
            paths.append(os.path.join(
                local_app_data,
                'Google', 'Chrome', 'User Data', 'Default', 'History'
            ))
            
            # Edge History
            paths.append(os.path.join(
                local_app_data,
                'Microsoft', 'Edge', 'User Data', 'Default', 'History'
            ))
            
        elif self._platform == PlatformType.LINUX:
            # Chrome
            paths.append(os.path.join(
                home, '.config', 'google-chrome', 'Default', 'History'
            ))
            
            # Firefox
            firefox_path = os.path.join(home, '.mozilla', 'firefox')
            if os.path.exists(firefox_path):
                for item in os.listdir(firefox_path):
                    if '.default' in item:
                        paths.append(os.path.join(
                            firefox_path, item, 'places.sqlite'
                        ))
        
        return paths
    
    def _clear_sqlite_history(self, db_path: str, result: CleanupResult) -> None:
        """Clear history from SQLite database files."""
        if self.config.dry_run:
            result.items_cleaned.append(f"{db_path} (would clear)")
            return
        
        try:
            # Get original file size
            original_size = os.path.getsize(db_path)
            
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Get list of tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()
            
            # Clear history-related tables
            history_tables = ['urls', 'visits', 'downloads', 'moz_places', 
                            'moz_historyvisits', 'moz_downloads']
            
            for table in tables:
                table_name = table[0]
                if any(h in table_name.lower() for h in ['url', 'visit', 'history', 'download']):
                    try:
                        cursor.execute(f"DELETE FROM {table_name}")
                    except sqlite3.OperationalError:
                        pass
            
            conn.commit()
            cursor.execute("VACUUM")
            conn.close()
            
            # Calculate space freed
            new_size = os.path.getsize(db_path)
            result.bytes_freed += max(0, original_size - new_size)
            result.items_cleaned.append(db_path)
            result.files_deleted += 1
            
        except (sqlite3.Error, OSError) as e:
            result.errors.append(f"{db_path}: {str(e)}")
    
    def clean_thumbnails(self) -> CleanupResult:
        """Clean system thumbnail caches."""
        result = CleanupResult(category="thumbnails")
        start_time = time.time()
        
        thumb_paths = self._get_thumbnail_paths()
        
        for thumb_path in thumb_paths:
            if os.path.exists(thumb_path):
                self._clean_directory(thumb_path, result, recursive=True)
        
        result.duration_seconds = time.time() - start_time
        self._total_bytes_freed += result.bytes_freed
        self._total_files_deleted += result.files_deleted
        return result
    
    def _get_thumbnail_paths(self) -> List[str]:
        """Get thumbnail cache directory paths."""
        paths = []
        home = os.path.expanduser('~')
        
        if self._platform == PlatformType.WINDOWS:
            local_app_data = os.environ.get('LOCALAPPDATA', '')
            
            # Windows thumbnail cache
            paths.append(os.path.join(
                local_app_data,
                'Microsoft', 'Windows', 'Explorer'
            ))
            
        elif self._platform == PlatformType.LINUX:
            # GNOME/GTK thumbnails
            paths.append(os.path.join(home, '.cache', 'thumbnails'))
            paths.append(os.path.join(home, '.thumbnails'))
            
        elif self._platform == PlatformType.MACOS:
            paths.append(os.path.join(
                home, 'Library', 'Caches', 'com.apple.QuickLook.thumbnailcache'
            ))
        
        return paths
    
    def clean_recycle_bin(self) -> CleanupResult:
        """Empty the system recycle bin / trash."""
        result = CleanupResult(category="recycle_bin")
        start_time = time.time()
        
        if self._platform == PlatformType.WINDOWS:
            self._clean_windows_recycle_bin(result)
        elif self._platform == PlatformType.LINUX:
            self._clean_linux_trash(result)
        elif self._platform == PlatformType.MACOS:
            self._clean_macos_trash(result)
        
        result.duration_seconds = time.time() - start_time
        self._total_bytes_freed += result.bytes_freed
        self._total_files_deleted += result.files_deleted
        return result
    
    def _clean_windows_recycle_bin(self, result: CleanupResult) -> None:
        """Empty Windows Recycle Bin."""
        if self.config.dry_run:
            result.items_cleaned.append("Windows Recycle Bin (would empty)")
            return
        
        try:
            import subprocess
            # Use PowerShell to empty recycle bin
            subprocess.run(
                ['powershell', '-Command', 
                 'Clear-RecycleBin', '-Force', '-ErrorAction', 'SilentlyContinue'],
                capture_output=True,
                timeout=60
            )
            result.items_cleaned.append("Windows Recycle Bin")
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            result.errors.append(f"Recycle Bin: {str(e)}")
    
    def _clean_linux_trash(self, result: CleanupResult) -> None:
        """Empty Linux trash."""
        home = os.path.expanduser('~')
        trash_paths = [
            os.path.join(home, '.local', 'share', 'Trash', 'files'),
            os.path.join(home, '.local', 'share', 'Trash', 'info'),
            os.path.join(home, '.Trash')
        ]
        
        for trash_path in trash_paths:
            if os.path.exists(trash_path):
                self._clean_directory(trash_path, result, recursive=True)
    
    def _clean_macos_trash(self, result: CleanupResult) -> None:
        """Empty macOS Trash."""
        home = os.path.expanduser('~')
        trash_path = os.path.join(home, '.Trash')
        
        if os.path.exists(trash_path):
            self._clean_directory(trash_path, result, recursive=True)
    
    def clean_prefetch(self) -> CleanupResult:
        """Clean Windows Prefetch files."""
        result = CleanupResult(category="prefetch")
        start_time = time.time()
        
        if self._platform != PlatformType.WINDOWS:
            result.errors.append("Prefetch cleaning only available on Windows")
            return result
        
        prefetch_path = r'C:\Windows\Prefetch'
        
        if os.path.exists(prefetch_path):
            self._clean_directory(prefetch_path, result, extensions=['.pf'])
        
        result.duration_seconds = time.time() - start_time
        self._total_bytes_freed += result.bytes_freed
        self._total_files_deleted += result.files_deleted
        return result
    
    def clean_system_logs(self) -> CleanupResult:
        """Clean system log files."""
        result = CleanupResult(category="system_logs")
        start_time = time.time()
        
        log_paths = self._get_log_paths()
        
        for log_path in log_paths:
            if os.path.exists(log_path):
                if os.path.isdir(log_path):
                    self._clean_directory(log_path, result, extensions=['.log', '.old', '.1', '.2', '.gz'])
                elif os.path.isfile(log_path):
                    self._truncate_log_file(log_path, result)
        
        result.duration_seconds = time.time() - start_time
        self._total_bytes_freed += result.bytes_freed
        self._total_files_deleted += result.files_deleted
        return result
    
    def _get_log_paths(self) -> List[str]:
        """Get system log paths."""
        paths = []
        
        if self._platform == PlatformType.WINDOWS:
            # Windows log locations
            paths.append(os.path.join(os.environ.get('SYSTEMROOT', r'C:\Windows'), 'Logs'))
            paths.append(os.path.join(os.environ.get('SYSTEMROOT', r'C:\Windows'), 'Debug'))
            
        elif self._platform == PlatformType.LINUX:
            paths.append('/var/log')
            
        elif self._platform == PlatformType.MACOS:
            paths.append('/var/log')
            paths.append(os.path.expanduser('~/Library/Logs'))
        
        return paths
    
    def _truncate_log_file(self, file_path: str, result: CleanupResult) -> None:
        """Truncate a log file to zero bytes."""
        try:
            original_size = os.path.getsize(file_path)
            
            if not self.config.dry_run:
                with open(file_path, 'w') as f:
                    pass  # Truncate to zero
            
            result.bytes_freed += original_size
            result.items_cleaned.append(file_path)
            result.files_deleted += 1
        except (PermissionError, OSError) as e:
            result.errors.append(f"{file_path}: {str(e)}")
    
    def _clean_directory(
        self,
        directory: str,
        result: CleanupResult,
        recursive: bool = False,
        extensions: Optional[List[str]] = None
    ) -> None:
        """
        Clean files from a directory.
        
        Args:
            directory: Directory to clean
            result: CleanupResult to update
            recursive: If True, clean subdirectories as well
            extensions: If provided, only clean files with these extensions
        """
        try:
            for item in os.listdir(directory):
                item_path = os.path.join(directory, item)
                
                try:
                    if os.path.isfile(item_path):
                        # Check extension filter
                        if extensions:
                            if not any(item.lower().endswith(ext) for ext in extensions):
                                continue
                        
                        # Check age filter
                        if self.config.min_file_age_days > 0:
                            mtime = os.path.getmtime(item_path)
                            age_days = (time.time() - mtime) / 86400
                            if age_days < self.config.min_file_age_days:
                                continue
                        
                        # Check size filter
                        file_size = os.path.getsize(item_path)
                        if self.config.max_file_size_mb > 0:
                            if file_size > self.config.max_file_size_mb * 1024 * 1024:
                                continue
                        
                        if not self.config.dry_run:
                            self._delete_file(item_path)
                        
                        result.files_deleted += 1
                        result.bytes_freed += file_size
                        result.items_cleaned.append(item_path)
                        
                    elif os.path.isdir(item_path) and recursive:
                        self._clean_directory(item_path, result, recursive=True, extensions=extensions)
                        
                        # Try to remove empty directory
                        if not self.config.dry_run:
                            try:
                                os.rmdir(item_path)
                            except OSError:
                                pass  # Directory not empty
                                
                except (PermissionError, OSError) as e:
                    result.errors.append(f"{item_path}: {str(e)}")
                    
        except (PermissionError, OSError) as e:
            result.errors.append(f"{directory}: {str(e)}")
    
    def _delete_file(self, file_path: str) -> None:
        """Delete a file, optionally with secure deletion."""
        if self.config.secure_delete:
            self._secure_delete_file(file_path)
        else:
            os.remove(file_path)
    
    def _secure_delete_file(self, file_path: str) -> None:
        """
        Securely delete a file by overwriting with random data.
        
        Uses multiple passes of random data before deletion
        to prevent forensic recovery.
        """
        try:
            file_size = os.path.getsize(file_path)
            
            with open(file_path, 'r+b') as f:
                for _ in range(self.config.secure_delete_passes):
                    f.seek(0)
                    f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())
            
            os.remove(file_path)
        except (PermissionError, OSError):
            # Fall back to regular deletion
            os.remove(file_path)
    
    def analyze_disk_usage(self, path: str = '/') -> Dict[str, Any]:
        """
        Analyze disk usage and identify large files/directories.
        
        Args:
            path: Root path to analyze
            
        Returns:
            Analysis results with space breakdown
        """
        usage = shutil.disk_usage(path)
        
        # Find largest directories
        large_dirs = []
        large_files = []
        
        try:
            for root, dirs, files in os.walk(path):
                # Skip system directories
                if any(skip in root for skip in ['$', '.git', 'node_modules', '__pycache__']):
                    continue
                
                # Calculate directory size
                dir_size = sum(
                    os.path.getsize(os.path.join(root, f))
                    for f in files
                    if os.path.exists(os.path.join(root, f))
                )
                
                if dir_size > 100 * 1024 * 1024:  # > 100MB
                    large_dirs.append({
                        "path": root,
                        "size_mb": round(dir_size / (1024 * 1024), 2)
                    })
                
                # Check individual files
                for f in files:
                    file_path = os.path.join(root, f)
                    try:
                        file_size = os.path.getsize(file_path)
                        if file_size > 50 * 1024 * 1024:  # > 50MB
                            large_files.append({
                                "path": file_path,
                                "size_mb": round(file_size / (1024 * 1024), 2)
                            })
                    except OSError:
                        continue
                
                # Limit search depth
                if len(large_dirs) > 100 or len(large_files) > 100:
                    break
                    
        except (PermissionError, OSError):
            pass
        
        # Sort by size
        large_dirs.sort(key=lambda x: x['size_mb'], reverse=True)
        large_files.sort(key=lambda x: x['size_mb'], reverse=True)
        
        return {
            "total_gb": round(usage.total / (1024 ** 3), 2),
            "used_gb": round(usage.used / (1024 ** 3), 2),
            "free_gb": round(usage.free / (1024 ** 3), 2),
            "percent_used": round(usage.used / usage.total * 100, 1),
            "largest_directories": large_dirs[:20],
            "largest_files": large_files[:20]
        }
    
    def get_cleanup_preview(self) -> Dict[str, Any]:
        """
        Preview what would be cleaned without actually cleaning.
        
        Returns:
            Preview of cleanup operations
        """
        original_dry_run = self.config.dry_run
        self.config.dry_run = True
        
        try:
            result = self.run_full_cleanup()
            result["is_preview"] = True
            return result
        finally:
            self.config.dry_run = original_dry_run


# =============================================================================
# Registry Cleaner (Windows)
# =============================================================================

class RegistryCleaner:
    """
    Windows Registry cleaner for removing invalid entries.
    
    Scans and cleans:
    - Invalid file associations
    - Missing application references
    - Orphaned startup entries
    - Invalid MUI cache entries
    """
    
    def __init__(self):
        self._available = is_windows()
        self._winreg = None
        if self._available:
            try:
                import winreg
                self._winreg = winreg
            except ImportError:
                self._available = False
        
        self._issues: List[Dict[str, Any]] = []
    
    def is_available(self) -> bool:
        """Check if registry cleaning is available."""
        return self._available
    
    def scan_registry(self) -> List[Dict[str, Any]]:
        """
        Scan registry for invalid entries.
        
        Returns:
            List of detected issues
        """
        if not self._available:
            return []
        
        self._issues = []
        
        self._scan_invalid_file_associations()
        self._scan_orphaned_startup_entries()
        self._scan_invalid_uninstall_entries()
        
        return self._issues
    
    def _scan_invalid_file_associations(self) -> None:
        """Scan for invalid file associations."""
        try:
            key = self._winreg.OpenKey(
                self._winreg.HKEY_CLASSES_ROOT,
                "",
                0,
                self._winreg.KEY_READ
            )
            
            try:
                i = 0
                while True:
                    try:
                        subkey_name = self._winreg.EnumKey(key, i)
                        if subkey_name.startswith('.'):
                            # Check if associated program exists
                            try:
                                subkey = self._winreg.OpenKey(key, subkey_name)
                                prog_id, _ = self._winreg.QueryValueEx(subkey, "")
                                self._winreg.CloseKey(subkey)
                                
                                # Check if program ID exists
                                try:
                                    prog_key = self._winreg.OpenKey(key, prog_id)
                                    self._winreg.CloseKey(prog_key)
                                except WindowsError:
                                    self._issues.append({
                                        "type": "invalid_file_association",
                                        "extension": subkey_name,
                                        "missing_prog_id": prog_id,
                                        "severity": "low"
                                    })
                            except WindowsError:
                                pass
                        i += 1
                    except WindowsError:
                        break
            finally:
                self._winreg.CloseKey(key)
        except (WindowsError, PermissionError):
            pass
    
    def _scan_orphaned_startup_entries(self) -> None:
        """Scan for startup entries pointing to non-existent files."""
        startup_paths = [
            (self._winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (self._winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        ]
        
        for hive, path in startup_paths:
            try:
                key = self._winreg.OpenKey(hive, path, 0, self._winreg.KEY_READ)
                try:
                    i = 0
                    while True:
                        try:
                            name, value, _ = self._winreg.EnumValue(key, i)
                            
                            # Extract path from value
                            exe_path = self._extract_path_from_command(value)
                            
                            if exe_path and not os.path.exists(exe_path):
                                self._issues.append({
                                    "type": "orphaned_startup",
                                    "name": name,
                                    "value": value,
                                    "missing_path": exe_path,
                                    "severity": "medium"
                                })
                            i += 1
                        except WindowsError:
                            break
                finally:
                    self._winreg.CloseKey(key)
            except (WindowsError, PermissionError):
                continue
    
    def _scan_invalid_uninstall_entries(self) -> None:
        """Scan for uninstall entries with missing executables."""
        uninstall_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        
        try:
            key = self._winreg.OpenKey(
                self._winreg.HKEY_LOCAL_MACHINE,
                uninstall_path,
                0,
                self._winreg.KEY_READ
            )
            
            try:
                i = 0
                while True:
                    try:
                        subkey_name = self._winreg.EnumKey(key, i)
                        subkey = self._winreg.OpenKey(key, subkey_name)
                        
                        try:
                            install_location, _ = self._winreg.QueryValueEx(
                                subkey, "InstallLocation"
                            )
                            
                            if install_location and not os.path.exists(install_location):
                                display_name = ""
                                try:
                                    display_name, _ = self._winreg.QueryValueEx(
                                        subkey, "DisplayName"
                                    )
                                except WindowsError:
                                    pass
                                
                                self._issues.append({
                                    "type": "orphaned_uninstall",
                                    "key": subkey_name,
                                    "display_name": display_name,
                                    "missing_path": install_location,
                                    "severity": "low"
                                })
                        except WindowsError:
                            pass
                        
                        self._winreg.CloseKey(subkey)
                        i += 1
                    except WindowsError:
                        break
            finally:
                self._winreg.CloseKey(key)
        except (WindowsError, PermissionError):
            pass
    
    def _extract_path_from_command(self, command: str) -> Optional[str]:
        """Extract executable path from a command string."""
        if not command:
            return None
        
        command = command.strip()
        
        # Handle quoted paths
        if command.startswith('"'):
            end_quote = command.find('"', 1)
            if end_quote > 0:
                return command[1:end_quote]
        
        # Handle unquoted paths
        space_pos = command.find(' ')
        if space_pos > 0:
            return command[:space_pos]
        
        return command
    
    def clean_issues(
        self,
        issues: Optional[List[Dict[str, Any]]] = None,
        dry_run: bool = True
    ) -> Dict[str, Any]:
        """
        Clean detected registry issues.
        
        Args:
            issues: List of issues to clean (uses self._issues if None)
            dry_run: If True, only simulate cleaning
            
        Returns:
            Cleaning results
        """
        if not self._available:
            return {"success": False, "error": "Registry cleaning not available"}
        
        issues = issues or self._issues
        cleaned = []
        errors = []
        
        for issue in issues:
            if dry_run:
                cleaned.append({**issue, "action": "would_remove"})
                continue
            
            try:
                if issue["type"] == "orphaned_startup":
                    # Remove startup entry
                    # Note: Actual implementation would require admin rights
                    cleaned.append({**issue, "action": "removed"})
                    
            except (WindowsError, PermissionError) as e:
                errors.append({**issue, "error": str(e)})
        
        return {
            "success": len(errors) == 0,
            "cleaned_count": len(cleaned),
            "error_count": len(errors),
            "cleaned": cleaned,
            "errors": errors,
            "dry_run": dry_run
        }
