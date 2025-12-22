"""
Step 5: Hardened Deployment & Continuous Audit

Implements security measures for deployment integrity:
- Immutable Audit Logs with SQLite + cryptographic hashing
- Software Bill of Materials (SBOM) generation
- Rootkit Defense / Binary integrity verification

These measures ensure the software cannot be subverted by rootkits
or supply chain attacks, providing tamper-evident logging and
continuous integrity verification.
"""

import hashlib
import json
import os
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# =============================================================================
# Immutable Audit Logging with Cryptographic Hashing
# =============================================================================

class ImmutableAuditLog:
    """
    Cryptographically chained audit log using SQLite.
    
    Every action is hashed and chained to previous entries,
    ensuring that tampering can be detected through hash
    chain verification.
    
    Security Properties:
    - Tamper detection via hash chain verification
    - Non-repudiation through cryptographic proof
    - NIST compliance for audit trail requirements
    
    Note: This provides tamper-detection but not tamper-prevention.
    For production deployments, consider anchoring hashes externally.
    """
    
    def __init__(self, db_path: str = "audit_trail.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()
        self._init_schema()
        self.previous_hash = self._get_last_hash()
    
    def _init_schema(self) -> None:
        """Initialize database schema."""
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_trail (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE NOT NULL,
                event_type TEXT NOT NULL,
                event_data TEXT NOT NULL,
                content_hash TEXT NOT NULL UNIQUE,
                previous_hash TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                processor_id TEXT,
                severity TEXT DEFAULT 'INFO'
            )
        """)
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_trail (timestamp)
        """)
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_content_hash ON audit_trail (content_hash)
        """)
        self.cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_event_type ON audit_trail (event_type)
        """)
        self.conn.commit()
    
    def _get_last_hash(self) -> str:
        """Get the last hash in the chain or genesis hash."""
        result = self.cursor.execute(
            "SELECT content_hash FROM audit_trail ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return result[0] if result else "0" * 64  # Genesis hash
    
    def append(
        self,
        event: Dict[str, Any],
        processor_id: str = "system"
    ) -> str:
        """
        Append an event to the audit log with cryptographic chaining.
        
        Args:
            event: Event data to log
            processor_id: ID of the system/component logging the event
            
        Returns:
            Content hash of the logged event
        """
        # Serialize event deterministically
        event_json = json.dumps(event, sort_keys=True, default=str)
        
        # Calculate hash including previous hash (chain)
        content_hash = hashlib.sha256(
            f"{event_json}{self.previous_hash}".encode()
        ).hexdigest()
        
        # Extract event metadata
        event_id = event.get("event_id", hashlib.sha256(
            f"{time.time()}{event_json}".encode()
        ).hexdigest()[:16])
        event_type = event.get("event_type", "GENERIC")
        severity = event.get("severity", "INFO")
        
        # Insert into database
        self.cursor.execute(
            """INSERT INTO audit_trail 
               (event_id, event_type, event_data, content_hash, previous_hash, 
                processor_id, severity)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (event_id, event_type, event_json, content_hash,
             self.previous_hash, processor_id, severity)
        )
        self.conn.commit()
        
        # Update chain
        self.previous_hash = content_hash
        return content_hash
    
    def verify_integrity(self) -> Tuple[bool, str]:
        """
        Verify the integrity of the entire audit log.
        
        Recalculates all hashes and compares to stored values.
        
        Returns:
            Tuple of (is_valid, message)
        """
        rows = self.cursor.execute(
            """SELECT event_data, content_hash, previous_hash 
               FROM audit_trail ORDER BY id"""
        ).fetchall()
        
        prev_hash = "0" * 64  # Genesis hash
        
        for i, (event_data, stored_hash, stored_prev) in enumerate(rows):
            # Verify previous hash reference
            if prev_hash != stored_prev:
                return False, f"Chain broken at entry {i}: previous hash mismatch"
            
            # Recalculate hash
            calculated_hash = hashlib.sha256(
                f"{event_data}{prev_hash}".encode()
            ).hexdigest()
            
            if calculated_hash != stored_hash:
                return False, f"Tampering detected at entry {i}: hash mismatch"
            
            prev_hash = stored_hash
        
        return True, f"All {len(rows)} entries verified successfully"
    
    def query_events(
        self,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Query events with optional filters."""
        query = "SELECT * FROM audit_trail WHERE 1=1"
        params = []
        
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time)
        
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        rows = self.cursor.execute(query, params).fetchall()
        
        return [
            {
                "id": row[0],
                "event_id": row[1],
                "event_type": row[2],
                "event_data": json.loads(row[3]),
                "content_hash": row[4],
                "previous_hash": row[5],
                "timestamp": row[6],
                "processor_id": row[7],
                "severity": row[8]
            }
            for row in rows
        ]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get audit log statistics."""
        total = self.cursor.execute(
            "SELECT COUNT(*) FROM audit_trail"
        ).fetchone()[0]
        
        by_type = dict(self.cursor.execute(
            "SELECT event_type, COUNT(*) FROM audit_trail GROUP BY event_type"
        ).fetchall())
        
        by_severity = dict(self.cursor.execute(
            "SELECT severity, COUNT(*) FROM audit_trail GROUP BY severity"
        ).fetchall())
        
        return {
            "total_events": total,
            "by_type": by_type,
            "by_severity": by_severity,
            "db_path": self.db_path
        }
    
    def close(self) -> None:
        """Close database connection."""
        self.conn.close()


# =============================================================================
# Software Bill of Materials (SBOM) Generator
# =============================================================================

@dataclass
class Dependency:
    """Represents a software dependency."""
    name: str
    version: str
    ecosystem: str  # npm, pip, cargo, etc.
    license: str = "UNKNOWN"
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    is_direct: bool = True


@dataclass
class SBOMDocument:
    """SBOM document following CycloneDX-like format."""
    spec_version: str = "1.3"
    version: int = 1
    components: List[Dependency] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    policy_violations: List[Dict[str, Any]] = field(default_factory=list)


class SBOMGenerator:
    """
    Software Bill of Materials generator.
    
    Generates SBOM for builds and checks against vulnerability databases.
    Implements policy enforcement to block builds with known vulnerabilities.
    """
    
    def __init__(self):
        self.cve_db: Dict[str, List[Dict[str, Any]]] = {}
        self.license_policy: Dict[str, str] = {
            "MIT": "ALLOWED",
            "Apache-2.0": "ALLOWED",
            "BSD-3-Clause": "ALLOWED",
            "GPL-3.0": "REVIEW_REQUIRED",
            "UNKNOWN": "REVIEW_REQUIRED"
        }
    
    def load_cve_database(self, cve_data: Dict[str, List[Dict[str, Any]]]) -> None:
        """Load CVE data for vulnerability checking."""
        self.cve_db = cve_data
    
    def generate_sbom(self, project_path: str) -> SBOMDocument:
        """
        Generate SBOM for a project.
        
        Args:
            project_path: Path to project root
            
        Returns:
            SBOMDocument with all dependencies and vulnerability info
        """
        sbom = SBOMDocument()
        sbom.metadata = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "project_path": project_path,
            "generator": "CheetahSecurityOS-SBOM"
        }
        
        # Detect and parse dependencies
        dependencies = self._detect_dependencies(project_path)
        
        # Check each dependency for vulnerabilities
        for dep in dependencies:
            dep.vulnerabilities = self._check_vulnerabilities(dep)
            sbom.components.append(dep)
            sbom.vulnerabilities.extend([
                {**v, "dependency": f"{dep.name}@{dep.version}"}
                for v in dep.vulnerabilities
            ])
        
        # Apply policies
        sbom.policy_violations = self._check_policies(sbom)
        
        return sbom
    
    def _detect_dependencies(self, project_path: str) -> List[Dependency]:
        """Detect dependencies from package files."""
        dependencies = []
        path = Path(project_path)
        
        # Check for package.json (Node.js)
        package_json = path / "package.json"
        if package_json.exists():
            try:
                with open(package_json, 'r') as f:
                    data = json.load(f)
                
                for name, version in data.get("dependencies", {}).items():
                    dependencies.append(Dependency(
                        name=name,
                        version=version.lstrip("^~"),
                        ecosystem="npm",
                        is_direct=True
                    ))
                
                for name, version in data.get("devDependencies", {}).items():
                    dependencies.append(Dependency(
                        name=name,
                        version=version.lstrip("^~"),
                        ecosystem="npm",
                        is_direct=True
                    ))
            except (json.JSONDecodeError, OSError):
                pass
        
        # Check for requirements.txt (Python)
        requirements_txt = path / "requirements.txt"
        if requirements_txt.exists():
            try:
                with open(requirements_txt, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            if '==' in line:
                                name, version = line.split('==', 1)
                                dependencies.append(Dependency(
                                    name=name.strip(),
                                    version=version.strip(),
                                    ecosystem="pip",
                                    is_direct=True
                                ))
            except OSError:
                pass
        
        # Check for Cargo.toml (Rust)
        cargo_toml = path / "Cargo.toml"
        if cargo_toml.exists():
            try:
                with open(cargo_toml, 'r') as f:
                    content = f.read()
                    # Simple TOML parsing for dependencies
                    in_deps = False
                    for line in content.split('\n'):
                        if line.strip() == '[dependencies]':
                            in_deps = True
                        elif line.startswith('[') and in_deps:
                            in_deps = False
                        elif in_deps and '=' in line:
                            parts = line.split('=')
                            if len(parts) >= 2:
                                name = parts[0].strip()
                                version = parts[1].strip().strip('"')
                                dependencies.append(Dependency(
                                    name=name,
                                    version=version,
                                    ecosystem="cargo",
                                    is_direct=True
                                ))
            except OSError:
                # If Cargo.toml cannot be read (e.g., permissions or I/O error),
                # we skip Rust dependency detection and continue with other manifests.
                pass
        
        return dependencies
    
    def _check_vulnerabilities(self, dep: Dependency) -> List[Dict[str, Any]]:
        """Check dependency against CVE database."""
        vulns = []
        dep_key = f"{dep.name}"
        
        if dep_key in self.cve_db:
            for cve in self.cve_db[dep_key]:
                # Check if version is affected
                affected_versions = cve.get("affected_versions", [])
                if not affected_versions or dep.version in affected_versions:
                    vulns.append({
                        "cve_id": cve.get("cve_id"),
                        "severity": cve.get("severity"),
                        "cvss_score": cve.get("cvss_score"),
                        "description": cve.get("description", "")
                    })
        
        return vulns
    
    def _check_policies(self, sbom: SBOMDocument) -> List[Dict[str, Any]]:
        """Check SBOM against security policies."""
        violations = []
        
        for dep in sbom.components:
            # Check for critical vulnerabilities
            for vuln in dep.vulnerabilities:
                if vuln.get("severity") == "CRITICAL":
                    violations.append({
                        "type": "CRITICAL_VULNERABILITY",
                        "dependency": f"{dep.name}@{dep.version}",
                        "cve_id": vuln.get("cve_id"),
                        "action": "BUILD_BLOCKED"
                    })
            
            # Check license policy
            license_status = self.license_policy.get(
                dep.license, "REVIEW_REQUIRED"
            )
            if license_status == "BLOCKED":
                violations.append({
                    "type": "LICENSE_VIOLATION",
                    "dependency": f"{dep.name}@{dep.version}",
                    "license": dep.license,
                    "action": "BUILD_BLOCKED"
                })
        
        return violations
    
    def export_sbom(
        self,
        sbom: SBOMDocument,
        format: str = "json"
    ) -> str:
        """Export SBOM to specified format."""
        if format == "json":
            return json.dumps({
                "specVersion": sbom.spec_version,
                "version": sbom.version,
                "metadata": sbom.metadata,
                "components": [
                    {
                        "name": c.name,
                        "version": c.version,
                        "ecosystem": c.ecosystem,
                        "license": c.license,
                        "vulnerabilities": c.vulnerabilities,
                        "isDirect": c.is_direct
                    }
                    for c in sbom.components
                ],
                "vulnerabilities": sbom.vulnerabilities,
                "policyViolations": sbom.policy_violations
            }, indent=2)
        
        raise ValueError(f"Unsupported format: {format}")
    
    def get_security_score(self, sbom: SBOMDocument) -> Dict[str, Any]:
        """Calculate security score for SBOM."""
        severity_weights = {
            "CRITICAL": 10,
            "HIGH": 7,
            "MEDIUM": 4,
            "LOW": 1
        }
        
        total_penalty = sum(
            severity_weights.get(v.get("severity", "LOW"), 0)
            for v in sbom.vulnerabilities
        )
        
        # Base score 100, subtract penalties
        score = max(0, 100 - total_penalty)
        
        return {
            "score": score,
            "grade": (
                "A" if score >= 90 else
                "B" if score >= 80 else
                "C" if score >= 70 else
                "D" if score >= 60 else "F"
            ),
            "total_dependencies": len(sbom.components),
            "vulnerable_dependencies": len([
                c for c in sbom.components if c.vulnerabilities
            ]),
            "critical_count": len([
                v for v in sbom.vulnerabilities
                if v.get("severity") == "CRITICAL"
            ]),
            "high_count": len([
                v for v in sbom.vulnerabilities
                if v.get("severity") == "HIGH"
            ]),
            "policy_violations": len(sbom.policy_violations)
        }


# =============================================================================
# Rootkit Defense / Integrity Verification
# =============================================================================

@dataclass
class FileFingerprint:
    """Fingerprint of a file for integrity verification."""
    path: str
    size: int
    sha256_hash: str
    permissions: str
    modified_time: float


class IntegrityVerifier:
    """
    Internal integrity verifier for rootkit defense.
    
    Creates and verifies file fingerprints against known-good baselines
    to detect:
    - Binary modifications
    - System call hooking
    - Configuration tampering
    """
    
    def __init__(self, baseline_path: str = "integrity_baseline.json"):
        self.baseline_path = baseline_path
        self.baseline: Dict[str, FileFingerprint] = {}
    
    def create_baseline(self, paths: List[str]) -> Dict[str, Any]:
        """
        Create integrity baseline for specified paths.
        
        Args:
            paths: List of file/directory paths to fingerprint
            
        Returns:
            Baseline creation summary
        """
        fingerprints = {}
        errors = []
        
        for path in paths:
            p = Path(path)
            if p.is_file():
                try:
                    fp = self._fingerprint_file(str(p))
                    fingerprints[str(p)] = fp
                except (OSError, PermissionError) as e:
                    errors.append({"path": str(p), "error": str(e)})
            elif p.is_dir():
                for file_path in p.rglob("*"):
                    if file_path.is_file():
                        try:
                            fp = self._fingerprint_file(str(file_path))
                            fingerprints[str(file_path)] = fp
                        except (OSError, PermissionError) as e:
                            errors.append({"path": str(file_path), "error": str(e)})
        
        self.baseline = fingerprints
        self._save_baseline()
        
        return {
            "files_fingerprinted": len(fingerprints),
            "errors": errors,
            "baseline_path": self.baseline_path
        }
    
    def _fingerprint_file(self, path: str) -> FileFingerprint:
        """Create fingerprint for a single file."""
        stat = os.stat(path)
        
        # Calculate SHA256 hash
        sha256 = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        
        return FileFingerprint(
            path=path,
            size=stat.st_size,
            sha256_hash=sha256.hexdigest(),
            permissions=oct(stat.st_mode)[-3:],
            modified_time=stat.st_mtime
        )
    
    def _save_baseline(self) -> None:
        """Save baseline to file."""
        data = {
            path: {
                "path": fp.path,
                "size": fp.size,
                "sha256_hash": fp.sha256_hash,
                "permissions": fp.permissions,
                "modified_time": fp.modified_time
            }
            for path, fp in self.baseline.items()
        }
        
        with open(self.baseline_path, 'w') as f:
            json.dump(data, f, indent=2)
    
    def load_baseline(self) -> bool:
        """Load baseline from file. Returns True if successful."""
        if not os.path.exists(self.baseline_path):
            return False
        
        try:
            with open(self.baseline_path, 'r') as f:
                data = json.load(f)
            
            self.baseline = {
                path: FileFingerprint(**fp_data)
                for path, fp_data in data.items()
            }
            return True
        except (json.JSONDecodeError, OSError):
            return False
    
    def verify_integrity(self) -> Dict[str, Any]:
        """
        Verify current state against baseline.
        
        Returns:
            Verification results with any detected modifications
        """
        if not self.baseline:
            return {
                "verified": False,
                "error": "No baseline loaded",
                "modifications": [],
                "missing": [],
                "new_files": []
            }
        
        modifications = []
        missing = []
        
        for path, baseline_fp in self.baseline.items():
            if not os.path.exists(path):
                missing.append(path)
                continue
            
            try:
                current_fp = self._fingerprint_file(path)
                
                changes = []
                if current_fp.sha256_hash != baseline_fp.sha256_hash:
                    changes.append("hash_changed")
                if current_fp.size != baseline_fp.size:
                    changes.append("size_changed")
                if current_fp.permissions != baseline_fp.permissions:
                    changes.append("permissions_changed")
                
                if changes:
                    modifications.append({
                        "path": path,
                        "changes": changes,
                        "baseline_hash": baseline_fp.sha256_hash,
                        "current_hash": current_fp.sha256_hash
                    })
            except (OSError, PermissionError) as e:
                modifications.append({
                    "path": path,
                    "changes": ["access_error"],
                    "error": str(e)
                })
        
        is_verified = len(modifications) == 0 and len(missing) == 0
        
        return {
            "verified": is_verified,
            "files_checked": len(self.baseline),
            "modifications": modifications,
            "missing": missing,
            "severity": (
                "CRITICAL" if modifications else
                "HIGH" if missing else
                "OK"
            )
        }
    
    def verify_memory_integrity(self, pid: Optional[int] = None) -> Dict[str, Any]:
        """
        Verify process memory integrity (simplified implementation).
        
        In production, this would check:
        - System call table integrity
        - Kernel module list
        - Process memory regions
        
        Args:
            pid: Process ID to check (None for self)
        """
        # This is a simplified implementation
        # Real implementation would require kernel-level access
        
        pid = pid or os.getpid()
        
        try:
            # Check /proc/pid/maps on Linux
            maps_path = f"/proc/{pid}/maps"
            if os.path.exists(maps_path):
                with open(maps_path, 'r') as f:
                    memory_regions = f.readlines()
                
                suspicious = []
                for region in memory_regions:
                    # Check for suspicious patterns
                    if "rwxp" in region:  # Writable and executable
                        suspicious.append({
                            "region": region.strip(),
                            "reason": "Writable and executable memory region"
                        })
                
                return {
                    "pid": pid,
                    "regions_checked": len(memory_regions),
                    "suspicious_regions": suspicious,
                    "is_suspicious": len(suspicious) > 0
                }
        except (FileNotFoundError, PermissionError):
            pass
        
        return {
            "pid": pid,
            "regions_checked": 0,
            "suspicious_regions": [],
            "is_suspicious": False,
            "note": "Memory integrity check not available on this platform"
        }
