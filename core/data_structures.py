"""
Step 2: High-Performance Data Architecture

Implements optimized data structures for O(1) access and real-time processing:
- Hash Maps for threat signature lookup (O(1) time complexity)
- Tries (Prefix Trees) for IP whitelisting/blacklisting and URL filtering
- Bloom Filters for rapid membership testing with low memory footprint
- Sets for instant membership checking

These structures enable real-time packet inspection and threat blocking
without the latency of iterating through lists during high-traffic attacks.
"""

import hashlib
import math
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field


# =============================================================================
# Hash Map for O(1) Threat Signature Lookup
# =============================================================================

@dataclass
class ThreatSignature:
    """Represents a threat signature entry."""
    cve_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    affected_versions: List[str]
    detection_pattern: str
    description: str = ""
    remediation: str = ""


class ThreatSignatureDB:
    """
    Hash Map based threat signature database.
    Provides O(1) lookup time regardless of database size.
    """
    
    def __init__(self):
        self._signatures: Dict[str, ThreatSignature] = {}
        self._hash_index: Dict[str, str] = {}  # file_hash -> cve_id
        self._ip_index: Dict[str, List[str]] = {}  # ip -> list of cve_ids
    
    def add_signature(self, signature: ThreatSignature) -> None:
        """Add a threat signature to the database. O(1)."""
        self._signatures[signature.cve_id] = signature
    
    def lookup_by_cve(self, cve_id: str) -> Optional[ThreatSignature]:
        """Lookup threat by CVE ID. O(1)."""
        return self._signatures.get(cve_id)
    
    def lookup_by_hash(self, file_hash: str) -> Optional[ThreatSignature]:
        """Lookup threat by file hash. O(1)."""
        cve_id = self._hash_index.get(file_hash)
        if cve_id:
            return self._signatures.get(cve_id)
        return None
    
    def add_hash_mapping(self, file_hash: str, cve_id: str) -> None:
        """Map a file hash to a CVE. O(1)."""
        self._hash_index[file_hash] = cve_id
    
    def add_ip_mapping(self, ip: str, cve_id: str) -> None:
        """Map an IP address to associated CVEs. O(1) amortized."""
        if ip not in self._ip_index:
            self._ip_index[ip] = []
        self._ip_index[ip].append(cve_id)
    
    def lookup_by_ip(self, ip: str) -> List[ThreatSignature]:
        """Get all threats associated with an IP. O(k) where k = threats per IP."""
        cve_ids = self._ip_index.get(ip, [])
        return [
            self._signatures[cve_id] 
            for cve_id in cve_ids 
            if cve_id in self._signatures
        ]
    
    def contains(self, cve_id: str) -> bool:
        """Check if CVE exists in database. O(1)."""
        return cve_id in self._signatures
    
    @property
    def size(self) -> int:
        """Return number of signatures in database."""
        return len(self._signatures)


# =============================================================================
# Trie (Prefix Tree) for IP/URL Filtering
# =============================================================================

class TrieNode:
    """A node in the Trie structure."""
    
    def __init__(self):
        self.children: Dict[str, 'TrieNode'] = {}
        self.is_terminal: bool = False
        self.data: Optional[Dict[str, Any]] = None


class IPTrie:
    """
    Trie-based IP address filtering structure.
    
    Optimized for:
    - IP whitelisting/blacklisting
    - CIDR range matching
    - O(k) lookup where k = number of octets (4 for IPv4)
    """
    
    def __init__(self):
        self.root = TrieNode()
        self._size = 0
    
    def insert(
        self,
        ip: str,
        threat_level: str = "UNKNOWN",
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Insert an IP address into the trie.
        O(k) where k = number of octets.
        """
        octets = ip.split('.')
        node = self.root
        
        for octet in octets:
            if octet not in node.children:
                node.children[octet] = TrieNode()
            node = node.children[octet]
        
        node.is_terminal = True
        node.data = {
            "ip": ip,
            "threat_level": threat_level,
            "metadata": metadata or {}
        }
        self._size += 1
    
    def lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Lookup an IP address in the trie.
        O(4) for IPv4 = O(1) constant time.
        """
        octets = ip.split('.')
        node = self.root
        
        for octet in octets:
            if octet not in node.children:
                return None
            node = node.children[octet]
        
        return node.data if node.is_terminal else None
    
    def contains(self, ip: str) -> bool:
        """Check if IP exists in trie. O(1) for IPv4."""
        return self.lookup(ip) is not None
    
    def prefix_match(self, ip_prefix: str) -> List[Dict[str, Any]]:
        """
        Find all IPs matching a prefix (e.g., "192.168").
        Useful for subnet-level blocking.
        """
        octets = ip_prefix.split('.')
        node = self.root
        
        for octet in octets:
            if octet not in node.children:
                return []
            node = node.children[octet]
        
        # Collect all terminal nodes under this prefix
        results = []
        self._collect_terminals(node, results)
        return results
    
    def _collect_terminals(
        self,
        node: TrieNode,
        results: List[Dict[str, Any]]
    ) -> None:
        """Recursively collect all terminal nodes."""
        if node.is_terminal and node.data:
            results.append(node.data)
        for child in node.children.values():
            self._collect_terminals(child, results)
    
    @property
    def size(self) -> int:
        """Return number of IPs in trie."""
        return self._size


class URLTrie:
    """
    Trie-based URL/domain filtering structure.
    
    Optimized for:
    - Domain blacklisting
    - URL pattern matching
    - O(k) lookup where k = number of path segments
    """
    
    def __init__(self):
        self.root = TrieNode()
        self._size = 0
    
    def insert(
        self,
        domain: str,
        is_blacklisted: bool = True,
        reason: str = ""
    ) -> None:
        """Insert a domain into the trie."""
        # Split domain into parts (reversed for tld-first matching)
        parts = domain.lower().split('.')
        parts.reverse()
        
        node = self.root
        for part in parts:
            if part not in node.children:
                node.children[part] = TrieNode()
            node = node.children[part]
        
        node.is_terminal = True
        node.data = {
            "domain": domain,
            "blacklisted": is_blacklisted,
            "reason": reason
        }
        self._size += 1
    
    def lookup(self, domain: str) -> Optional[Dict[str, Any]]:
        """Lookup a domain in the trie."""
        parts = domain.lower().split('.')
        parts.reverse()
        
        node = self.root
        for part in parts:
            if part not in node.children:
                return None
            node = node.children[part]
        
        return node.data if node.is_terminal else None
    
    def is_blacklisted(self, domain: str) -> bool:
        """Check if domain is blacklisted."""
        result = self.lookup(domain)
        return result.get("blacklisted", False) if result else False
    
    @property
    def size(self) -> int:
        """Return number of domains in trie."""
        return self._size


# =============================================================================
# Bloom Filter for Probabilistic Membership Testing
# =============================================================================

class BloomFilter:
    """
    Space-efficient probabilistic data structure for membership testing.
    
    Properties:
    - O(k) insert and lookup where k = number of hash functions
    - No false negatives (if reports absent, definitely absent)
    - Possible false positives (controlled by size and hash count)
    - Very memory efficient for large sets
    
    Ideal for:
    - Quick filtering of known-safe connections
    - Pre-filtering before expensive lookups
    - Memory-constrained environments
    """
    
    def __init__(
        self,
        expected_elements: int = 10000,
        false_positive_rate: float = 0.01
    ):
        """
        Initialize Bloom Filter with target parameters.
        
        Args:
            expected_elements: Expected number of elements to store
            false_positive_rate: Target false positive probability (0.01 = 1%)
        """
        # Calculate optimal size and hash count
        self._size = self._optimal_size(expected_elements, false_positive_rate)
        self._hash_count = self._optimal_hash_count(
            self._size, expected_elements
        )
        self._bit_array = [False] * self._size
        self._element_count = 0
    
    @staticmethod
    def _optimal_size(n: int, p: float) -> int:
        """Calculate optimal bit array size."""
        m = -(n * math.log(p)) / (math.log(2) ** 2)
        return int(m)
    
    @staticmethod
    def _optimal_hash_count(m: int, n: int) -> int:
        """Calculate optimal number of hash functions."""
        k = (m / n) * math.log(2)
        return max(1, int(k))
    
    def _get_hash_values(self, item: str) -> List[int]:
        """Generate k hash values for an item using SHA-256 based double hashing."""
        hashes = []
        # Use SHA-256 derivatives for both hash functions (security-safe)
        h1_bytes = hashlib.sha256(item.encode()).digest()
        h2_bytes = hashlib.sha256(b"secondary_" + item.encode()).digest()
        h1 = int.from_bytes(h1_bytes[:16], 'big')
        h2 = int.from_bytes(h2_bytes[:16], 'big')
        
        for i in range(self._hash_count):
            # Double hashing technique with SHA-256 derivatives
            combined = (h1 + i * h2) % self._size
            hashes.append(combined)
        return hashes
    
    def add(self, item: str) -> None:
        """Add an item to the filter. O(k)."""
        for index in self._get_hash_values(item):
            self._bit_array[index] = True
        self._element_count += 1
    
    def contains(self, item: str) -> bool:
        """
        Check if item might be in the filter. O(k).
        
        Returns:
            False = definitely not in filter
            True = probably in filter (may be false positive)
        """
        return all(
            self._bit_array[index] 
            for index in self._get_hash_values(item)
        )
    
    def __contains__(self, item: str) -> bool:
        """Enable 'in' operator."""
        return self.contains(item)
    
    @property
    def estimated_false_positive_rate(self) -> float:
        """Calculate current false positive rate."""
        filled = sum(self._bit_array)
        if filled == 0:
            return 0.0
        return (filled / self._size) ** self._hash_count
    
    @property
    def element_count(self) -> int:
        """Return number of elements added."""
        return self._element_count


# =============================================================================
# Set-based Membership Testing
# =============================================================================

class ConnectionSet:
    """
    Set-based structure for tracking active connections.
    Provides O(1) membership testing for known connections.
    """
    
    def __init__(self):
        self._safe_connections: Set[str] = set()
        self._malicious_connections: Set[str] = set()
        self._pending_connections: Set[str] = set()
    
    def add_safe(self, connection_id: str) -> None:
        """Mark a connection as safe. O(1)."""
        self._safe_connections.add(connection_id)
        self._malicious_connections.discard(connection_id)
        self._pending_connections.discard(connection_id)
    
    def add_malicious(self, connection_id: str) -> None:
        """Mark a connection as malicious. O(1)."""
        self._malicious_connections.add(connection_id)
        self._safe_connections.discard(connection_id)
        self._pending_connections.discard(connection_id)
    
    def add_pending(self, connection_id: str) -> None:
        """Mark a connection as pending analysis. O(1)."""
        if connection_id not in self._safe_connections and \
           connection_id not in self._malicious_connections:
            self._pending_connections.add(connection_id)
    
    def is_safe(self, connection_id: str) -> bool:
        """Check if connection is known safe. O(1)."""
        return connection_id in self._safe_connections
    
    def is_malicious(self, connection_id: str) -> bool:
        """Check if connection is known malicious. O(1)."""
        return connection_id in self._malicious_connections
    
    def is_pending(self, connection_id: str) -> bool:
        """Check if connection is pending analysis. O(1)."""
        return connection_id in self._pending_connections
    
    def get_status(self, connection_id: str) -> str:
        """Get connection status. O(1)."""
        if connection_id in self._safe_connections:
            return "SAFE"
        if connection_id in self._malicious_connections:
            return "MALICIOUS"
        if connection_id in self._pending_connections:
            return "PENDING"
        return "UNKNOWN"
    
    def remove(self, connection_id: str) -> None:
        """Remove a connection from all sets. O(1)."""
        self._safe_connections.discard(connection_id)
        self._malicious_connections.discard(connection_id)
        self._pending_connections.discard(connection_id)
    
    @property
    def stats(self) -> Dict[str, int]:
        """Return connection statistics."""
        return {
            "safe": len(self._safe_connections),
            "malicious": len(self._malicious_connections),
            "pending": len(self._pending_connections),
            "total": (
                len(self._safe_connections) + 
                len(self._malicious_connections) + 
                len(self._pending_connections)
            )
        }
