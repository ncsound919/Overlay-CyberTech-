"""
Global Cybersecurity Mesh specification.

This module exposes the full problem statement as a structured dictionary so it
can be consumed programmatically.
"""

from copy import deepcopy
import json


_GLOBAL_CYBERSECURITY_MESH_JSON = """{
  "global_cybersecurity_mesh": {
    "network_metadata": {
      "version": "1.0.0",
      "creation_date": "2025-12-22",
      "network_name": "CyberSecMeshGlobal",
      "description": "Decentralized cybersecurity mesh with integrated social networking for threat intelligence sharing"
    },
    "architecture": {
      "type": "cybersecurity_mesh_with_social_layer",
      "topology": "hybrid_p2p_with_supernodes",
      "governance": "decentralized_with_federated_consensus",
      "identity_model": "self_sovereign_with_reputation"
    },
    "core_layers": {
      "identity_fabric": {
        "authentication": "multi_factor_cryptographic",
        "identity_type": "pseudonymous_with_verifiable_credentials",
        "key_management": "distributed_with_hardware_enclaves",
        "revocation": "immediate_with_global_consensus",
        "privacy_level": "zero_knowledge_proofs"
      },
      "communication_mesh": {
        "protocol": "quantum_resistant_encryption",
        "routing": "onion_routing_with_source_routing",
        "message_types": ["threat_intel", "file_share", "social_update", "emergency_alert"],
        "bandwidth_sharing": "incentivized_with_tokens",
        "relay_nodes": "auto_selected_based_on_reputation"
      },
      "social_networking": {
        "feed_structure": "twitter_like_with_threading",
        "content_types": ["threat_reports", "mitigation_strategies", "file_shares", "discussions"],
        "interaction_mechanisms": ["like", "share", "validate", "comment", "endorse"],
        "reputation_integration": "weighted_interactions",
        "moderation": "community_driven_with_ai_assistance"
      },
      "threat_intelligence": {
        "data_format": "STIX_TAXII_3.0_compatible",
        "validation": "multi_peer_consensus_with_ai_correlation",
        "scoring": "cvss_with_community_adjustment",
        "expiration": "dynamic_based_on_activity_and_relevance",
        "attribution": "optional_anonymous_with_reputation_link"
      },
      "file_sharing": {
        "storage_model": "distributed_encrypted_sharding",
        "access_control": "attribute_based_encryption",
        "integrity": "merkle_trees_with_blockchain_anchor",
        "retention": "configurable_with_automatic_cleanup",
        "virus_scanning": "distributed_multi_engine"
      }
    },
    "network_protocols": {
      "peer_discovery": {
        "method": "DHT_with_geographic_affinity",
        "bootstrap": "trusted_seed_nodes_rotating",
        "peer_selection": "reputation_weighted_random",
        "connection_limits": "adaptive_based_on_capacity",
        "NAT_traversal": "automatic_with_STUN_TURN"
      },
      "consensus_mechanisms": {
        "threat_validation": "practical_byzantine_fault_tolerance",
        "network_governance": "delegated_stake_with_reputation",
        "emergency_decisions": "faster_consensus_with_higher_threshold",
        "fork_resolution": "longest_reputation_chain_wins",
        "slashing_conditions": ["false_threat_reports", "network_sabotage", "privacy_breaches"]
      },
      "security_protocols": {
        "encryption": "AES_256_with_post_quantum_signatures",
        "perfect_forward_secrecy": "ephemeral_keys_rotated_hourly",
        "authentication": "mutual_with_certificate_pinning",
        "DDoS_protection": "adaptive_rate_limiting_with_proof_of_work",
        "privacy_preservation": "differential_privacy_for_aggregates"
      }
    },
    "reputation_system": {
      "factors": {
        "threat_accuracy": {"weight": 0.35, "calculation": "validated_reports / total_reports"},
        "contribution_quality": {"weight": 0.25, "calculation": "peer_ratings_weighted_by_reviewer_reputation"},
        "network_participation": {"weight": 0.20, "calculation": "uptime_bandwidth_shared_helpfulness"},
        "longevity": {"weight": 0.10, "calculation": "time_since_first_verified_contribution"},
        "community_building": {"weight": 0.10, "calculation": "referrals_mentorship_discussion_value"}
      },
      "scoring": {
        "range": [0, 1],
        "decay": "exponential_half_life_30_days",
        "recalculation": "real_time_with_hourly_aggregation",
        "minimum_for_participation": 0.6,
        "maximum_penalty": 0.5
      },
      "rewards": {
        "threat_intelligence_access": "tiered_by_reputation",
        "file_sharing_priority": "bandwidth_allocation_based",
        "governance_voting": "quadratic_with_reputation_cap",
        "token_rewards": "monthly_distribution_based_on_contribution",
        "premium_features": "early_access_for_top_10_percent"
      }
    },
    "data_structures": {
      "user_profile": {
        "public_fields": ["reputation_score", "contribution_count", "specialization_tags", "join_date"],
        "private_fields": ["real_identity", "contact_info", "organization"],
        "encrypted_fields": ["private_keys", "personal_preferences"],
        "mutable_fields": ["specialization_tags", "preferences", "contact_methods"],
        "immutable_fields": ["join_date", "initial_reputation", "genesis_contribution"]
      },
      "threat_intel_package": {
        "required_fields": ["threat_type", "severity_score", "indicators", "confidence_level"],
        "optional_fields": ["mitigation_steps", "affected_systems", "attribution_data"],
        "metadata": ["submitter_reputation", "validation_status", "community_score"],
        "attachments": ["file_hashes", "pcap_files", "malware_samples"],
        "temporal_data": {"created": "timestamp", "expires": "auto_calculated", "last_updated": "timestamp"}
      },
      "social_post": {
        "content_types": ["text", "threat_report", "file_share", "poll", "emergency_alert"],
        "visibility": ["public", "connections_only", "regional", "expert_circle"],
        "interaction_data": ["likes", "shares", "validations", "comments_thread"],
        "context_links": ["related_threats", "previous_discussions", "external_references"],
        "moderation_status": ["pending", "approved", "flagged", "removed"]
      }
    },
    "network_governance": {
      "decision_making": {
        "policy_changes": "supermajority_75_percent_with_reputation_quorum",
        "emergency_response": "core_developer_team_with_community_ratification",
        "dispute_resolution": "elected_arbitration_panel_with_appeal_process",
        "fork_management": "social_contract_with_technical_migration_plan"
      },
      "compliance": {
        "data_protection": "GDPR_compliant_with_privacy_by_design",
        "cross_border_transfer": "encrypted_with_local_processing_options",
        "audit_requirements": "transparent_logging_with_selective_disclosure",
        "legal_jurisdiction": "distributed_with_arbitration_clause"
      }
    },
    "incentive_mechanisms": {
      "token_economics": {
        "token_name": "CyberSecMeshToken",
        "distribution": "fair_launch_with_mining_period",
        "utility": ["bandwidth_purchase", "premium_features", "governance_voting", "priority_access"],
        "inflation": "controlled_with_annual_halving",
        "value_accrual": "transaction_fees_burn_mechanism"
      },
      "non_monetary_incentives": {
        "recognition": ["leaderboards", "badges", "expert_status", "community_highlights"],
        "access": ["exclusive_threat_feeds", "early_feature_access", "direct_communication_with_experts"],
        "influence": ["governance_participation", "feature_voting", "policy_input", "moderator_status"]
      }
    },
    "scalability_solutions": {
      "horizontal_scaling": {
        "sharding": "geographic_and_threat_type_based",
        "load_balancing": "intelligent_with_latency_optimization",
        "storage": "distributed_with_redundancy_factor_3",
        "compute": "edge_computing_with_cloud_backup"
      },
      "performance_optimization": {
        "caching": "multi_level_with_intelligent_invalidation",
        "compression": "adaptive_based_on_content_type",
        "batching": "intelligent_with_latency_tradeoffs",
        "prefetching": "predictive_based_on_user_patterns"
      }
    },
    "security_measures": {
      "attack_resistance": {
        "sybil_attack": "economic_barrier_with_reputation_requirement",
        "eclipse_attack": "diverse_peer_selection_with_randomization",
        "routing_attack": "multiple_path_validation_with_consensus",
        "data_poisoning": "multi_validation_with_statistical_detection",
        "privacy_attacks": "differential_privacy_with_noise_injection"
      },
      "incident_response": {
        "detection": "real_time_monitoring_with_ml_anomaly_detection",
        "containment": "automatic_isolation_with_manual_override",
        "recovery": "automated_backup_with_consensus_restoration",
        "post_mortem": "transparent_reporting_with_community_input"
      }
    },
    "integration_interfaces": {
      "APIs": {
        "REST_API": "full_functionality_with_rate_limiting",
        "GraphQL": "flexible_queries_with_field_level_security",
        "Webhooks": "real_time_notifications_with_signature_verification",
        "WebSocket": "live_updates_with_authentication"
      },
      "external_integrations": {
        "SIEM_systems": "standardized_connectors_with_field_mapping",
        "threat_feeds": "STIX_TAXII_compatible_with_scheduled_sync",
        "identity_providers": "SAML_OIDC_with_attribute_mapping",
        "storage_systems": "encrypted_backup_with_version_control"
      }
    },
    "monitoring_analytics": {
      "network_health": {
        "peer_connectivity": "continuous_with_geographic_heatmap",
        "message_propagation": "latency_and_success_rate_tracking",
        "storage_utilization": "distributed_with_imbalance_alerts",
        "bandwidth_usage": "per_node_with_fairness_metrics"
      },
      "security_metrics": {
        "threat_detection_rate": "true_positive_and_false_positive_tracking",
        "response_time": "incident_to_resolution_with_escalation_tracking",
        "user_behavior": "anomaly_detection_with_privacy_preservation",
        "attack_attempts": "categorized_with_success_rate_analysis"
      },
      "community_metrics": {
        "engagement": "posts_comments_validations_with_trend_analysis",
        "growth": "new_users_with_retention_and_churn_rates",
        "quality": "content_evaluation_with_reputation_correlation",
        "satisfaction": "periodic_surveys_with_anonymous_feedback"
      }
    },
    "deployment_specifications": {
      "node_requirements": {
        "minimum_hardware": {"cpu": "2_cores", "memory": "4GB", "storage": "100GB", "bandwidth": "10Mbps"},
        "recommended_hardware": {"cpu": "4_cores", "memory": "8GB", "storage": "500GB", "bandwidth": "100Mbps"},
        "supported_platforms": ["linux_x64", "windows_x64", "macOS", "docker_containers"],
        "security_requirements": ["trusted_platform_module", "secure_boot", "encrypted_storage"]
      },
      "network_bootstrap": {
        "seed_nodes": ["seed1.cybersecmesh.global", "seed2.cybersecmesh.global", "seed3.cybersecmesh.global"],
        "genesis_parameters": {"initial_reputation": 0.5, "token_allocation": "fair_distribution", "governance_setup": "temporary_core_team"},
        "initial_policies": {"data_retention": "90_days_default", "encryption_level": "maximum", "validation_threshold": "3_peer_minimum"}
      }
    }
  }
}"""


_GLOBAL_CYBERSECURITY_MESH = json.loads(_GLOBAL_CYBERSECURITY_MESH_JSON)
global_cybersecurity_mesh = _GLOBAL_CYBERSECURITY_MESH["global_cybersecurity_mesh"]
GLOBAL_CYBERSECURITY_MESH = global_cybersecurity_mesh


def get_global_cybersecurity_mesh(include_wrapper: bool = False):
    """
    Return the global cybersecurity mesh specification.

    Args:
        include_wrapper: When True, include the top-level wrapper key
            ``global_cybersecurity_mesh``. When False (default), returns the
            inner mesh specification dictionary.

    Returns:
        A deep copy of the requested specification dictionary.
    """
    data = _GLOBAL_CYBERSECURITY_MESH if include_wrapper else global_cybersecurity_mesh
    return deepcopy(data)
