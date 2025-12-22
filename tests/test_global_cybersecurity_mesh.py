import json
import pytest

from core.global_cybersecurity_mesh import (
    GLOBAL_CYBERSECURITY_MESH,
    get_global_cybersecurity_mesh,
    global_cybersecurity_mesh,
)


def test_global_mesh_top_level_keys():
    mesh = get_global_cybersecurity_mesh()
    assert mesh["network_metadata"]["network_name"] == "CyberSecMeshGlobal"
    assert mesh["architecture"]["topology"] == "hybrid_p2p_with_supernodes"
    assert "identity_fabric" in mesh["core_layers"]
    assert "peer_discovery" in mesh["network_protocols"]
    assert "token_economics" in mesh["incentive_mechanisms"]


def test_wrapper_option_returns_full_structure():
    wrapped = get_global_cybersecurity_mesh(include_wrapper=True)
    assert "global_cybersecurity_mesh" in wrapped
    assert wrapped["global_cybersecurity_mesh"]["reputation_system"]["factors"]["threat_accuracy"]["weight"] == pytest.approx(
        0.35
    )


def test_constants_are_synced():
    assert json.dumps(GLOBAL_CYBERSECURITY_MESH, sort_keys=True) == json.dumps(
        global_cybersecurity_mesh, sort_keys=True
    )
    node_requirements = GLOBAL_CYBERSECURITY_MESH["deployment_specifications"]["node_requirements"]
    assert node_requirements["minimum_hardware"]["cpu"] == "2_cores"


def test_getter_returns_deep_copy():
    mesh = get_global_cybersecurity_mesh()
    mesh["network_metadata"]["network_name"] = "MutatedMesh"

    assert GLOBAL_CYBERSECURITY_MESH["network_metadata"]["network_name"] == "CyberSecMeshGlobal"
    assert global_cybersecurity_mesh["network_metadata"]["network_name"] == "CyberSecMeshGlobal"
