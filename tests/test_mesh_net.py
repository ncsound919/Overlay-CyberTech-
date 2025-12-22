from mesh_net import get_mesh_net, mesh_net


def test_mesh_net_basic_structure():
    spec = get_mesh_net()

    assert "global_cybersecurity_mesh" in spec
    mesh = spec["global_cybersecurity_mesh"]

    assert mesh["network_metadata"]["network_name"] == "CyberSecMeshGlobal"
    assert mesh["architecture"]["topology"] == "hybrid_p2p_with_supernodes"
    assert "identity_fabric" in mesh["core_layers"]
    assert "peer_discovery" in mesh["network_protocols"]
    assert mesh["reputation_system"]["scoring"]["range"] == [0, 1]


def test_mesh_net_returns_copy():
    spec = get_mesh_net()
    spec["global_cybersecurity_mesh"]["network_metadata"]["network_name"] = "modified"

    original = mesh_net["global_cybersecurity_mesh"]["network_metadata"]["network_name"]
    assert original == "CyberSecMeshGlobal"
