import pytest
from types import SimpleNamespace

import mesh_net as mn
from mesh_net import get_mesh_net, mesh_net


@pytest.fixture
def reset_mesh_cache(monkeypatch):
    monkeypatch.setattr(mn, "_mesh_net_cache", None)


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


def test_mesh_net_module_attribute_and_invalid():
    spec_attr = mn.mesh_net
    spec_attr["global_cybersecurity_mesh"]["architecture"]["topology"] = "changed"

    assert (
        mn.get_mesh_net()["global_cybersecurity_mesh"]["architecture"]["topology"]
        == "hybrid_p2p_with_supernodes"
    )
    with pytest.raises(AttributeError):
        getattr(mn, "does_not_exist")


def test_mesh_net_deep_copy_nested_structures():
    spec = get_mesh_net()
    spec["global_cybersecurity_mesh"]["core_layers"]["communication_mesh"]["message_types"].append(
        "new_type"
    )

    original = get_mesh_net()["global_cybersecurity_mesh"]["core_layers"]["communication_mesh"][
        "message_types"
    ]
    assert "new_type" not in original


def test_mesh_net_lazy_load_caches(monkeypatch, reset_mesh_cache):
    calls = []

    def fake_loads(data):
        calls.append(data)
        return {"global_cybersecurity_mesh": {"network_metadata": {}}}

    monkeypatch.setattr(mn, "json", SimpleNamespace(loads=fake_loads))

    mn.get_mesh_net()
    mn.get_mesh_net()

    assert len(calls) == 1
