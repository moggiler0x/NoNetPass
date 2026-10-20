from nonetpass.gates import load_catalog
from nonetpass.routercfg import HotspotSetup, ipset, mikrotik, nftables


def test_mikrotik_follows_provider_hotspot():
    rsc = mikrotik(load_catalog())
    lines = rsc.splitlines()
    # Окна до входа: walled garden ip по спискам шлюза, на сервере hotspot1.
    wg = lines.index("/ip hotspot walled-garden ip")
    assert lines[wg + 1].startswith(
        "add action=accept server=hotspot1 src-address-list=nonetpass-clients-vk "
        "dst-address-list=nonetpass-targets-vk"
    )
    # Портал доступен до входа, трафик к нему не маскарадится.
    assert "add action=accept server=hotspot1 dst-address=172.17.0.2 protocol=tcp dst-port=8080" in rsc
    assert "add chain=srcnat src-address=192.168.110.0/24 dst-address=172.17.0.2 action=accept place-before=0" in rsc
    # Провайдер отключает api/api-ssl: REST через www-ssl только с адреса NoNetPass.
    assert "/ip service set www-ssl disabled=no certificate=nonetpass-rest address=172.17.0.2/32" in rsc
    assert "set api " not in rsc and "api-ssl disabled=no" not in rsc
    assert "add list=nonetpass-targets-vk address=api.vk.ru" in rsc


def test_mikrotik_custom_network():
    rsc = mikrotik(load_catalog(), hotspot=HotspotSetup("hs-guest", "10.10.0.0/22", "10.10.0.5", 9000))
    assert "server=hs-guest" in rsc and "server=hotspot1" not in rsc
    assert "src-address=10.10.0.0/22 dst-address=10.10.0.5" in rsc
    assert "dst-address=10.10.0.5 protocol=tcp dst-port=9000" in rsc


def test_one_window_rule_per_gate():
    catalog = load_catalog()
    rsc = mikrotik(catalog)
    for gate in catalog.all:
        assert rsc.count(f"src-address-list=nonetpass-clients-{gate.id} ") == 2  # walled garden + forward


def test_local_configs_use_pairs():
    assert "type ipv4_addr . ipv4_addr" in nftables(load_catalog())
    assert "hash:net,net" in ipset(load_catalog())
