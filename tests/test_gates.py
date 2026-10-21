import json

import pytest

from nonetpass.config import Settings
from nonetpass.gates import PAY, VERIFY, load_catalog


def test_default_catalog_windows():
    catalog = load_catalog()
    verify = {g.id for g in catalog.all if g.kind == VERIFY}
    pay = {g.id for g in catalog.all if g.kind == PAY}
    assert verify == {"vk", "sber-id", "yandex-id", "alfa-id", "gosuslugi"}
    assert pay == {"sber-pay", "alfa-pay", "vtb-pay", "tbank-pay"}
    assert all(g.window == 120 for g in catalog.all if g.kind == VERIFY)
    assert all(g.window == 300 for g in catalog.all if g.kind == PAY)


def test_window_override_from_settings():
    catalog = Settings(verify_window_seconds=15, pay_window_seconds=45).catalog()
    assert catalog.get("vk").window == 15
    assert catalog.get("vtb-pay").window == 45


def test_gates_file(tmp_path):
    path = tmp_path / "gates.json"
    path.write_text(json.dumps([
        {"id": "corp", "name": "Corp SSO", "kind": "verify", "gateways": ["sso.corp"], "targets": ["push.corp"]},
        {"id": "bank", "name": "Bank", "kind": "pay", "targets": ["acs.bank"]},
    ]))
    catalog = load_catalog(gates_file=str(path))
    assert [g.id for g in catalog.all] == ["corp", "bank"]
    assert catalog.for_host("sso.corp").id == "corp"
    assert catalog.get("bank").window == 300


def test_gates_file_rejects_bad_kind(tmp_path):
    path = tmp_path / "gates.json"
    path.write_text(json.dumps([{"id": "x", "name": "X", "kind": "other", "targets": ["a"]}]))
    with pytest.raises(ValueError):
        load_catalog(gates_file=str(path))


def test_provider_sso_hosts_trigger_gates():
    # Узлы страниц входа из walled garden инструкции провайдера Captive Portal.
    catalog = load_catalog()
    assert catalog.for_host("id.vk.ru").id == "vk"
    assert catalog.for_host("id.sber.ru").id == "sber-id"
    assert catalog.for_host("oauth.yandex.ru").id == "yandex-id"
    assert catalog.for_host("id.alfabank.ru").id == "alfa-id"
    assert catalog.for_host("esia.gosuslugi.ru").id == "gosuslugi"
