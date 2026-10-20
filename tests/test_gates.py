import json

import pytest

from nonetpass.config import Settings
from nonetpass.gates import PAY, VERIFY, load_catalog


def test_default_catalog_windows():
    catalog = load_catalog()
    verify = {g.id for g in catalog.all if g.kind == VERIFY}
    pay = {g.id for g in catalog.all if g.kind == PAY}
    assert verify == {"vk", "sber-id", "yandex-id", "alfa-id"}
    assert pay == {"sber-pay", "alfa-pay", "vtb-pay", "tbank-pay"}
    assert all(g.window == 20 for g in catalog.all if g.kind == VERIFY)
    assert all(g.window == 60 for g in catalog.all if g.kind == PAY)


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
    assert catalog.get("bank").window == 60


def test_gates_file_rejects_bad_kind(tmp_path):
    path = tmp_path / "gates.json"
    path.write_text(json.dumps([{"id": "x", "name": "X", "kind": "other", "targets": ["a"]}]))
    with pytest.raises(ValueError):
        load_catalog(gates_file=str(path))
