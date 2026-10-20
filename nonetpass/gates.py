"""Каталог шлюзов.

Шлюз — это один сервис, через который пользователь либо входит в сеть
(верификация), либо проводит оплату. У каждого шлюза свои узлы-триггеры
(обращение к ним означает начало сессии), свои узлы доставки (их NoNetPass
открывает на время окна) и своя длительность окна.

* Верификация (kind="verify") — окно короткое, по умолчанию 20 секунд:
  ровно чтобы дошёл код подтверждения.
* Оплата (kind="pay") — окно до минуты, по умолчанию 60 секунд: чтобы
  успеть подтвердить платёж (3-D Secure, пуш из банковского приложения).

Списки узлов ниже — разумная отправная точка по основным доменам сервисов.
Их обязательно нужно сверить с конкретной сетью: адреса доставки пушей,
ACS-серверов 3-D Secure и API у банков и платформ меняются. Весь каталог
переопределяется файлом NONETPASS_GATES_FILE (JSON), а длительность окон —
переменными NONETPASS_VERIFY_WINDOW_SECONDS и NONETPASS_PAY_WINDOW_SECONDS.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

VERIFY = "verify"
PAY = "pay"


@dataclass(frozen=True)
class Gate:
    id: str
    name: str
    kind: str  # VERIFY | PAY
    gateways: tuple[str, ...]  # узлы-триггеры (SSO-шлюз, страница оплаты)
    targets: tuple[str, ...]  # узлы доставки кода / подтверждения платежа
    window: float
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "kind": self.kind,
            "window": self.window,
            "targets": list(self.targets),
            "note": self.note,
        }


# Длительность окон по типу (переопределяется из окружения в config.py).
DEFAULT_VERIFY_WINDOW = 20.0
DEFAULT_PAY_WINDOW = 60.0


def _verify(id: str, name: str, gateways, targets, note: str = "") -> Gate:
    return Gate(id, name, VERIFY, tuple(gateways), tuple(targets), DEFAULT_VERIFY_WINDOW, note)


def _pay(id: str, name: str, gateways, targets, note: str = "") -> Gate:
    return Gate(id, name, PAY, tuple(gateways), tuple(targets), DEFAULT_PAY_WINDOW, note)


# Вход в сеть: SSO-сервисы, через которые сейчас можно верифицироваться.
VERIFY_GATES = (
    _verify("vk", "VK", ["id.vk.com"], ["im.vk.com", "api.vk.com", "login.vk.com"]),
    _verify("sber-id", "Сбер ID", ["id.sber.ru", "online.sberbank.ru"],
            ["api.sberbank.ru", "securepayments.sberbank.ru"]),
    _verify("yandex-id", "Яндекс ID", ["passport.yandex.ru", "id.yandex.ru"],
            ["passport.yandex.ru", "api.passport.yandex.ru"]),
    _verify("alfa-id", "Альфа ID", ["id.alfabank.ru"],
            ["alfabank.ru", "click.alfabank.ru", "api.alfabank.ru"]),
)

# Оплата: банки, которым нужно короткое окно на подтверждение платежа.
PAY_GATES = (
    _pay("sber-pay", "Сбер", ["securepayments.sberbank.ru", "3dsec.sberbank.ru"],
         ["securepayments.sberbank.ru", "api.sberbank.ru"]),
    _pay("alfa-pay", "Альфа-Банк", ["pay.alfabank.ru", "web.rbsuat.com"],
         ["pay.alfabank.ru", "click.alfabank.ru"]),
    _pay("vtb-pay", "ВТБ", ["3ds.vtb.ru", "online.vtb.ru"],
         ["3ds.vtb.ru", "api.vtb.ru"]),
    _pay("tbank-pay", "Т-Банк", ["secure.tbank.ru", "secure.tinkoff.ru", "id.tbank.ru"],
         ["secure.tbank.ru", "api.tbank.ru"]),
)

DEFAULT_GATES = VERIFY_GATES + PAY_GATES


@dataclass
class GateCatalog:
    gates: dict[str, Gate] = field(default_factory=dict)

    @property
    def all(self) -> list[Gate]:
        return list(self.gates.values())

    def get(self, gate_id: str) -> Gate | None:
        return self.gates.get(gate_id)

    def for_host(self, host: str) -> Gate | None:
        """Шлюз, которому принадлежит узел-триггер host (или его поддомен)."""
        host = host.lower().rstrip(".")
        for gate in self.gates.values():
            for gw in gate.gateways:
                if host == gw or host.endswith("." + gw):
                    return gate
        return None


def _apply_window(gate: Gate, verify_window: float, pay_window: float) -> Gate:
    window = verify_window if gate.kind == VERIFY else pay_window
    return Gate(gate.id, gate.name, gate.kind, gate.gateways, gate.targets, window, gate.note)


def load_catalog(
    verify_window: float = DEFAULT_VERIFY_WINDOW,
    pay_window: float = DEFAULT_PAY_WINDOW,
    gates_file: str | None = None,
) -> GateCatalog:
    source = _read_file(gates_file) if gates_file else DEFAULT_GATES
    gates = {g.id: _apply_window(g, verify_window, pay_window) for g in source}
    if not gates:
        raise ValueError("каталог шлюзов пуст")
    return GateCatalog(gates)


def _read_file(path: str) -> list[Gate]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    gates = []
    for item in data:
        kind = item.get("kind", VERIFY)
        if kind not in (VERIFY, PAY):
            raise ValueError(f"шлюз {item.get('id')!r}: kind должен быть verify или pay")
        gates.append(
            Gate(
                id=item["id"],
                name=item["name"],
                kind=kind,
                gateways=tuple(item.get("gateways", [])),
                targets=tuple(item["targets"]),
                window=float(item.get("window", DEFAULT_VERIFY_WINDOW if kind == VERIFY else DEFAULT_PAY_WINDOW)),
                note=item.get("note", ""),
            )
        )
    return gates
