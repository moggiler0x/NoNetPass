"""Чёрный список устройств по MAC и IP.

IP в гостевой сети выдаёт DHCP, и он меняется, поэтому основной ключ — MAC.
MAC берётся у роутера (ARP или Hotspot), а если NoNetPass стоит в той же
сети, то из ``/proc/net/arp``. Записи из окружения
(``NONETPASS_BLOCKED_MACS``, ``NONETPASS_BLOCKED_IPS``) нельзя снять из
панели: они действуют, пока заданы в окружении.
"""

from __future__ import annotations

import ipaddress
import re
import time
from pathlib import Path

from .store import StateStore

MAC_RE = re.compile(r"^[0-9a-f]{2}([:-]?)[0-9a-f]{2}(\1[0-9a-f]{2}){4}$")


def normalize_mac(value: str) -> str | None:
    raw = value.strip().lower()
    if not MAC_RE.match(raw):
        return None
    hexes = re.sub(r"[^0-9a-f]", "", raw)
    return ":".join(hexes[i:i + 2] for i in range(0, 12, 2))


def normalize_ip(value: str) -> str | None:
    try:
        return str(ipaddress.IPv4Address(value.strip()))
    except ValueError:
        return None


def parse_entry(value: str) -> tuple[str, str]:
    """``("macs", "aa:bb:…")`` или ``("ips", "1.2.3.4")``; ValueError, если ни то ни другое."""
    if mac := normalize_mac(value):
        return "macs", mac
    if ip := normalize_ip(value):
        return "ips", ip
    raise ValueError(f"{value!r} не MAC и не IPv4")


class Blocklist:
    def __init__(self, store: StateStore, macs: list[str] = (), ips: list[str] = ()):
        self.store = store
        self.fixed: dict[str, set[str]] = {"macs": set(), "ips": set()}
        for value in (*macs, *ips):
            kind, key = parse_entry(value)
            self.fixed[kind].add(key)

    @property
    def _data(self) -> dict[str, dict]:
        return self.store.data["blocklist"]

    def add(self, value: str, note: str = "", by: str = "admin") -> tuple[str, str]:
        kind, key = parse_entry(value)
        self._data[kind][key] = {"note": note, "by": by, "ts": time.time()}
        self.store.save()
        return kind, key

    def remove(self, value: str) -> bool:
        kind, key = parse_entry(value)
        if key in self.fixed[kind]:
            raise ValueError(f"{key} задан в окружении, снимите его там")
        found = self._data[kind].pop(key, None) is not None
        if found:
            self.store.save()
        return found

    def match(self, ip: str | None, mac: str | None) -> str | None:
        """Что именно заблокировано (MAC или IP), либо None."""
        if mac and (mac in self.fixed["macs"] or mac in self._data["macs"]):
            return mac
        if ip and (ip in self.fixed["ips"] or ip in self._data["ips"]):
            return ip
        return None

    def entries(self) -> list[dict]:
        out = []
        for kind in ("macs", "ips"):
            for key in sorted(self.fixed[kind]):
                out.append({"kind": kind[:-1], "value": key, "note": "из окружения", "fixed": True})
            for key, meta in sorted(self._data[kind].items()):
                if key not in self.fixed[kind]:
                    out.append({"kind": kind[:-1], "value": key, "fixed": False, **meta})
        return out

    def __len__(self) -> int:
        return len(self.entries())


def arp_lookup(ip: str, path: str = "/proc/net/arp") -> str | None:
    """MAC из ARP-таблицы машины, где запущен NoNetPass."""
    try:
        lines = Path(path).read_text().splitlines()[1:]
    except OSError:
        return None
    for line in lines:
        parts = line.split()
        if len(parts) >= 4 and parts[0] == ip:
            mac = normalize_mac(parts[3])
            if mac and mac != "00:00:00:00:00:00":
                return mac
    return None
