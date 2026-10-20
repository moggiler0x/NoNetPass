from __future__ import annotations

from ..config import Settings
from .base import DriverError, Grant, RouterDriver
from .mock import MockDriver

# Набор пар «клиент · узел шлюза» для nftables, ipset и OpenWrt.
PAIRS_SET = "nonetpass_pairs"

DRIVERS = ("mock", "mikrotik", "mikrotik-api", "keenetic", "openwrt", "opnsense", "nftables", "ipset")


def _require(settings: Settings, *names: str) -> None:
    missing = [n for n in names if not getattr(settings, n)]
    if missing:
        env = ", ".join(f"NONETPASS_{n.upper()}" for n in missing)
        raise ValueError(f"драйвер {settings.driver}: не заданы {env}")


def build_driver(settings: Settings) -> RouterDriver:
    opts = settings.driver_options
    name = settings.driver
    if name == "mock":
        return MockDriver()
    if name == "mikrotik":
        from .mikrotik import MikroTikRestDriver

        _require(settings, "router_url", "router_user")
        return MikroTikRestDriver(
            settings.router_url, settings.router_user, settings.router_password or "",
            settings.client_list, settings.router_verify_tls,
        )
    if name == "mikrotik-api":
        from .mikrotik import MikroTikApiDriver

        _require(settings, "router_url", "router_user")
        return MikroTikApiDriver(
            settings.router_url, settings.router_user, settings.router_password or "",
            settings.client_list, settings.router_verify_tls,
        )
    if name == "keenetic":
        from .keenetic import DEFAULT_GRANT_CMD, DEFAULT_REVOKE_CMD, KeeneticDriver

        return KeeneticDriver(
            settings.router_url or "http://127.0.0.1:79",
            settings.router_user,
            settings.router_password,
            acl=opts.get("acl", "nonetpass"),
            verify_tls=settings.router_verify_tls,
            grant_cmd=opts.get("grant_cmd", DEFAULT_GRANT_CMD),
            revoke_cmd=opts.get("revoke_cmd", DEFAULT_REVOKE_CMD),
            state_file=opts.get("state_file", "nonetpass-keenetic-state.json"),
        )
    if name == "openwrt":
        from .openwrt import OpenWrtDriver

        _require(settings, "router_url", "router_user")
        return OpenWrtDriver(
            settings.router_url, settings.router_user, settings.router_password or "",
            opts.get("set", PAIRS_SET),
            family=opts.get("family", "inet"), table=opts.get("table", "fw4"),
            verify_tls=settings.router_verify_tls,
        )
    if name == "opnsense":
        from .opnsense import OPNsenseDriver

        _require(settings, "router_url", "router_user", "router_password")
        return OPNsenseDriver(
            settings.router_url, settings.router_user, settings.router_password,
            settings.client_list.replace("-", "_"), settings.router_verify_tls,
        )
    if name == "nftables":
        from .local import NftablesDriver

        return NftablesDriver(
            opts.get("set", PAIRS_SET),
            family=opts.get("family", "inet"), table=opts.get("table", "fw4"),
        )
    if name == "ipset":
        from .local import IpsetDriver

        return IpsetDriver(opts.get("set", PAIRS_SET))
    raise ValueError(f"неизвестный драйвер {name!r}, доступны: {', '.join(DRIVERS)}")


__all__ = ["DRIVERS", "DriverError", "Grant", "MockDriver", "RouterDriver", "build_driver"]
