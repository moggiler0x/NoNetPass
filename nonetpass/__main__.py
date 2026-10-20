import argparse
import logging

from .config import Settings


def main() -> None:
    parser = argparse.ArgumentParser(prog="nonetpass")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    sub = parser.add_subparsers(dest="command")
    cfg = sub.add_parser("router-config", help="напечатать разовую настройку роутера")
    cfg.add_argument("kind", choices=["mikrotik", "nftables", "ipset"])
    cfg.add_argument("--hotspot-server", default="hotspot1", help="MikroTik: имя сервера Hotspot")
    cfg.add_argument("--hotspot-net", default="192.168.110.0/24", help="MikroTik: сеть Hotspot")
    cfg.add_argument("--portal", default="172.17.0.2:8080", help="MikroTik: адрес и порт NoNetPass")
    args = parser.parse_args()
    settings = Settings.from_env()

    if args.command == "router-config":
        from .routercfg import GENERATORS, HotspotSetup

        catalog = settings.catalog()
        if args.kind == "mikrotik":
            host, _, port = args.portal.partition(":")
            hotspot = HotspotSetup(args.hotspot_server, args.hotspot_net, host, int(port or 8080))
            print(GENERATORS["mikrotik"](catalog, settings.client_list, hotspot), end="")
        else:
            print(GENERATORS[args.kind](catalog), end="")
        return

    import uvicorn

    from .app import create_app

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    uvicorn.run(create_app(settings), host=args.host, port=args.port, ws="auto")


if __name__ == "__main__":
    main()
