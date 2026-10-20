import argparse
import logging

import uvicorn

from .app import create_app
from .config import Settings


def main() -> None:
    parser = argparse.ArgumentParser(prog="authpass")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    uvicorn.run(create_app(Settings.from_env()), host=args.host, port=args.port, ws="auto")


if __name__ == "__main__":
    main()
