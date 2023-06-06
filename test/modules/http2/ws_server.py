#!/usr/bin/env python3
import argparse
import asyncio
import logging
import sys

from websockets import server
from websockets.exceptions import ConnectionClosedError


async def echo(websocket):
    try:
        async for message in websocket:
            await websocket.send(message)
    except ConnectionClosedError:
        pass


async def run_server(port):
    async with server.serve(echo, "localhost", port):
        await asyncio.Future()  # run forever


def main():
    parser = argparse.ArgumentParser(prog='scorecard', description="""
        Run a websocket echo server.
        """)
    parser.add_argument("--port", type=int,
                        default=0, help="port to listen on")
    args = parser.parse_args()

    if args.port == 0:
        sys.stderr.write('need --port\n')
        sys.exit(1)

    logging.basicConfig(
        format="%(asctime)s %(message)s",
        level=logging.DEBUG,
    )
    asyncio.run(run_server(args.port))


if __name__ == "__main__":
    main()
