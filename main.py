import asyncio
import json
import ssl
from asyncio import CancelledError

import aioconsole as aioconsole
import persistqueue
import websockets
from persistqueue import Empty, SQLiteQueue

from rule import Rule

auto_remove = True
uri = "wss://certstream.calidog.io/"

ssl_context = ssl.SSLContext()
loop = asyncio.get_event_loop()
queue: SQLiteQueue

rules: list[Rule]


def is_idn(domain: str):
    return domain != domain.encode('idna')


async def query():
    queried: int = 0
    while True:
        try:
            async with websockets.connect(uri, ssl=ssl_context) as websocket:
                while True:
                    data = await websocket.recv()
                    if queried % 1000 == 0 or queried == 0:
                        print(f'Queried certificates: {queried}')
                    queried += 1
                    doc = json.loads(data)
                    for domain in doc['data']['leaf_cert']['all_domains']:
                        queue.put(domain)
        except CancelledError:
            pass


async def process():
    processed: int = 0
    global rules
    while True:
        try:
            domain: str = queue.get_nowait()
            if domain is not None:
                if processed % 1000 == 0 or processed == 0:
                    print(f'Processed domains: {processed}')
                processed += 1
                for rule in rules:
                    if rule.brand in domain:
                        print(f"{rule.brand} {domain}")
        except Empty:
            await asyncio.sleep(0.1)


def read_rules():
    global rules
    with open(file='rules.json', mode='r') as f:
        json_data: str = f.read()
        rules = Rule.Schema().loads(json_data, many=True)


async def main():
    # Setup queue
    global queue
    if auto_remove:
        queue = persistqueue.SQLiteQueue('.', auto_commit=True)
    else:
        queue = persistqueue.SQLiteAckQueue('.', auto_commit=True)

    # Read rules
    read_rules()

    # Schedule coroutines
    asyncio.ensure_future(query())
    asyncio.ensure_future(process())

    # Keep running until ctrl-d
    while True:
        try:
            await aioconsole.ainput()
        except EOFError:
            break


if __name__ == '__main__':
    loop.run_until_complete(main())
