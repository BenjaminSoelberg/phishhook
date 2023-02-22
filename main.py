#!/usr/bin/env python3

import asyncio
import json
from ssl import SSLContext

import aioconsole
import websockets
from persistqueue import Empty, SQLiteQueue, SQLiteAckQueue
from websockets.exceptions import ConnectionClosedError

from rule import Rule

loop = asyncio.get_event_loop()


def is_idn(domain: str):
    return domain != domain.encode('idna')


def read_rules():
    with open(file='rules.json', mode='r') as f:
        json_data: str = f.read()
        return Rule.Schema().loads(json_data, many=True)

    # # Generate white lists
    # for rule in self._rules:
    #     if rule.name in domain:
    #         pass


class Processor:

    def __init__(self, uri: str = 'wss://certstream.calidog.io/', auto_remove: bool = False, rules: list[Rule] = None):
        self._rules = rules
        self._uri = uri
        self._auto_remove: bool = auto_remove

        # Setup queue
        if auto_remove:
            self._queue: SQLiteQueue = SQLiteQueue('.', auto_commit=True)
        else:
            self._queue: SQLiteAckQueue = SQLiteAckQueue('.', auto_commit=True)

        self._ssl_context: SSLContext = SSLContext()

        super().__init__()

    async def query(self):
        queried: int = 0
        while True:
            try:
                async with websockets.connect(self._uri, ssl=self._ssl_context) as ws:
                    print("Connected")
                    while True:
                        data = await ws.recv()
                        if queried % 1000 == 0 or queried == 0:
                            print(f'Queried certificates: {queried}')
                        queried += 1
                        doc = json.loads(data)
                        for domain in doc['data']['leaf_cert']['all_domains']:
                            self._queue.put(domain)
            except ConnectionClosedError:
                print("Reconnecting...")
                pass

    async def process_queue(self):
        processed: int = 0
        while True:
            try:
                domain: str = self._queue.get_nowait()
                if domain is not None:
                    if processed % 1000 == 0 or processed == 0:
                        print(f'Processed domains: {processed}')
                    processed += 1
                    for rule in self._rules:
                        if rule.name in domain:
                            print(f"HIT: {rule.brand} {domain}")
            except Empty:
                await asyncio.sleep(0.1)


async def main():
    # Read rules
    rules = read_rules()

    processor: Processor = Processor(auto_remove=False, rules=rules)
    # Schedule coroutines
    asyncio.ensure_future(processor.query())
    asyncio.ensure_future(processor.process_queue())

    # Keep running until ctrl-d
    while True:
        try:
            await aioconsole.ainput()
        except EOFError:
            break


if __name__ == '__main__':
    loop.run_until_complete(main())
