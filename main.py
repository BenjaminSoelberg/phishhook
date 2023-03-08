#!/usr/bin/env python3
import asyncio
import json
import logging
import sys
from itertools import product
from ssl import SSLContext

import aioconsole
import websockets
from more_itertools import roundrobin
from persistqueue import Empty, SQLiteQueue, SQLiteAckQueue

from brand import Brand

logging.basicConfig(
    stream=sys.stderr,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    level=logging.INFO
)

log = logging.getLogger()
loop = asyncio.get_event_loop()


def is_idn(domain: str):
    return domain != domain.encode('idna')


def read_brands() -> list[Brand]:
    with open(file='brands.json', mode='r') as f:
        json_data: str = f.read()
        return Brand.Schema().loads(json_data, many=True)


class Processor:

    def __init__(self,
                 uri: str = 'wss://certstream.calidog.io/',
                 auto_remove: bool = False,
                 brands: list[Brand] = None):

        self._brands = brands
        self._uri = uri
        self._auto_remove: bool = auto_remove

        # Setup queue
        if auto_remove:
            self._queue: SQLiteQueue = SQLiteQueue('.', auto_commit=True)
        else:
            self._queue: SQLiteAckQueue = SQLiteAckQueue('.', auto_commit=True)

        self._ssl_context: SSLContext = SSLContext()

        super().__init__()

    # noinspection PyBroadException
    async def query(self) -> None:
        log.info('Connecting...')
        queried: int = 0
        while True:
            try:
                async with websockets.connect(self._uri, ssl=self._ssl_context) as ws:
                    log.info('Connected')
                    while True:
                        if queried % 10000 == 0 or queried == 0:
                            log.info(f'Queried certificates: {queried}')
                        data = await ws.recv()
                        queried += 1
                        doc = json.loads(data)
                        for domain in doc['data']['leaf_cert']['all_domains']:
                            self._queue.put(domain)
            # except ConnectionClosedError:
            #   print(f'Reconnecting {ConnectionClosedError}...')
            # except CancelledError:
            #    print(f'Reconnecting {CancelledError}...')
            # except TimeoutError:
            #    print(f'Reconnecting {TimeoutError}...')
            except BaseException:
                log.warning(f'Reconnecting {BaseException.__class__}...')

    async def process_queue(self) -> None:
        processed: int = 0
        while True:
            if processed % 10000 == 0 or processed == 0:
                log.info(f'Processed domains: {processed}')

            try:
                domain: str = self._queue.get_nowait()
                if domain is None:
                    continue

                self.check_domain(domain)

            except Empty:
                await asyncio.sleep(0.5)

            processed += 1

    def check_domain(self, domain):
        for brand in self._brands:
            if not brand.enabled:
                continue

            accepted_domains: set[str] = set()
            unknown_subdomains: set[str] = set()
            suspicious_domains: dict[str, int] = {}
            for known_domain in brand.known_domains:
                # ------------------------------------
                # ---- Check for direct ownership ----
                # ------------------------------------
                if domain == known_domain:
                    # Found known domains
                    accepted_domains.add(domain)
                    continue

                if known_domain.startswith('*.'):
                    if domain.endswith(known_domain[1:]):
                        # Found known subdomains
                        accepted_domains.add(domain)
                        continue
                    # Remove prefix and keep searching
                    known_domain = known_domain[2:]
                elif domain.endswith('.' + known_domain):
                    # Found unknown subdomain
                    unknown_subdomains.add(domain)
                    continue

                # --------------------------------
                # ---- Check for permutations ----
                # --------------------------------
                known_domain_words = known_domain.replace('.', ' ').replace('-', ' ').split(' ')
                perms = [''.join(roundrobin(r, known_domain_words)).replace(' ', '')
                         for r in product(['.', '-', ' '], repeat=(len(known_domain_words) + 1))]

                # Stage 1: look for domain contains something like ['.post.nord.dk.', '.post.nord.dk-', '.post.nord.dk', '.post.nord-dk-', '.post.nord-dk', '.post.norddk', '.post-nord-dk-', '.post-nord-dk', '.post-norddk', '.postnorddk', '-post-nord-dk-', '-post-nord-dk', '-post-norddk', '-postnorddk', 'postnorddk']
                [self.score_contains(suspicious_domains, domain, prospect) for prospect in perms]

                # Stage 2: permutate words in different order

            # Remove from unknown_subdomains if they also exist in accepted_domains
            unknown_subdomains -= accepted_domains
            # Remove from suspicious_domains if they also exist in accepted_domains or unknown_subdomains
            [suspicious_domains.pop(d) for d in unknown_subdomains | accepted_domains if d in suspicious_domains]

            for accepted_domain in accepted_domains:
                print(f'Known       {brand.brand} | 0 {accepted_domain}')
            for unknown_subdomain in unknown_subdomains:
                print(f'Unknown sub {brand.brand} | 0 {unknown_subdomain}')
            for suspicious_domain, score in suspicious_domains.items():
                print(f'Suspicious  {brand.brand} | {score} {suspicious_domain}')

    @staticmethod
    def score_contains(score_card: dict[str, int], domain: str, prospect: str):
        score: int = 0
        if domain.startswith(prospect) or domain.endswith(prospect):
            score = 4
        elif prospect in domain:
            score = 1 + (prospect[0] == '.' or prospect[0] == '-') + (prospect[-1] == '.' or prospect[-1] == '-')

        if score == 0:
            return

        if domain in score_card:
            score_card[domain] = max(score, score_card[domain])
        else:
            score_card[domain] = score


async def main():
    # Read brands
    brands = read_brands()

    processor: Processor = Processor(auto_remove=True, brands=brands)

    if False:
        with open(file='phishingdomains.bin', mode='r') as file:
            for line in file:
                domain = line.rstrip()
                processor.check_domain(domain)
    else:
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
