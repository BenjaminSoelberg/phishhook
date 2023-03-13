#!/usr/bin/env python3
import asyncio
import json
import logging
import sys
from asyncio import CancelledError, Task
from collections import deque
from itertools import product, permutations
from ssl import SSLContext
from typing import Any

import aioconsole
import websockets
from more_itertools import roundrobin
from persistqueue import Empty, SQLiteQueue, SQLiteAckQueue
from websockets.exceptions import ConnectionClosedError

from brand import Brand

DOT = '.'
DASH = '-'
SPACE = ' '
DOT_DASH = '.-'
SEEN_DOMAIN_CACHE_SIZE = 100000

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


# noinspection PyMethodMayBeStatic
class Processor:

    def __init__(self,
                 uri: str = 'wss://certstream.calidog.io/',
                 auto_remove: bool = False,
                 brands: list[Brand] = None):

        self._brands = brands
        self._uri = uri
        self._auto_remove: bool = auto_remove
        self.total_permutations_checked = 0
        self._seen_domain_cache = deque(maxlen=SEEN_DOMAIN_CACHE_SIZE)
        # Setup queue
        if auto_remove:
            self._queue: SQLiteQueue = SQLiteQueue(DOT, auto_commit=True)
        else:
            self._queue: SQLiteAckQueue = SQLiteAckQueue(DOT, auto_commit=True)

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
                            if domain.startswith('*.'):
                                domain = domain[2:]
                            if domain not in self._seen_domain_cache:
                                self._seen_domain_cache.append(domain)
                                self._queue.put(domain)

            except ConnectionClosedError:
                log.warning('Connection was closed, reconnecting...')
            except CancelledError:
                log.warning('Connection was cancelled, reconnecting...')
            except TimeoutError:
                log.warning('Connection timeout, reconnecting...')
            except Exception as e:
                log.warning(f'Unknown exception {e}, reconnecting...')

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

    def check_domain(self, specimen):
        for brand in self._brands:
            if not brand.enabled:
                continue

            is_known_domain: bool = False
            is_known_subdomain: bool = False
            is_unknown_subdomain: bool = False
            suspicious_score: int = 0

            for known_domain in brand.known_domains:
                # ------------------------------------
                # ---- Check for direct ownership ----
                # ------------------------------------
                if specimen == known_domain:
                    # Found known domains
                    is_known_domain = True
                    continue

                if known_domain.startswith('*.'):
                    if specimen.endswith(known_domain[1:]):
                        # Found known subdomains
                        is_known_subdomain = True
                        continue
                    # Remove prefix and keep searching
                    known_domain = known_domain[2:]
                elif specimen.endswith(DOT + known_domain):
                    # Found unknown subdomain
                    is_unknown_subdomain = True
                    continue

                # --------------------------------
                # ---- Check for permutations ----
                # --------------------------------
                known_domain_words = known_domain.replace(DOT, SPACE).replace(DASH, SPACE).split(SPACE)

                # if self.contains_word_from_wordlist(specimen, brand.trigger_words) > 0:
                #     score += self.contains_word_from_wordlist(specimen, brand.score_words)

                # Optimize search speed
                if not self.contains_all_the_words(specimen, known_domain_words):
                    continue
                # ----------------------------------------------------------
                # ---- Stage 0: Check if specimen contains known domain ----
                # ----------------------------------------------------------
                suspicious_score = max(suspicious_score, self.score_contains(specimen, known_domain, bias=2))

                # -----------------------------------------------------
                # ---- Stage 1: All the known domain words ordered ----
                # -----------------------------------------------------
                separators = set(product([DOT, DASH, SPACE], repeat=(len(known_domain_words) - 1)))  # TODO: Result should be cached

                stage_1_permutations: set[str] = {''.join(roundrobin(known_domain_words, separator)).replace(' ', '') for separator in separators}
                stage_1_permutations.discard(known_domain)  # Remove dupes already checked
                suspicious_score = max(suspicious_score, max([self.score_contains(specimen, stage_1_permutation, bias=1) for stage_1_permutation in stage_1_permutations]))

                # -------------------------------------------------------
                # ---- Stage 2: All the known domain words unordered ----
                # -------------------------------------------------------
                stage_2_permutations: set[str] = {
                    ''.join(roundrobin(known_domain_words_permutation, separator)).replace(' ', '')
                    for separator in separators
                    for known_domain_words_permutation in permutations(known_domain_words)
                }
                # Remove dupes already checked
                stage_2_permutations.discard(known_domain)
                stage_2_permutations -= stage_1_permutations
                suspicious_score = max(suspicious_score, max([self.score_contains(specimen, stage_2_permutation, bias=0) for stage_2_permutation in stage_2_permutations]))

            if is_known_domain:
                print(f'Known      [{brand.brand}] | 0 {specimen}')
            elif is_known_subdomain:
                print(f'Known sub   [{brand.brand}] | 0 [{specimen}]')
            elif is_unknown_subdomain:
                print(f'Unknown sub [{brand.brand}] | 0 [{specimen}]')
            elif suspicious_score > 0:
                print(f'Suspicious  [{brand.brand}] | {suspicious_score} [{specimen}]')

    def contains_all_the_words(self, domain, known_domain_words):
        for word in known_domain_words:
            if word not in domain:
                return False
        return True

    def contains_word_from_wordlist(self, specimen, word_list) -> int:
        score = 0
        for word in word_list:
            if word in specimen:
                score += 1
        return score

    def score_contains(self, specimen: str, artifact: str, bias: int) -> int:
        if self.total_permutations_checked % 10000 == 0 or self.total_permutations_checked == 0:
            log.info(f'Permutations checked {self.total_permutations_checked}')
        self.total_permutations_checked += 1

        score: int = 0
        if specimen.startswith(artifact):
            score += 4 + self.has_dot_or_dash_at_index(specimen, len(artifact))
        if specimen.endswith(artifact):
            score += 4 + self.has_dash_at_index(specimen, len(specimen) - len(artifact) - 1)
        # TODO:We could also think about counting the number of artifact repetitions in the specimen
        if score == 0 and artifact in specimen:
            score += 1 \
                     + self.has_dot_or_dash_at_index(specimen, specimen.index(artifact) - 1) \
                     + self.has_dot_or_dash_at_index(specimen, specimen.index(artifact) + len(artifact))

        if score > 0:
            score += bias

        return score

    def has_dash_at_index(self, specimen: str, index: int) -> bool:
        if len(specimen) < index + 1:
            return False
        return specimen[index] == DASH

    def has_dot_or_dash_at_index(self, specimen: str, index: int) -> bool:
        if len(specimen) < index + 1:
            return False
        return specimen[index] in DOT_DASH


async def main():
    # Read brands
    brands = read_brands()

    processor: Processor = Processor(auto_remove=True, brands=brands)

    if False:
        with open(file='phishingdomains.bin', mode='r') as file:
            for line in file:
                domain = line.split('#')[0].strip()
                if domain:
                    processor.check_domain(domain)
    else:
        # Schedule coroutines
        processor_future: Task[Any] = asyncio.ensure_future(processor.query())
        queue_future: Task[Any] = asyncio.ensure_future(processor.process_queue())

        # Keep running until ctrl-d
        while True:
            try:
                await aioconsole.ainput()
            except EOFError:
                break


if __name__ == '__main__':
    loop.run_until_complete(main())
