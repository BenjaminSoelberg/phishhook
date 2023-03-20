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
from nslookup import Nslookup
from persistqueue import Empty, SQLiteQueue, SQLiteAckQueue
from websockets.exceptions import ConnectionClosedError

from brand import Brand

# TODO: Add idna support like
# x = b'xn--postbdenhjort-tfb70a.dk.linux34.curanetserver.dk'
# x.decode('idna')

DOT = '.'
DASH = '-'
SPACE = ' '
DOT_DASH = '.-'
DOT_STAR = '*.'
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
        self.dns_query = Nslookup()

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
                            if domain.startswith(DOT_STAR):
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
            if not brand.enabled or self.is_ignored(specimen, brand.ignored_domains):
                continue

            kind, score, state = self.calc_domain_score(brand, specimen)

            if kind == 0:
                continue
            elif kind == 1:
                print(f'Known       {score} | [{state}] | [{brand.brand}] | [{specimen}]')
            elif kind == 2:
                print(f'Known sub   {score} | [{state}] | [{brand.brand}] | [{specimen}]')
            elif kind == 3:
                print(f'Unknown sub {score} | [{state}] | [{brand.brand}] | [{specimen}]')
            elif kind == 4:
                print(f'Suspicious  {score} | [{state}] | [{brand.brand}] | [{specimen}]')
            else:
                assert "Unknown kind: [" + kind + "]"

    def is_ignored(self, specimen: str, ignored_domains: list[str]) -> bool:
        for ignored_domain in ignored_domains:
            if ignored_domain.startswith(DOT_STAR):
                if specimen.endswith(ignored_domain[1:]):
                    return True
            elif specimen == ignored_domain:
                return True

        return False

    def calc_domain_score(self, brand, specimen) -> (int, int, str):
        is_known_domain: bool = False
        is_known_subdomain: bool = False
        is_unknown_subdomain: bool = False
        domain_score: int = 0
        for known_domain in brand.known_domains:
            # ------------------------------------
            # ---- Check for direct ownership ----
            # ------------------------------------
            if specimen == known_domain:
                # Found known domains
                is_known_domain = True
                continue

            if known_domain.startswith(DOT_STAR):
                # rule *.apple.com matching specimen apple.com as known domain
                if specimen == known_domain[2:]:
                    is_known_domain = True
                    continue

                # rule *.apple.com matching specimen www.apple.com as known subdomain
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

            score: int = 0
            # --------------------------------
            # ---- Check for permutations ----
            # --------------------------------
            known_domain_words = known_domain.replace(DOT, SPACE).replace(DASH, SPACE).split(SPACE)

            # Optimize search speed
            if self.contains_all_the_words(specimen, known_domain_words):
                # ----------------------------------------------------------
                # ---- Stage 0: Check if specimen contains known domain ----
                # ----------------------------------------------------------
                score = max(score, self.score_contains(specimen, known_domain, bias=2))

                # -----------------------------------------------------
                # ---- Stage 1: All the known domain words ordered ----
                # -----------------------------------------------------
                separators = set(product([DOT, DASH, SPACE], repeat=(len(known_domain_words) - 1)))  # TODO: Result should be cached

                stage_1_permutations: set[str] = {''.join(roundrobin(known_domain_words, separator)).replace(' ', '') for separator in separators}
                stage_1_permutations.discard(known_domain)  # Remove dupes already checked
                score = max(score, max([self.score_contains(specimen, stage_1_permutation, bias=1) for stage_1_permutation in stage_1_permutations]))

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
                stage_2_permutations -= stage_1_permutations  # Remove dupes already checked
                score = max(score, max([self.score_contains(specimen, stage_2_permutation, bias=0) for stage_2_permutation in stage_2_permutations]))

                # -----------------------------------------------
                # ---- Stage 3: Extra points for score words ----
                # -----------------------------------------------
                score += self.count_word_from_wordlist(specimen, brand.score_words)  # TODO: Should we score both myaccount and account in myaccount.apple.com.baddomain.com ?

                domain_score = max(domain_score, score)

        if is_known_domain:
            return 1, 0, self.get_state(specimen)
        if is_known_subdomain:
            return 2, 0, self.get_state(specimen)
        if is_unknown_subdomain:
            return 3, 0, self.get_state(specimen)

        trigger_words: set[str] = {
            ''.join(roundrobin(trigger_word.split('*'), separator)).replace(' ', '')
            for trigger_word in brand.trigger_words
            for separator in set(product([DOT, DASH, SPACE], repeat=trigger_word.count('*')))
        }

        if self.contains_word_from_wordlist(specimen, trigger_words):
            domain_score = max(domain_score, self.count_word_from_wordlist(specimen, brand.score_words))

        if domain_score > 0:
            return 4, domain_score, self.get_state(specimen)

        return 0, 0, None

    def get_state(self, domain: str) -> str:
        if len(self.dns_query.dns_lookup(domain).answer) > 0:
            return " active "
        else:
            return "inactive"

    def contains_all_the_words(self, domain, known_domain_words) -> bool:
        for word in known_domain_words:
            if word not in domain:
                return False
        return True

    def contains_word_from_wordlist(self, specimen, word_list) -> int:
        for word in word_list:
            if word in specimen:
                return True
        return False

    def count_word_from_wordlist(self, specimen, word_list) -> int:
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

        if score:
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
