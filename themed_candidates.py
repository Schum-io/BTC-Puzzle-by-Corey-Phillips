#!/usr/bin/env python3
"""
Puzzle-specific seed words, one per line, for tier 3 of run_plan.sh. These are
NOT the final candidates -- they are stems that hashcat's rule engine mutates
(case, leet, affixes, years). Keep this list small and on-topic; breadth comes
from the rules, relevance comes from here.
"""
WORDS = [
    # the puzzle / demo
    "bitimage", "kitten", "kittens", "kitty", "cat", "cats", "meow", "purr",
    "picture", "photo", "image", "satoshi", "satoshis", "sats", "thousand",
    "wealth", "bitcoin", "puzzle", "mnemonic", "seed", "passphrase", "segwit",
    # people / handles
    "corey", "phillips", "coreyphillips", "coreylphillips", "aantonop",
    "andreas", "antonopoulos",
    # his other projects
    "bitbip", "kisswallet",
    # stego / origin
    "steganography", "stego", "hidden", "secret",
    # bitcoin culture
    "hodl", "moon", "nakamoto", "blockchain",
]
if __name__ == "__main__":
    seen = set()
    for w in WORDS:
        for form in (w, w.capitalize()):
            if form not in seen:
                seen.add(form)
                print(form)
