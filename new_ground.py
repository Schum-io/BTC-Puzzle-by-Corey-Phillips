#!/usr/bin/env python3
"""
The two bounded searches floflo777's ledger lists as "not yet run" -- everything
else in their 1.16-billion-candidate sweep is already exhausted, so this is the
genuinely-additive work.

  Lead 2  BIP44/BIP49 safety net: replay the thematic vocabulary AND every
          bundled wordlist against m/44' and m/49' as well as m/84'. Closes the
          "maybe he used a different purpose" hypothesis. Minutes.

  Lead 3  Three-word thematic combinator: only 1- and 2-word combinations of the
          puzzle vocabulary have been tested. Extend to three words over the same
          join styles. Bounded (hours at most).

Every candidate is checked against the target hash160 on all three paths at once
(the seed is computed once and reused), so the safety net costs almost nothing on
top of the BIP84 check. A positive control is verified before the run so a silent
failure cannot masquerade as "0 matches".

    python3 new_ground.py --selftest
    python3 new_ground.py lead2
    python3 new_ground.py lead3            # --words N caps combinator vocab (default 40)
"""
from __future__ import annotations

import argparse
import itertools
import os
import sys
import time
from multiprocessing import Pool
from pathlib import Path

import derive
from themed_candidates import WORDS as THEME_WORDS

HERE = Path(__file__).resolve().parent
TARGET20 = derive.decode_p2wpkh(derive.TARGET_ADDRESS)
JOIN_STYLES = ("", " ", "_", "-")  # + camelCase and PascalCase handled below


_WORKER_TARGET = TARGET20  # overridden per-process by _init (spawn-safe)


def _init(target: bytes):
    global _WORKER_TARGET
    _WORKER_TARGET = target


def _check(batch: list[str]):
    hits = []
    for p in batch:
        h = derive.hash160_on_paths(p, derive.PATHS)
        for name, digest in h.items():
            if digest == _WORKER_TARGET:
                hits.append((p, name))
    return len(batch), hits


def _chunks(it, size):
    it = iter(it)
    while True:
        block = list(itertools.islice(it, size))
        if not block:
            return
        yield block


def _run(candidates, label, jobs, batch=5000):
    print(f"\n{label}")
    tried = 0
    t0 = last = time.perf_counter()
    with Pool(jobs, initializer=_init, initargs=(TARGET20,)) as pool:
        for n, hits in pool.imap_unordered(_check, _chunks(candidates, batch)):
            tried += n
            for phrase, path in hits:
                # verify before believing
                if derive.hash160_on_paths(phrase, derive.PATHS)[path] == TARGET20:
                    print(f"\n*** MATCH *** path={path}  passphrase={phrase!r}", flush=True)
                    (HERE / "HITS.txt").open("a").write(f"{path}  {phrase!r}\n")
                    return phrase
            now = time.perf_counter()
            if now - last > 2:
                last = now
                sys.stdout.write(f"\r  {tried:,} tried, {tried/(now-t0):,.0f}/s   ")
                sys.stdout.flush()
    dt = time.perf_counter() - t0
    print(f"\r  {tried:,} tried in {dt:.1f}s ({tried/max(dt,1e-9):,.0f}/s) -- 0 matches")
    return None


def _joins(words):
    yield "".join(words)
    for sep in (" ", "_", "-"):
        yield sep.join(words)
    # camelCase and PascalCase
    yield words[0] + "".join(w.capitalize() for w in words[1:])
    yield "".join(w.capitalize() for w in words)


def lead2_candidates():
    """Thematic vocab + every bundled wordlist, deduped. Checked on all 3 paths."""
    seen = set()
    for w in THEME_WORDS:
        for form in (w, w.capitalize(), w.upper()):
            if form not in seen:
                seen.add(form); yield form
    for wl in sorted((HERE / "wordlists").glob("*.txt")):
        with wl.open(encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                c = line.rstrip("\r\n")
                if c and c not in seen:
                    seen.add(c); yield c


def lead3_candidates(vocab):
    seen = set()
    for combo in itertools.permutations(vocab, 3):
        for form in _joins(combo):
            if form not in seen:
                seen.add(form); yield form


def selftest(jobs):
    # Plant a known passphrase reachable on a NON-default path, so the safety net
    # itself is exercised, not just BIP84.
    import derive as d
    secret = "safety-net-control-99"
    target = d.hash160_on_paths(secret, d.PATHS)["bip49"]
    global TARGET20
    saved = TARGET20
    TARGET20 = target
    try:
        stream = [f"decoy{i}" for i in range(3000)]
        stream[1500] = secret
        found = _run(iter(stream), "selftest (control planted on bip49 path)", jobs)
        ok = found == secret
        print("SELFTEST PASSED" if ok else "SELFTEST FAILED")
        return 0 if ok else 1
    finally:
        TARGET20 = saved


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("lead", nargs="?", choices=("lead2", "lead3"))
    ap.add_argument("--words", type=int, default=40, help="lead3: vocab size (permutations grow fast)")
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    print(f"target : {derive.TARGET_ADDRESS} (hash160 {TARGET20.hex()})")
    print(f"paths  : {', '.join(derive.PATHS)}")

    if args.selftest:
        return selftest(args.jobs)
    if args.lead == "lead2":
        return 0 if _run(lead2_candidates(), "Lead 2 -- BIP44/49 safety net", args.jobs) else 1
    if args.lead == "lead3":
        vocab = THEME_WORDS[:args.words]
        n = len(vocab)
        est = n * (n - 1) * (n - 2) * 6
        print(f"Lead 3 -- 3-word combinator over {n} words, ~{est:,} candidates")
        return 0 if _run(lead3_candidates(vocab), "Lead 3 -- 3-word thematic combinator", args.jobs) else 1
    ap.error("give lead2, lead3, or --selftest")


if __name__ == "__main__":
    sys.exit(main())
