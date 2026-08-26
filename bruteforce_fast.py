#!/usr/bin/env python3
"""
Fast CPU passphrase search -- the same job as `bruteforce.py`, ~1.5x quicker per
core, streaming (so a 14 M-line wordlist needs no memory), resumable, and able to
take candidates on stdin so hashcat's rule engine can drive it.

    python3 bruteforce_fast.py --selftest              # prove it can find a known answer
    python3 bruteforce_fast.py wordlists/              # every *.txt in a directory
    python3 bruteforce_fast.py rockyou.txt --mutate    # + case/leet/affix variants
    hashcat --stdout -r best64.rule rockyou.txt | python3 bruteforce_fast.py --stdin

Reading candidates from stdin is the recommended way to use real rule sets: it
gives you hashcat's entire rules ecosystem without reimplementing it here, and
`--stdin` keeps up with anything a single `hashcat --stdout` process can emit.

Resume: each finished input file is appended to `--state` (default
`stats_fast.txt`) and skipped next run. A file interrupted halfway is NOT
recorded, so it restarts from the top -- keep individual wordlists to a size you
are willing to redo, or split them.

Every hit is printed and appended to `--hits` (default `HITS.txt`), and is
re-derived and re-checked against the full address string before being reported,
so a reported hit is never a false positive.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from itertools import islice
from multiprocessing import Pool
from pathlib import Path

import derive

HERE = Path(__file__).resolve().parent
_TARGET: bytes = b""


# --------------------------------------------------------------------------- #
# candidate sources
# --------------------------------------------------------------------------- #

# Deliberately small: anything more elaborate belongs in a hashcat rule file
# piped in through --stdin, not hard-coded here.
_LEET = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"})
_AFFIX = ("", "1", "123", "!", "2019", "01", "?")


def mutations(word: str):
    """A compact case/leet/affix expansion (~40 candidates per input word)."""
    stems = {word, word.lower(), word.upper(), word.capitalize()}
    stems.add(word.lower().translate(_LEET))
    for stem in stems:
        for suffix in _AFFIX:
            yield stem + suffix


def read_lines(path: Path):
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            yield line.rstrip("\r\n")


def expand(lines, mutate: bool):
    if not mutate:
        yield from lines
        return
    for line in lines:
        yield from mutations(line)


def chunks(iterable, size: int):
    it = iter(iterable)
    while True:
        block = list(islice(it, size))
        if not block:
            return
        yield block


def collect_sources(paths: list[Path]) -> list[Path]:
    out: list[Path] = []
    for p in paths:
        if p.is_dir():
            out.extend(sorted(p.rglob("*.txt")))
        elif p.exists():
            out.append(p)
        else:
            sys.exit(f"{p}: no such file or directory")
    return out


# --------------------------------------------------------------------------- #
# workers
# --------------------------------------------------------------------------- #


def _init(target: bytes) -> None:
    # macOS/Windows use spawn, so a module-level assignment in the parent would
    # not reach the workers -- the target has to be passed in explicitly.
    global _TARGET
    _TARGET = target


def _check(batch: list[str]) -> tuple[int, list[str]]:
    """Returns (candidates tried, hits) -- the count comes back so the progress
    line stays honest on a short final chunk."""
    hash160 = derive.hash160_from_passphrase
    target = _TARGET
    return len(batch), [p for p in batch if hash160(p) == target]


# --------------------------------------------------------------------------- #
# the run
# --------------------------------------------------------------------------- #


def run(candidates, pool, batch: int, label: str, hits_path: Path, target_address: str) -> list[str]:
    found: list[str] = []
    done = 0
    t0 = last = time.perf_counter()
    for tried, hits in pool.imap_unordered(_check, chunks(candidates, batch), chunksize=1):
        done += tried
        for phrase in hits:
            # Re-derive on this process before believing it.
            if derive.address_from_passphrase(phrase) != target_address:
                print(f"\nWARNING: worker flagged {phrase!r} but it does not verify -- ignoring", flush=True)
                continue
            line = f"*** PASSPHRASE FOUND *** {target_address}\n    {phrase!r}"
            print("\n" + line, flush=True)
            with hits_path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            found.append(phrase)
        now = time.perf_counter()
        if now - last > 2.0:
            last = now
            sys.stdout.write(f"\r  {label}: {done:,} tried, {done / (now - t0):,.0f}/s   ")
            sys.stdout.flush()
        if found:
            break
    elapsed = time.perf_counter() - t0
    sys.stdout.write(f"\r  {label}: {done:,} tried in {elapsed:.1f}s ({done / max(elapsed, 1e-9):,.0f}/s)\n")
    return found


def selftest(jobs: int, batch: int) -> int:
    """Positive control: hide a known passphrase in a stream and make sure it is found."""
    secret = "kitten-positive-control-42"
    target = derive.hash160_from_passphrase(secret)
    address = derive.encode_p2wpkh(target)
    print(f"planted passphrase : {secret!r}")
    print(f"its address        : {address}")
    stream = [f"decoy{i}" for i in range(5000)]
    stream.insert(3717, secret)
    with Pool(jobs, initializer=_init, initargs=(target,)) as pool:
        found = run(iter(stream), pool, batch, "selftest", Path(os.devnull), address)
    ok = found == [secret]
    print(f"\n{'SELFTEST PASSED' if ok else 'SELFTEST FAILED'}")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("sources", nargs="*", type=Path, help="wordlist files, or directories of *.txt")
    ap.add_argument("--stdin", action="store_true", help="read candidates from stdin, one per line")
    ap.add_argument("--mutate", action="store_true", help="expand each word with case/leet/affix variants")
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    ap.add_argument("--batch", type=int, default=20_000, help="candidates per worker task")
    ap.add_argument("--hits", type=Path, default=HERE / "HITS.txt")
    ap.add_argument("--state", type=Path, default=HERE / "stats_fast.txt")
    ap.add_argument("--no-resume", action="store_true")
    ap.add_argument("--target", default=derive.TARGET_ADDRESS,
                    help="override the target address (for positive-control runs)")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        return selftest(args.jobs, args.batch)
    if not args.sources and not args.stdin:
        ap.error("give at least one wordlist, a directory, or --stdin")

    try:
        target = derive.decode_p2wpkh(args.target)
    except ValueError as exc:
        sys.exit(f"--target {args.target}: {exc}")

    print(f"target   : {args.target}  (hash160 {target.hex()})")
    print(f"mnemonic : {derive.MNEMONIC}")
    print(f"path     : m/84'/0'/0'/0/0")
    print(f"workers  : {args.jobs}   batch: {args.batch:,}   mutate: {args.mutate}")

    done_files: set[str] = set()
    if args.state.exists() and not args.no_resume:
        done_files = {ln.strip() for ln in args.state.read_text(encoding="utf-8").splitlines() if ln.strip()}

    found: list[str] = []
    with Pool(args.jobs, initializer=_init, initargs=(target,)) as pool:
        if args.stdin:
            print("source   : stdin\n")
            found = run(expand((ln.rstrip("\r\n") for ln in sys.stdin), args.mutate),
                        pool, args.batch, "stdin", args.hits, args.target)
        else:
            files = collect_sources(args.sources)
            todo = [f for f in files if str(f) not in done_files]
            print(f"source   : {len(files)} file(s), {len(files) - len(todo)} already done\n")
            for path in todo:
                found = run(expand(read_lines(path), args.mutate),
                            pool, args.batch, str(path), args.hits, args.target)
                if found:
                    break
                with args.state.open("a", encoding="utf-8") as fh:
                    fh.write(str(path) + "\n")

    if found:
        print(f"\nSolved. Sweep {args.target} immediately -- see the README on fee/broadcast.")
        return 0
    print("\nNo match. Nothing found is still information: add what you ran to the README.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
