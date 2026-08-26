#!/usr/bin/env python3
"""
CPU passphrase search: dictionary files/directories, or a stdin stream.

    python3 bruteforce_fast.py --selftest              # prove it can find a known answer
    python3 bruteforce_fast.py wordlists/              # walk a directory for *.txt (recursively)
    python3 bruteforce_fast.py a.txt b.txt             # specific files
    python3 bruteforce_fast.py wordlists/ --mutate     # + case/leet/affix variants
    python3 bruteforce_fast.py wordlists/ --status     # what is done / pending, run nothing
    python3 bruteforce_fast.py wordlists/ --gpu        # run the search on the GPU (OpenCL)
    hashcat --stdout -r best66.rule rockyou.txt | python3 bruteforce_fast.py --stdin --gpu

`--gpu` runs the same candidate stream (directory walk with hash-based resume, or
stdin) through the OpenCL kernel in gpu/ instead of the CPU pool; it needs pyopencl
+ numpy and an OpenCL GPU. Every GPU hit is re-derived on the CPU before it counts.

Given a directory it walks that directory AND all subdirectories for *.txt files
and reads each line by line (over-long lines skipped). Each line is tested
verbatim as the BIP39 passphrase on all three paths (BIP84/44/49) -- add
casing/permutation variants as extra lines yourself, or pass --mutate for a small
automatic case/leet/affix expansion.

`--stdin` reads candidates from a pipe -- the recommended way to use hashcat's
rule engine for candidate generation (hashcat cannot derive the address; this does).

Resume is by file CONTENT HASH, not name: when a file is read to the end its
SHA-256 goes into the state file (default wordlist_state.json); next run, any
file that hashes to a recorded value is skipped -- so a dictionary is never
re-read even if renamed or moved, and duplicate copies are processed once. A file
interrupted midway is NOT recorded and is re-read in full, so a partial pass
never counts as done. (stdin has no state.) State keys are content hashes, so the
file is portable between machines.

Every hit is printed, appended to `--hits` (default HITS.txt), and re-derived and
re-checked against the full address before being reported -- never a false positive.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import time
from itertools import islice
from multiprocessing import Pool
from pathlib import Path

import derive

HERE = Path(__file__).resolve().parent
MAX_LINE_BYTES = 256
_TARGET: bytes = b""


# --------------------------------------------------------------------------- #
# candidate sources
# --------------------------------------------------------------------------- #

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
    """Text lines of a file, tolerant of non-UTF-8 bytes (rockyou has a few);
    over-long lines dropped (a passphrase is not a megabyte blob)."""
    with path.open("rb") as fh:
        for raw in fh:
            if len(raw) > MAX_LINE_BYTES + 2:
                continue
            yield raw.decode("utf-8", "surrogateescape").rstrip("\r\n")


def _stdin_lines():
    """Candidates from stdin, tolerant of non-UTF-8 bytes (rockyou has a few).

    Reading the raw buffer with surrogateescape means one malformed line is
    tested as its exact bytes instead of killing the pipe -- which is what a
    plain text-mode `for ln in sys.stdin` does partway through a 14 M-line feed.
    """
    for raw in sys.stdin.buffer:
        yield raw.decode("utf-8", "surrogateescape").rstrip("\r\n")


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


def collect_sources(paths: list[Path]) -> list[tuple[Path, str]]:
    """Every file to read, as (absolute path, display path).

    The display path is relative and rooted at the NAME of the directory you
    pointed at -- e.g. pointing at `.../SecLists` records
    `SecLists/Usernames/Names/x.txt`, not the machine-specific absolute path. It
    uses POSIX separators so the recorded name is identical on Windows and macOS.
    The display path is stored in the state file for convenience only; skipping is
    decided by the file's content hash, never by this string.
    """
    out: list[tuple[Path, str]] = []
    for p in paths:
        if p.is_dir():
            root = p
            for f in sorted(p.rglob("*.txt")):
                out.append((f, f"{root.name}/{f.relative_to(root).as_posix()}"))
        elif p.exists():
            out.append((p, p.name))
        else:
            sys.exit(f"{p}: no such file or directory")
    return out


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


# --------------------------------------------------------------------------- #
# state (keyed by file content hash, so names/paths/machines don't matter)
# --------------------------------------------------------------------------- #


def load_state(path: Path) -> dict:
    if path.exists():
        try:
            d = json.loads(path.read_text(encoding="utf-8"))
            d.setdefault("done", {})
            return d
        except (json.JSONDecodeError, OSError):
            print(f"warning: {path.name} unreadable, starting fresh", file=sys.stderr)
    return {"version": 1, "done": {}}


def _read_done(path: Path) -> dict:
    """Best-effort read of the on-disk 'done' map; empty on missing/corrupt file."""
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8")).get("done", {})
    except (json.JSONDecodeError, OSError):
        return {}


def _replace_with_retry(tmp: str, path: Path, attempts: int = 8, delay: float = 0.05) -> None:
    """os.replace() can transiently fail on Windows (WinError 5, PermissionError)
    when another process -- antivirus, an editor's file watcher, a cloud-sync
    client -- briefly has the target open without FILE_SHARE_DELETE. Frequent
    saves (brute-forcing many small wordlists means one save per file) raise
    the odds of colliding with one of these; retry with backoff instead of
    crashing the run over a momentary lock."""
    for attempt in range(attempts):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            if attempt == attempts - 1:
                raise
            time.sleep(delay * (attempt + 1))


def save_state(state: dict, path: Path) -> None:
    """Merge with whatever is on disk before writing, so a second process (or a
    run over a different set of sources) can never wipe out hashes recorded by
    another writer -- the file only ever grows."""
    state["done"] = {**_read_done(path), **state["done"]}
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".wordlist_state.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=1)
        _replace_with_retry(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


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


def drive(args, check) -> list[str]:
    """Shared driver for both backends: either the stdin stream, or the *.txt
    files under the sources with hash-based resume. `check(candidates, label)`
    runs one candidate stream and returns the passphrases found (empty if none).
    """
    if args.stdin:
        print("source   : stdin\n")
        return check(expand(_stdin_lines(), args.mutate), "stdin")

    state = {"version": 1, "done": {}} if args.no_resume else load_state(args.state)
    done_hashes = set(state["done"])
    files = collect_sources(args.sources)
    skipped_done = 0
    print(f"source   : {len(files)} *.txt file(s) under {', '.join(map(str, args.sources))}\n")
    for path, display in files:
        digest = file_sha256(path)
        if digest in done_hashes:
            skipped_done += 1
            continue
        found = check(expand(read_lines(path), args.mutate), display)
        if found:
            return found
        # only reached if the whole file was read with no hit. The hash is the
        # key (it decides skipping); the relative display path is stored only for
        # human convenience and never affects the run.
        state["done"][digest] = display
        save_state(state, args.state)
        done_hashes = set(state["done"])
    print(f"\nskipped {skipped_done} already-done; "
          f"{len(state['done'])} files recorded in {args.state.name}")
    return []


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
    ap.add_argument("sources", nargs="*", type=Path, help="files, or directories walked recursively")
    ap.add_argument("--stdin", action="store_true", help="read candidates from stdin, one per line")
    ap.add_argument("--gpu", action="store_true",
                    help="run the search on the GPU (OpenCL) instead of the CPU pool")
    ap.add_argument("--mutate", action="store_true", help="expand each line with case/leet/affix variants")
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    ap.add_argument("--batch", type=int, default=20_000, help="CPU: candidates per worker task")
    ap.add_argument("--gpu-batch", type=int, default=262_144, help="GPU: candidates per dispatch")
    ap.add_argument("--hits", type=Path, default=HERE / "HITS.txt")
    ap.add_argument("--state", type=Path, default=HERE / "wordlist_state.json")
    ap.add_argument("--no-resume", action="store_true", help="ignore state, re-read every file")
    ap.add_argument("--status", action="store_true", help="print done/pending files, run nothing")
    ap.add_argument("--target", default=derive.TARGET_ADDRESS,
                    help="override the target address (for positive-control runs)")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        return selftest(args.jobs, args.batch)
    if not args.sources and not args.stdin:
        ap.error("give at least one file, a directory, or --stdin")

    try:
        target = derive.decode_p2wpkh(args.target)
    except ValueError as exc:
        sys.exit(f"--target {args.target}: {exc}")

    # --- status view: no derivation, just what the state file says ---
    if args.status:
        if args.stdin or not args.sources:
            ap.error("--status needs file/directory sources")
        state = load_state(args.state)
        done = set(state["done"])
        for f, display in collect_sources(args.sources):
            mark, note = ("x", "done") if file_sha256(f) in done else (" ", "pending")
            print(f"  [{mark}] {display}  ({note})")
        return 0

    print(f"target   : {args.target}  (hash160 {target.hex()})")
    print(f"path     : m/84'/0'/0'/0/0   (checked on bip84/44/49)")

    if args.gpu:
        # The GPU host code lives in gpu/gpu_bruteforce.py; reuse its Searcher so
        # there is exactly one OpenCL implementation to keep correct.
        sys.path.insert(0, str(HERE / "gpu"))
        try:
            from gpu_bruteforce import Searcher
        except Exception as exc:  # noqa: BLE001 -- surface any import/OpenCL setup failure plainly
            sys.exit(f"--gpu: could not load the GPU backend ({exc}). "
                     "Needs pyopencl + numpy and an OpenCL GPU; run "
                     "`python gpu/gpu_bruteforce.py --selftest` to diagnose.")
        print(f"backend  : GPU   gpu-batch: {args.gpu_batch:,}   mutate: {args.mutate}")
        searcher = Searcher(args.target, args.gpu_batch)
        found = drive(args, lambda cands, label: searcher.run(cands, label, args.hits))
        if searcher.diverted:
            print(f"note: {searcher.diverted:,} over-length candidate(s) were checked on the CPU")
    else:
        print(f"backend  : CPU   workers: {args.jobs}   batch: {args.batch:,}   mutate: {args.mutate}")
        with Pool(args.jobs, initializer=_init, initargs=(target,)) as pool:
            found = drive(args, lambda cands, label: run(cands, pool, args.batch, label,
                                                         args.hits, args.target))

    if found:
        print(f"\nSolved. Sweep {args.target} immediately -- see the README on fee/broadcast.")
        return 0
    print("\nNo match. Nothing found is still information: add what you ran to the README.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
