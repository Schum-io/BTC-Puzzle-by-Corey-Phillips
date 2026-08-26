#!/usr/bin/env python3
"""
GPU passphrase search (OpenCL) for the Corey Phillips kitten puzzle.

Runs gpu/passphrase_search.cl over a stream of candidate passphrases. Same job
as ../bruteforce_fast.py, same verification discipline (every GPU hit is
re-derived on the CPU before it is believed), but sized for a real GPU.

    python3 gpu/gpu_bruteforce.py --selftest             # positive control, run this first
    python3 gpu/gpu_bruteforce.py --bench
    python3 gpu/gpu_bruteforce.py ../wordlists/
    hashcat --stdout -r best64.rule rockyou.txt | python3 gpu/gpu_bruteforce.py --stdin

Requires `pyopencl` and `numpy` plus an OpenCL GPU; `coincurve` is used for the
CPU-side verification of hits. On the machine this was developed on there is no
OpenCL device, so the kernel ships **unvalidated on hardware** -- run
`--selftest` once on the GPU box before trusting a "no match" result from it.
The self-test plants a known passphrase in the candidate stream and fails loudly
if the kernel does not find it, which catches a miscompile, a bad driver, or a
packing mistake.

Normalization: BIP39 applies NFKD to the passphrase. This host does that before
handing bytes to the device, so the kernel stays byte-oriented. Candidates
longer than MAX_PASS (192 bytes after NFKD+UTF-8) are diverted to the CPU
instead of being silently dropped -- the count of diverted candidates is
reported.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
import unicodedata
from itertools import islice
from pathlib import Path

import numpy as np
import pyopencl as cl

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import derive  # noqa: E402

MAX_PASS = 192  # must match passphrase_search.cl


# --------------------------------------------------------------------------- #
# device setup
# --------------------------------------------------------------------------- #


def make_context():
    for platform in cl.get_platforms():
        devices = platform.get_devices(device_type=cl.device_type.GPU)
        if devices:
            dev = devices[0]
            print(f"gpu backend: {dev.name} ({dev.max_compute_units} CUs)")
            return cl.Context([dev]), dev
    sys.exit("no OpenCL GPU device found")


def build_program(ctx):
    """Concatenate the OpenCL sources in dependency order, exactly as the
    poetry project's bench_search.py does (the vendored header is prepended
    directly, so its #include is stripped)."""
    parts = [
        (HERE / "secp256k1_shim.cl").read_text(encoding="utf-8"),
        (HERE / "vendor" / "inc_ecc_secp256k1.h").read_text(encoding="utf-8"),
        (HERE / "vendor" / "inc_ecc_secp256k1.cl").read_text(encoding="utf-8")
            .replace('#include "inc_ecc_secp256k1.h"', ""),
        (HERE / "pbkdf2_sha512.cl").read_text(encoding="utf-8"),
        (HERE / "bip32_tree.cl").read_text(encoding="utf-8"),
        (HERE / "passphrase_search.cl").read_text(encoding="utf-8"),
    ]
    return cl.Program(ctx, "\n".join(parts)).build()


# --------------------------------------------------------------------------- #
# runner
# --------------------------------------------------------------------------- #


class Searcher:
    def __init__(self, target_address: str, batch: int):
        self.target_address = target_address
        self.target20 = derive.decode_p2wpkh(target_address)
        self.batch = batch
        self.ctx, self.device = make_context()
        self.queue = cl.CommandQueue(self.ctx)
        self.kernel = cl.Kernel(build_program(self.ctx), "search_passphrase")

        mnemonic = unicodedata.normalize("NFKD", derive.MNEMONIC).encode()
        mf = cl.mem_flags
        self.mnemonic_len = np.uint32(len(mnemonic))
        self.d_mnemonic = cl.Buffer(self.ctx, mf.READ_ONLY | mf.COPY_HOST_PTR,
                                    hostbuf=np.frombuffer(mnemonic, dtype=np.uint8))
        self.d_target = cl.Buffer(self.ctx, mf.READ_ONLY | mf.COPY_HOST_PTR,
                                  hostbuf=np.frombuffer(self.target20, dtype=np.uint8))
        self.tried = 0
        self.diverted = 0   # candidates too long for the kernel, checked on CPU
        self.found: list[str] = []

    def _run_batch(self, cands: list[str]) -> None:
        # NFKD is a no-op on ASCII, and essentially every candidate a wordlist or
        # a hashcat mask produces is ASCII. Skipping the call there keeps this
        # host loop from becoming the bottleneck on a fast device -- at 10^5
        # candidates/s the per-candidate Python work is no longer free.
        encoded = [c.encode() if c.isascii() else derive._passphrase_bytes(c)
                   for c in cands]

        # Long candidates are rare; check them here rather than sizing every
        # device buffer for the worst case.
        gpu_idx, gpu_bytes = [], []
        for i, b in enumerate(encoded):
            if len(b) <= MAX_PASS:
                gpu_idx.append(i)
                gpu_bytes.append(b)
            else:
                self.diverted += 1
                if derive.hash160_from_passphrase(cands[i]) == self.target20:
                    self._record(cands[i])
        if not gpu_bytes:
            self.tried += len(cands)
            return

        offsets = np.zeros(len(gpu_bytes) + 1, dtype=np.uint32)
        offsets[1:] = np.cumsum([len(b) for b in gpu_bytes], dtype=np.uint32)
        blob = np.frombuffer(b"".join(gpu_bytes) or b"\x00", dtype=np.uint8)

        mf = cl.mem_flags
        d_blob = cl.Buffer(self.ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=blob)
        d_off = cl.Buffer(self.ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=offsets)
        d_flags = cl.Buffer(self.ctx, mf.WRITE_ONLY, size=len(gpu_bytes))

        self.kernel.set_args(self.d_mnemonic, self.mnemonic_len, d_blob, d_off,
                             self.d_target, d_flags)
        evt = cl.enqueue_nd_range_kernel(self.queue, self.kernel, (len(gpu_bytes),), None)
        flags = np.empty(len(gpu_bytes), dtype=np.uint8)
        cl.enqueue_copy(self.queue, flags, d_flags, wait_for=[evt])
        self.queue.finish()

        for pos in np.nonzero(flags)[0]:
            phrase = cands[gpu_idx[int(pos)]]
            # A kernel bug can only ever cost time, never a false "no hit":
            # the CPU has the last word on anything the GPU flags.
            if derive.address_from_passphrase(phrase) == self.target_address:
                self._record(phrase)
            else:
                print(f"\nWARNING: GPU flagged {phrase!r} but the CPU did not confirm it. "
                      f"The kernel is wrong -- do not trust a 'no match' from this build. "
                      f"Run --selftest.", flush=True)
        self.tried += len(cands)

    def _record(self, phrase: str) -> None:
        line = f"*** PASSPHRASE FOUND *** {self.target_address}\n    {phrase!r}"
        print("\n" + line, flush=True)
        self.found.append(phrase)

    def run(self, candidates, label: str, hits_path: Path | None) -> list[str]:
        t0 = last = time.perf_counter()
        start_tried = self.tried
        it = iter(candidates)
        while True:
            block = list(islice(it, self.batch))
            if not block:
                break
            self._run_batch(block)
            now = time.perf_counter()
            if now - last > 2.0:
                last = now
                n = self.tried - start_tried
                sys.stdout.write(f"\r  {label}: {n:,} tried, {n / (now - t0):,.0f}/s   ")
                sys.stdout.flush()
            if self.found:
                break
        elapsed = time.perf_counter() - t0
        n = self.tried - start_tried
        sys.stdout.write(f"\r  {label}: {n:,} tried in {elapsed:.1f}s "
                         f"({n / max(elapsed, 1e-9):,.0f}/s)\n")
        if hits_path is not None:
            for phrase in self.found:
                with hits_path.open("a", encoding="utf-8") as fh:
                    fh.write(f"{self.target_address}\n    {phrase!r}\n")
        return self.found


# --------------------------------------------------------------------------- #
# candidate sources (kept identical in behaviour to bruteforce_fast.py)
# --------------------------------------------------------------------------- #


def _stdin_lines():
    """Candidates from stdin, tolerant of non-UTF-8 bytes (see bruteforce_fast.py)."""
    for raw in sys.stdin.buffer:
        yield raw.decode("utf-8", "surrogateescape").rstrip("\r\n")


def read_lines(path: Path):
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            yield line.rstrip("\r\n")


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
# self-test and benchmark
# --------------------------------------------------------------------------- #


def selftest(batch: int) -> int:
    """Plant a known passphrase in the stream; the kernel must find exactly it.

    Also checks a long candidate (> MAX_PASS) so the CPU-divert path is
    exercised, and confirms the kernel does NOT flag anything else.
    """
    secret = "kitten-positive-control-42"
    long_secret = "x" * (MAX_PASS + 40)
    address = derive.address_from_passphrase(secret)
    long_address = derive.address_from_passphrase(long_secret)
    print(f"planted passphrase : {secret!r}")
    print(f"its address        : {address}")

    ok = True
    stream = [f"decoy{i}" for i in range(20_000)]
    stream[13_337] = secret
    stream[19_000] = long_secret

    s = Searcher(address, batch)
    found = s.run(iter(stream), "selftest (short secret)", None)
    if found == [secret]:
        print("  [PASS] kernel found the planted passphrase")
    else:
        ok = False
        print(f"  [FAIL] expected [{secret!r}], got {found!r}")

    s2 = Searcher(long_address, batch)
    found2 = s2.run(iter(stream), "selftest (long secret, CPU divert)", None)
    if found2 == [long_secret]:
        print(f"  [PASS] over-length candidate diverted to CPU and found "
              f"({s2.diverted} diverted)")
    else:
        ok = False
        print(f"  [FAIL] over-length candidate not found: {found2!r}")

    s3 = Searcher(derive.TARGET_ADDRESS, batch)
    found3 = s3.run(iter(stream[:5000]), "selftest (no false positives)", None)
    if not found3:
        print("  [PASS] no false positive against the real target")
    else:
        ok = False
        print(f"  [FAIL] false positive: {found3!r}")

    print(f"\n{'SELFTEST PASSED -- results from this build can be trusted' if ok else 'SELFTEST FAILED -- do not trust this build'}")
    return 0 if ok else 1


def benchmark(batch: int, total: int) -> int:
    s = Searcher(derive.TARGET_ADDRESS, batch)
    s.run((f"bench{i}" for i in range(total)), f"bench ({total:,} candidates)", None)
    print(f"\nbatch size {batch:,}. Increase --batch until the rate stops improving.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("sources", nargs="*", type=Path, help="wordlist files, or directories of *.txt")
    ap.add_argument("--stdin", action="store_true", help="read candidates from stdin, one per line")
    ap.add_argument("--batch", type=int, default=262_144, help="candidates per GPU dispatch")
    ap.add_argument("--hits", type=Path, default=HERE.parent / "HITS.txt")
    ap.add_argument("--state", type=Path, default=HERE.parent / "stats_gpu.txt")
    ap.add_argument("--no-resume", action="store_true")
    ap.add_argument("--target", default=derive.TARGET_ADDRESS)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--bench", type=int, nargs="?", const=1_000_000, metavar="N",
                    help="time N candidates (default 1,000,000)")
    args = ap.parse_args()

    if args.selftest:
        return selftest(min(args.batch, 20_000))
    if args.bench:
        return benchmark(args.batch, args.bench)
    if not args.sources and not args.stdin:
        ap.error("give at least one wordlist, a directory, or --stdin")

    try:
        derive.decode_p2wpkh(args.target)
    except ValueError as exc:
        sys.exit(f"--target {args.target}: {exc}")

    searcher = Searcher(args.target, args.batch)
    print(f"target   : {args.target}")
    print(f"path     : m/84'/0'/0'/0/0   batch: {args.batch:,}")

    done_files: set[str] = set()
    if args.state.exists() and not args.no_resume:
        done_files = {ln.strip() for ln in args.state.read_text(encoding="utf-8").splitlines() if ln.strip()}

    if args.stdin:
        print("source   : stdin\n")
        searcher.run(_stdin_lines(), "stdin", args.hits)
    else:
        files = collect_sources(args.sources)
        todo = [f for f in files if str(f) not in done_files]
        print(f"source   : {len(files)} file(s), {len(files) - len(todo)} already done\n")
        for path in todo:
            searcher.run(read_lines(path), str(path), args.hits)
            if searcher.found:
                break
            with args.state.open("a", encoding="utf-8") as fh:
                fh.write(str(path) + "\n")

    if searcher.diverted:
        print(f"note: {searcher.diverted:,} candidate(s) exceeded {MAX_PASS} bytes "
              f"and were checked on the CPU instead")
    if searcher.found:
        print(f"\nSolved. Sweep {args.target} immediately -- see the README on fee/broadcast.")
        return 0
    print("\nNo match.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
