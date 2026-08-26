#!/usr/bin/env python3
"""
Where does the kernel's time actually go -- PBKDF2 or the BIP32/EC part?

Compiles passphrase_search.cl twice: once as shipped, and once truncated right
after the PBKDF2 loop (so it computes the seed and nothing else). The difference
is the cost of the 3 EC multiplications plus hash160.

This matters because the two halves want opposite optimizations, and which one
dominates is device-dependent:

    Apple M1 Max (24 CUs)   full ~21,000/s   PBKDF2-only ~43,500/s
                            -> PBKDF2 ~23 us, BIP32/EC ~24 us, i.e. a ~50/50 split
                            (reproducible across runs at --count 300000)

A 50/50 split is the least convenient answer: perfecting either half alone caps
out at a 2x overall gain, and PBKDF2's 2048 iterations are irreducible by
definition. Run this on a different GPU before optimizing anything there -- an
AMD/NVIDIA card with much better 32-bit integer throughput may land somewhere
else entirely.

Take a single reading with a grain of salt: an early one-off run of this
comparison reported PBKDF2-only at 110,000/s (a 20/80 split) and did not
reproduce. Use --count 300000 or more and repeat the run.

One thing already tried and rejected on Apple: moving the precomputed-basepoint
table (secp256k1_t, 384 bytes, one per work-item in private memory) into
__constant via SECP256K1_TMPS_TYPE. That measured 0.94x -- slower, not faster.
Worth re-testing on a device with real constant caches.

    python3 gpu/bench_split.py [--count 200000]
"""

from __future__ import annotations

import argparse
import sys
import time
import unicodedata
from pathlib import Path

import numpy as np
import pyopencl as cl

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import derive  # noqa: E402

# The full kernel's EC section starts here; everything from this line on is what
# the PBKDF2-only variant drops.
EC_SECTION_MARKER = "    secp256k1_t g_tmps;"


def sources() -> list[str]:
    full = (HERE / "passphrase_search.cl").read_text(encoding="utf-8")
    if EC_SECTION_MARKER not in full:
        sys.exit(f"passphrase_search.cl no longer contains {EC_SECTION_MARKER!r} -- "
                 "update EC_SECTION_MARKER in bench_split.py")
    # Keep the seed alive with a comparison the compiler cannot fold away, or it
    # will dead-code-eliminate the entire PBKDF2 loop and report a fake speed.
    pbkdf2_only = (
        full[: full.index(EC_SECTION_MARKER)]
        + "    match_flags[gid] = (T[0] == 0xff && T[1] == 0xff) ? 1 : 0;\n}\n"
    ).replace("search_passphrase", "search_pbkdf2_only")
    return [
        (HERE / "secp256k1_shim.cl").read_text(encoding="utf-8"),
        (HERE / "vendor" / "inc_ecc_secp256k1.h").read_text(encoding="utf-8"),
        (HERE / "vendor" / "inc_ecc_secp256k1.cl").read_text(encoding="utf-8")
            .replace('#include "inc_ecc_secp256k1.h"', ""),
        (HERE / "pbkdf2_sha512.cl").read_text(encoding="utf-8"),
        (HERE / "bip32_tree.cl").read_text(encoding="utf-8"),
        full,
        pbkdf2_only,
    ]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--count", type=int, default=200_000, help="candidates per timed dispatch")
    args = ap.parse_args()

    devices = [d for p in cl.get_platforms() for d in p.get_devices(device_type=cl.device_type.GPU)]
    if not devices:
        sys.exit("no OpenCL GPU device found")
    dev = devices[0]
    print(f"device: {dev.name} ({dev.max_compute_units} CUs)\n")
    ctx = cl.Context([dev])
    queue = cl.CommandQueue(ctx)
    program = cl.Program(ctx, "\n".join(sources())).build()

    mnemonic = unicodedata.normalize("NFKD", derive.MNEMONIC).encode()
    n = args.count
    cands = [f"bench{i}".encode() for i in range(n)]
    offsets = np.zeros(n + 1, dtype=np.uint32)
    offsets[1:] = np.cumsum([len(c) for c in cands], dtype=np.uint32)

    mf = cl.mem_flags
    buffers = [
        cl.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=np.frombuffer(mnemonic, dtype=np.uint8)),
        np.uint32(len(mnemonic)),
        cl.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=np.frombuffer(b"".join(cands), dtype=np.uint8)),
        cl.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=offsets),
        cl.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR,
                  hostbuf=np.frombuffer(derive.decode_p2wpkh(derive.TARGET_ADDRESS), dtype=np.uint8)),
        cl.Buffer(ctx, mf.WRITE_ONLY, size=n),
    ]

    rates = {}
    for name in ("search_passphrase", "search_pbkdf2_only"):
        kernel = cl.Kernel(program, name)
        kernel.set_args(*buffers)
        cl.enqueue_nd_range_kernel(queue, kernel, (1024,), None)
        queue.finish()  # warm up: first dispatch pays JIT/allocation costs
        t0 = time.perf_counter()
        cl.enqueue_nd_range_kernel(queue, kernel, (n,), None)
        queue.finish()
        dt = time.perf_counter() - t0
        rates[name] = n / dt
        print(f"  {name:20s} {n / dt:>10,.0f} cand/s   {dt * 1e6 / n:>6.1f} us each")

    us_full = 1e6 / rates["search_passphrase"]
    us_pbkdf2 = 1e6 / rates["search_pbkdf2_only"]
    us_ec = us_full - us_pbkdf2
    print(f"\n  PBKDF2 (2048 iters) : {us_pbkdf2:6.1f} us  ({us_pbkdf2 / us_full:5.1%})")
    print(f"  BIP32 + 3x EC + h160: {us_ec:6.1f} us  ({us_ec / us_full:5.1%})")
    print(f"\nOptimize the {'EC/BIP32' if us_ec > us_pbkdf2 else 'PBKDF2'} half on this device.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
