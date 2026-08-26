# BTC Puzzle by Corey Phillips — passphrase brute-force toolkit

Tools to brute-force the BIP39 passphrase of the [Corey Phillips kitten puzzle](https://corey-lyle-phillips.medium.com/part-1-3-turn-your-photos-into-bitcoin-private-keys-addresses-57669771cf7a).

| | |
|---|---|
| Target address | `bc1qcyrndzgy036f6ax370g8zyvlw86ulawgt0246r` (0.01 BTC, unspent) |
| Unknown | **only the BIP39 passphrase** — the 24-word mnemonic and the path `m/84'/0'/0'/0/0` are fixed and public |
| Mnemonic | `blossom educate state course sick fresh color divide number soap please pull glide weather join grit depart dynamic tenant leopard alter piano slight room` |

Each candidate = one passphrase; the derivation is
`PBKDF2-HMAC-SHA512(mnemonic, "mnemonic"+passphrase, 2048)` → `m/84'/0'/0'/0/0` →
P2WPKH address, compared against the target. The search checks all three common
purposes (BIP84/44/49) per candidate.

Background (not needed to run the tools): [docs/algorithm.md](docs/algorithm.md) —
the exact derivation, the canonical image, on-chain facts;
[docs/analysis.md](docs/analysis.md) — passphrase hypotheses, everything already
ruled out, and what's left to try.

---

## Setup

```bash
python3.13 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Use **Python 3.13 or older** — `coincurve` has no `cp314` wheel, so on 3.14 pip
tries a source build that fails. `pyopencl`/`numpy` are only needed for the GPU
search. EC math uses `coincurve` (libsecp256k1, C); PBKDF2 uses `hashlib` (OpenSSL).

Verify the toolkit reproduces the puzzle before trusting any run:

```bash
.venv/bin/python derive.py --selftest       # article sha256 + address, BIP84 vector, bech32
.venv/bin/python derive.py "some passphrase" # print the address for one passphrase
```

---

## Dictionary brute force — `bruteforce_fast.py`

Point it at files or a directory (walked recursively for `*.txt`), or feed a
stream on stdin. Each line is tested verbatim as the passphrase; add your own
casing/spacing/permutation variants as extra lines, or pass `--mutate` for a
small automatic case/leet/affix expansion.

```bash
python3 bruteforce_fast.py --selftest              # positive control (must find a planted secret)
python3 bruteforce_fast.py /path/to/SecLists       # walk the tree for *.txt, resume automatically
python3 bruteforce_fast.py /path/to/SecLists --gpu # same, on the GPU (OpenCL) instead of the CPU pool
python3 bruteforce_fast.py /path/to/SecLists --status # what is done / pending, run nothing
python3 bruteforce_fast.py a.txt b.txt --mutate    # specific files + variants
```

* `--gpu` routes the same stream through the OpenCL kernel in `gpu/` (needs
  pyopencl + numpy + an OpenCL GPU). Every GPU hit is re-derived on the CPU before
  it counts, so a kernel bug can never produce a false "found".
* `--jobs N` / `--batch N` (CPU), `--gpu-batch N` (GPU) tune throughput.
* A found passphrase is printed and appended to `HITS.txt`.

**Resume is by file content hash, not name** (`wordlist_state.json`). When a file
is read to the end its SHA-256 is recorded; next run, any file that hashes to a
recorded value is skipped — so a dictionary is never re-read even if renamed or
moved, and duplicate copies are processed once. The state stores `hash → path`,
where the path is relative and rooted at the directory you pointed at
(`SecLists/Usernames/Names/x.txt`, POSIX separators) — but only the hash decides
skipping; the path is for your convenience and never affects the run. A file
interrupted midway is not recorded and is re-read in full. (stdin has no state.)

Feed hashcat's rule engine through stdin when you want mangling rules:

```bash
hashcat --stdout -r best66.rule rockyou.txt | python3 bruteforce_fast.py --stdin
hashcat --stdout -r best66.rule rockyou.txt | python3 bruteforce_fast.py --stdin --gpu
```

---

## Rule sweeps — `run_plan.py`

Drives large hashcat-generated sweeps: hashcat emits candidates (`--stdout`:
wordlist × rules, no cracking), piped into the derivation search — hashcat cannot
turn a mnemonic+passphrase into an address, so our code does that. Cross-platform
(Windows/macOS/Linux), no shell needed.

Point it at your files once (flags or environment variables), then pick a tier:

```bash
# macOS / Linux
export KITTEN_HASHCAT=/path/to/hashcat        # or auto-detected from PATH
export KITTEN_ROCKYOU=/path/to/rockyou.txt
python3 run_plan.py A --search gpu            # run tier A on the GPU
python3 run_plan.py A --status               # units done / pending, run nothing
python3 run_plan.py A --dry-run              # print the per-chunk commands
```

```powershell
# Windows PowerShell
$env:KITTEN_HASHCAT="C:\tools\hashcat\hashcat.exe"
$env:KITTEN_ROCKYOU="C:\wordlists\rockyou.txt"
python run_plan.py A --search gpu
```

| Tier | Candidates |
|---|---|
| A | `rockyou.txt` × `dive` |
| B | `rockyou.txt` × `d3ad0ne` |
| C | `xato-10M` × `best66` (needs `KITTEN_XATO`) |
| D | SecLists language lists × `best66` (needs `KITTEN_LANGDIR`) |

* Paths: `--hashcat`, `--rules`, `--rockyou`, `--xato`, `--langdir` (or the
  matching `KITTEN_*` env vars). Rules dir is auto-detected next to the hashcat
  binary. `--search cpu` (default) or `--search gpu`.
* Device: left to hashcat on Windows/Linux, pinned to `-d 1` on macOS (Apple's
  OpenCL GPU can't build hashcat's kernel); override with `--hashcat-device`.

**Resume (`run_plan_state.json`).** A tier is split into units — each wordlist
chunked into `--chunk-words` ranges (default 2,000,000) via hashcat `--skip`/`--limit`.
The chunking is exact (the chunks' union is byte-for-byte the whole keyspace), so
nothing is skipped or double-counted. A completed unit is recorded and skipped next
time; a unit interrupted midway is **not** recorded and re-runs in full. Keep
`--chunk-words` to a size you're willing to redo.

`run_plan_state.json` is committed to git on purpose so one machine continues where
another left off: commit, push, `git pull` on the other box, run again. Unit keys
use the tier's role (`rockyou`/`xato`) and the wordlist keyspace, not the file path,
so progress is shared even if the files live elsewhere. `HITS.txt` is git-ignored —
a found key must never be pushed.

```bash
python3 run_plan.py A --search gpu   # runs only the not-yet-done chunks
python3 run_plan.py A --no-resume    # ignore state, redo the whole tier
```

---

## GPU kernel — `gpu/`

`gpu/passphrase_search.cl` is one work-item per candidate: PBKDF2 → `m/84'/0'/0'/0/0`
→ hash160 → compare. It reuses `pbkdf2_sha512.cl`, `bip32_tree.cl` and hashcat's
vendored secp256k1 (`gpu/vendor/NOTICE.md`).

```bash
python3 gpu/gpu_bruteforce.py --selftest       # RUN THIS FIRST on any new device
python3 gpu/gpu_bruteforce.py --bench          # candidates/s on this GPU
python3 gpu/bench_split.py --count 300000      # is PBKDF2 or EC the bottleneck here?
```

`--selftest` is a positive control: it plants a known passphrase and fails loudly if
the kernel doesn't find it. A "no match" from a build that hasn't passed it means
nothing — run it once per machine before trusting results.

---

## Files

| Path | Purpose |
|---|---|
| `derive.py` | the key derivation, used by every tool (`--selftest`, `--bench`) |
| `bruteforce_fast.py` | CPU/GPU dictionary search (directory walk, hash-based resume, stdin) |
| `run_plan.py` | hashcat-driven rule sweeps, chunked resume, cross-machine state |
| `gpu/` | OpenCL kernel + host + benchmarks |
| `kitten.jpeg` | the puzzle image (its base64's sha256 is the BIP39 entropy) |
| `run_plan_state.json`, `wordlist_state.json` | resume state (committed, portable) |
| `HITS.txt` | any found passphrase (git-ignored) |

If you find this useful, you can donate BTC at `bc1qezsaphs22e278n235dyw46jyya58352eyk095q`
