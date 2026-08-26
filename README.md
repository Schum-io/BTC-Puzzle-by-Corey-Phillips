# BTC Puzzle by Corey Phillips — hints & analysis

This repository collects the publicly known facts and hints about the BTC Puzzle by Corey Phillips,
plus a verified reference implementation of the key-derivation algorithm. Contributions are welcome!

If you find this useful, you can donate BTC at `bc1qezsaphs22e278n235dyw46jyya58352eyk095q`

---

# Summary

| | |
|---|---|
| Prize | **0.01 BTC** (currently 1,001,900 sat, see [On-chain facts](#on-chain-facts)) |
| Creator | Corey Phillips ([@coreylphillips](https://twitter.com/coreylphillips), [github](https://github.com/coreyphillips)) |
| Article | [Part 1/3: Turn Your Photos Into Bitcoin Private Keys/Addresses](https://corey-lyle-phillips.medium.com/part-1-3-turn-your-photos-into-bitcoin-private-keys-addresses-57669771cf7a) (2019-07-09) |
| Funded | 2019-06-28 (11 days **before** the article was published) |
| Target address | `bc1qcyrndzgy036f6ax370g8zyvlw86ulawgt0246r` |
| Status | **unsolved**, UTXOs unspent |
| What is unknown | **only the BIP39 passphrase.** The mnemonic, the derivation path and the address type are all known. |

> Note: an earlier version of this README listed the target as `bc1qcyrndzgy036f6ax370g8zyvlw86ulawgt0246`
> (missing the final `r`). That string is **not a valid bech32 address** — its checksum fails. The correct
> address is 42 characters and ends in `...gt0246r`. `bruteforce.py` always had the correct one.

# Description

From the article (verbatim, emphasis added):

> The mnemonic for the kitten photo without a passphrase contains roughly 0.00095133 BTC. Feel free to
> claim it if you manage to sweep the keys in time.
>
> To prove the viability of this method, I have also sent 0.01 BTC to the following address,
> "bc1qcyrndzgy036f6ax370g8zyvlw86ulawgt0246r". This address was generated using the kitten image along
> with a BIP39 passphrase. **Remember, this is not meant to be solved. It is meant to prove the viability
> of this method**, but if you somehow manage to claim it, congrats!

That last sentence is the single most informative statement anybody has about the passphrase — see
[What can the passphrase be?](#what-can-the-passphrase-be).

![kitten.jpeg](kitten.jpeg)

---

# The exact algorithm (verified)

The reference implementation is Corey's own demo page,
[coreyphillips/bitimage](https://github.com/coreyphillips/bitimage) (`index.html`). Verbatim from it:

```js
picReader.readAsDataURL(file);                       // "data:image/jpeg;base64,<b64>"
var n = 0, word = ",";
if (file.includes(word)) n = file.lastIndexOf(word); // strip the data-URI prefix
if (n > 0) file = file.slice(n + word.length, file.length);

var hash     = Bitcoin.crypto.sha256(file);         // sha256 over the ASCII base64 TEXT
var mnemonic = bip39.entropyToMnemonic(hash);       // 32 bytes -> 24 words
bip39.mnemonicToSeed(mnemonic, passphrase)          // PBKDF2-HMAC-SHA512, 2048 iters, salt "mnemonic"+pass
  .then(function (seed) {
     var root = bip32.fromSeed(seed, Bitcoin.networks.bitcoin);
     var p2shAddressPath   = `m/49'/0'/0'/0/0`;     // p2sh-p2wpkh  (3...)
     var bech32AddressPath = `m/84'/0'/0'/0/0`;     // p2wpkh       (bc1q...)  <-- the puzzle
  });
```

Step by step:

1. Read the file, base64-encode it (the data-URI prefix before the `,` is discarded).
2. `sha256` **of the base64 string as ASCII text** — not of the raw file bytes. This is the step people
   get wrong most often.
3. Feed those 32 bytes to BIP39 `entropyToMnemonic` → a 24-word mnemonic.
4. `mnemonicToSeed(mnemonic, passphrase)` → BIP39 seed. Both mnemonic and passphrase are NFKD-normalized;
   the PBKDF2 salt is the literal string `"mnemonic"` + passphrase.
5. Derive `m/84'/0'/0'/0/0`, take the compressed pubkey, hash160, encode as bech32 v0 → `bc1q...`.

## Is `main.py` correct? Yes — verified

`main.py` reproduces the article's published intermediate values *and* final address exactly:

| Value | `main.py` output | Article | Match |
|---|---|---|---|
| sha256 of the base64 text | `1808d35318ac7cb98b69ff9779b699d6a631f15e0b353ac89b7c4020774832ed` | same | ✅ |
| Address `m/84'/0'/0'/0/0` | `bc1q57euh23y3qs2f9d5mtwpax5lqecfvrdkqce82a` | same | ✅ |
| WIF | `L4WjYfoAmnEwaHAePLvr5gXUVmwNsFjALJNfpP3akrnHgxdWQekC` | — | — |

The 24-word mnemonic for `kitten.jpeg` with **no** passphrase:

```
blossom educate state course sick fresh color divide number soap please pull
glide weather join grit depart dynamic tenant leopard alter piano slight room
```

This is also the `KITTEN_MNEMONIC` constant in `bruteforce.py` / `mnemonic_variants.py` — confirmed identical.

Notes on the JS ↔ Python equivalence, all checked:

* `lastIndexOf(",")` vs Python's `split(b",", 1)` — the base64 alphabet contains no comma, so a data URI
  has exactly one; both are equivalent for any input file.
* `Bitcoin.crypto.sha256(file)` is called on a **JS string**; browserify's hash defaults to UTF-8, and
  base64 is pure ASCII, so it equals `hashlib.sha256(b64_bytes)`.
* `entropyToMnemonic` accepts the 32-byte Buffer; `Bip39MnemonicGenerator().FromEntropy(digest)` is the same.
* `bip_utils`' `Bip39SeedGenerator(...).Generate(passphrase)` and `Bip84` implement the same NFKD +
  PBKDF2 + BIP32/BIP84 as `bip39`/`bip32`/`bitcoinjs-lib`. Verified against an independent from-scratch
  implementation (pbkdf2 + HMAC-SHA512 + coincurve + hand-rolled bech32): identical addresses.

# Canonical input file

**The #1 reason people fail to reproduce the puzzle is using the wrong rendition of the image.** Every
re-encode (Twitter/Medium/imgur resize, "Save image as…" from a browser that re-compresses, EXIF stripping)
changes the bytes → changes the base64 → changes the sha256 → produces a completely different mnemonic.
Two commenters under the article hit exactly this (`bc1qasptyrp0xyjxzz95q9cr32y2pdptqlwekgww9x` and a
mnemonic starting `elite usual surround kiwi…` are both *wrong-rendition* artifacts).

`kitten.jpeg` in this repo is the correct file. Verify before you spend CPU on anything:

```
sha256(base64(file))  1808d35318ac7cb98b69ff9779b699d6a631f15e0b353ac89b7c4020774832ed  <- matches the article
sha256(file bytes)    b988e0881a0211222e83f3e2a4bfac695c951bf96aa33ec112fab6992f5e7343
sha1(file bytes)      fc7477df0b2b1670e19b006a0d319795178708ec
md5(file bytes)       ed08111b53debb7e318ad53ea9c9d3a6
size                  265456 bytes
dimensions            1200 x 667, progressive DCT (SOF2), YCbCr 4:2:0, JFIF only, no EXIF
```

# On-chain facts

**Target `bc1qcyrndzgy036f6ax370g8zyvlw86ulawgt0246r`** — 2 UTXOs, 1,001,900 sat, nothing ever spent:

* `c3a8c1eedc3512cc92e8798eb240d81bcb2446dfe91339bbafd5e9687c3c663d` — 2019-06-28, block 582796,
  **1,000,000 sat** from Corey. Change of that tx went to `bc1qzlhye4uzzxfa0mr0h36ksc5mzme4v87wm3qf7z`
  (i.e. that is Corey's own wallet address).
* `1e4c42f9aedfbdea00c2134af18de6d449a1a88565486a4de5b749634ecc07d8` — 2025-04-11, **1,900 sat** of spam
  from `1HELPMEyb9z5UrogyyfP6Twpk3Q6H9QJTL` with an OP_RETURN reading
  *"Please help me with any money. I am very grateful in advance!"*. Unrelated to the puzzle.

**No-passphrase address `bc1q57euh23y3qs2f9d5mtwpax5lqecfvrdkqce82a`** — empty:

* 2019-07-02: funded with 95,133 sat from `bc1qzlhye4uzzxfa0mr0h36ksc5mzme4v87wm3qf7z` (same Corey wallet).
* 2019-07-09: swept the same day the article went live — 89,787 sat to `bc1qfadx3xadzawp0fzspaglreg332jzfgxsu4gm9w`.
* 2024-09-22: received 320,000 sat in an unrelated batch payout, swept within the same day.

Takeaway: the demo address is picked clean within hours of anything landing there. Any solver of the real
puzzle is racing bots; use a high fee rate and, ideally, submit via a direct/private broadcast.

---

# What can the passphrase be?

## Format: technically unconstrained

A BIP39 passphrase is **not** a mnemonic. It is an arbitrary UTF-8 string used as PBKDF2 salt suffix:

```
seed = PBKDF2-HMAC-SHA512(password = NFKD(mnemonic), salt = "mnemonic" + NFKD(passphrase), c = 2048, dkLen = 64)
```

Consequences for the search:

* **No wordlist constraint.** It does not have to be BIP39 words, English words, or words at all.
* **No length constraint.** `""`, `"a"`, a 200-character sentence and a 32-byte random string are all valid.
* **Case, spaces, punctuation and Unicode all matter**, but NFKD normalization means visually-equal
  Unicode variants collapse (e.g. precomposed vs. decomposed accents, some full-width forms).
* Corey entered it by hand into an `<input type="text">` on his own demo page, so it is a **typeable
  string**, and it must have been fixed before 2019-06-28 (the funding date), i.e. **before the article
  was published**.

So the answer to *"is it one word, several words, or a set of symbols?"* is: **all three remain possible**,
and nothing in the article, the image or the repo narrows it structurally. What narrows it is the negative
evidence below.

## What the author said

The article frames the 0.01 BTC not as a puzzle with a findable answer, but as a **demonstration that a
passphrase protects funds even when the file is public**: *"Remember, this is not meant to be solved. It is
meant to prove the viability of this method."* He also never posted a hint, never answered the question when
it was asked in the comments (2024-04-15), and — unlike his 2020
[Bitcoin Audio Puzzle](https://corey-lyle-phillips.medium.com/a-bitcoin-audio-puzzle-61174b9849ce) — never
called this one a puzzle at all.

**Working conclusion:** this is most likely a private password of the author's own choosing, not an
encoded answer hidden in the article, the image, or the repo. Treat "find the hidden clue" theories as
low-probability and "guess a human-chosen password" as the main line of attack — while accepting that if
he used a password manager, it is unrecoverable.

## Ranked hypotheses

| # | Hypothesis | Assessment |
|---|---|---|
| 1 | A hand-picked password of his own, not derived from any public material | Most likely. Consistent with "not meant to be solved" and with 6+ years of failed dictionary attacks. |
| 2 | A multi-word phrase with case/punctuation from his own writing (e.g. the demo page's own tagline *"A picture is worth a thousand satoshis"*) | Plausible, cheap to test — the obvious forms are already ruled out (see below). Needs rule-based mutation, not plain wordlists. |
| 3 | Machine-random string from a password manager | Plausible and fatal. Unfalsifiable except by exhausting everything else. |
| 4 | Something recoverable from steganography in the image | **Very unlikely** — see below. |
| 5 | Words of the kitten mnemonic itself, reordered/subset | Partly ruled out (`mnemonic_variants.py`, permutations up to 4–5 words). |

## Ruled out by measurement

* **It is not a derivation-path trick.** 25,000 derivation paths of the *no-passphrase* seed were
  enumerated (`m/{84',49',44',0'}/0'/{0..5}'/{0,1}/{0..499}`, plus `m/i` and `m/0/i`). The target address
  is in none of them → a non-empty passphrase really is involved.
* **The image contains no plain stego container.** `kitten.jpeg` has no EXIF, no APP1/APP13/COM segment,
  no bytes appended after the `FFD9` end-of-image marker, and zero printable ASCII runs ≥20 chars;
  `binwalk` finds only the JPEG itself. It is a re-encoded 1200-px progressive rendition, so any
  coefficient-domain (LSB/F5/steghide-style) payload from Antonopoulos' original 2015 tweet would not have
  survived the re-compression. And even in the original, that payload was a *signed transaction* which
  Antonopoulos said was *"encrypted first"* — it was never Corey's passphrase. (Not attempted here for
  lack of tooling: `steghide`/`outguess`/`zsteg` extraction. Cheap to try if you have them, low expected value.)
* **The obvious semantic candidates are gone.** Two targeted runs completed with no match:
  * 1,414 hand-picked strings — every phrase and heading from the article and the bitimage repo
    (incl. *"A picture is worth a thousand satoshis"*), his own names/handles/projects
    (`bitimage`, `bitbip`, `kisswallet`, `coreylphillips`), Antonopoulos' name/handle/tweet id
    `603701870482300928`, cat vocabulary, the publication and funding dates, the mnemonic itself, the
    sha256 hex, both addresses and the WIF — each in lower/upper/title case, with separators
    (`""`, `-`, `_`, `.`, `+`) and with `!`/`1`/`123`/`2019`/`?`/`.` suffixes.
  * 212,562 themed 1–2 token combinations over a 48-word vocabulary (cat / bitcoin / crypto /
    author / stego terms) × 5 separators × 3 cases × 6 suffixes.

# Search space & throughput

Measured on a 10-core M-series Mac (M1 Max). Per candidate the work is 2048 HMAC-SHA512 iterations plus
three secp256k1 multiplications, and on this hardware those two halves cost about the same — see
`gpu/bench_split.py`:

| Implementation | Rate |
|---|---|
| `bruteforce.py` (`bip_utils`) | ~1,100 candidates/s per core |
| `derive.py` (`hashlib.pbkdf2_hmac` + `coincurve` + hand-rolled bech32) | ~1,600 candidates/s per core |
| `bruteforce_fast.py`, 9 worker processes | **~13,000 candidates/s** |
| `gpu/passphrase_search.cl` on the same machine's GPU (Apple M1 Max, 24 CUs) | ~21,000 candidates/s |

What that buys you, i.e. why the puzzle is still alive:

| Space | Size | Time at 13k/s |
|---|---|---|
| `rockyou.txt` | 14.3 M | ~18 min |
| all wordlists currently in `wordlists/` | 709 K | ~1 min |
| every lowercase a–z string ≤ 6 chars | 321 M | ~7 hours |
| every lowercase a–z string ≤ 8 chars | 217 G | ~530 years |
| 8 chars, full 95-char printable ASCII | 6.7 × 10¹⁵ | ~16 million years |

**A GPU helps much less here than the usual "just use hashcat" advice suggests, and it is worth being
precise about why.** Measured with `gpu/bench_split.py` on the M1 Max, the per-candidate cost splits about
50/50 between PBKDF2's 2048 HMAC-SHA512 iterations and the BIP32 derivation's 3 secp256k1 multiplications.
PBKDF2 at a fixed iteration count is irreducible, so even a perfect EC implementation caps out at 2x. An
integer-heavy discrete GPU does far better than an Apple one — the sibling kernels this was ported from
reach ~18,000 candidates/s on a Radeon 7900 XTX while testing *46* derivation nodes per candidate, so this
kernel's 3 nodes should land around 10⁵/s there — but that is still only ~10x a 10-core CPU, i.e. it moves
the brute-force wall by roughly one character. That extrapolation is unmeasured; run `gpu/bench_split.py`
on the card and replace this paragraph with the real number.

Two things that do *not* work, so nobody re-derives them: hashcat has no BIP39-mnemonic-to-address mode
(`-m 12100` is raw PBKDF2-HMAC-SHA512 and stops at the seed, and there is no way to make it derive and
match an address), and `btcrecover`, which *does* implement exactly this search correctly, is CPU-only for
BIP39 passphrases. That is why this repo carries its own OpenCL kernel.

**The only realistic attack is a smart, rule-based guess of a human-chosen password.**

# Dead ends (please add yours)

Recorded in `stats.txt` — completed with no match:

| Wordlist | Lines |
|---|---|
| `wordlists/english.txt` | 394,748 |
| `wordlists/cain.txt` | 306,706 |
| `wordlists/strings.txt` | 3,219 |
| `wordlists/john.txt` | 3,107 |
| `wordlists/500-worst-passwords.txt` | 500 |
| `wordlists/twitter-banned.txt` | 370 |
| `wordlists/conficker.txt` | 182 |

Each was tried in 4 case variants (as-is / lower / upper / capitalized). `strings.txt` (3,219 lines,
evidently strings pulled out of the image) is no longer in the working tree and was never committed, so
that row is a record of what was run, not something you can currently re-run.
**Note: `rockyou.txt` is *not* among them** — despite the earlier claim in this README that every list from
[skullsecurity](https://wiki.skullsecurity.org/index.php/Passwords) had been tried, `stats.txt` records only
the ~709 K lines above. Running rockyou properly is the cheapest untried step (~18 min, see above).

Also completed with no match:

* **~1.16 billion candidates** by floflo777 (rockyou raw + best64, the 108-word Corey corpus × 8 rule sets,
  human lists, 2-word combinator, quotes, the decoded audio message, alternate index paths) — see
  [the search plan](#the-search-plan) for the full breakdown.
* `new_ground.py lead2` — 421,973 candidates (every bundled wordlist + thematic vocab) on BIP44/BIP49/BIP84.
* `new_ground.py lead3` — 329,003 three-word thematic combinations on all three paths.
* `mnemonic_variants.py` — permutations/subsets/reversals/joins of the 24 kitten mnemonic words (up to
  4 words, `--deep` up to 5), plus the mnemonic's own sha256.
* [HomelessPhD/CorePhylips_CATS](https://github.com/HomelessPhD/CorePhylips_CATS) — ~1/3 of `rockyou.txt`
  plus phrases composed from the article and the bitimage repo. The author states: *"I have not found any
  clues or hints."*
* The two targeted runs described in [Ruled out by measurement](#ruled-out-by-measurement).

# The search plan

**Read this before spending any compute.** An independent researcher (floflo777's
[open-crypto-puzzles](https://github.com/floflo777/open-crypto-puzzles), folder
`2-mid-prizes/corey-phillips-kitten-passphrase-1msats/`) has already tested
**~1.16 billion candidates against this exact target, 0 matches**, with a planted
positive control recovered in each run. Their ledger covers:

* `rockyou.txt` raw (14.3 M) **and** `rockyou.txt` × `best64` (1.10 B)
* a 108-word Corey-specific corpus (mined from his Medium/GitHub/employer) × 8 rule
  sets — `best64`, `leetspeak`, `T0XlC`, `toggles3`, `rockyou-30000`,
  `OneRuleToRuleThemAll`, `d3ad0ne`, `dive` (23.7 M)
* human lists `probable-v2-top12000`, `darkweb2017-top10k`, `xato-top-1M`,
  `ncsc-100k`, raw + `best64` (9.0 M)
* a 2-word thematic combinator, in-joke taglines, famous quotes + the full BIP39
  list as a single word, and the decoded audio-puzzle message + 32 variants
* alternate BIP84 index paths on the corpus, and a `btcrecover` cross-check

So **do not re-run rockyou or the standard rule sets** — that ground is covered.
What is left is (a) the two bounded searches their ledger lists as *not yet run*,
(b) big blind rule sweeps they deliberately skipped, and (c) asking the author.

## Already done here — `new_ground.py` (floflo777's leads 2 & 3)

Both completed, 0 matches, each with a positive control planted on a non-default
path first:

```bash
python3 new_ground.py --selftest
python3 new_ground.py lead2      # BIP44/49 safety net
python3 new_ground.py lead3      # 3-word thematic combinator
```

* **Lead 2 — BIP44/BIP49 safety net.** Every bundled wordlist *and* the thematic
  vocabulary (421,973 candidates) checked against `m/44'`, `m/49'` and `m/84'` at
  once — the target is matched as a hash160, so the base58/bech32 encoding a real
  BIP44/49 wallet would show is irrelevant. This is broader than floflo777's lead 2
  (they proposed only the 108-word corpus). **0 matches** → the passphrase is not a
  bundled-list word under an alternate purpose.
* **Lead 3 — 3-word thematic combinator.** All 3-word permutations of the 39-word
  puzzle vocabulary × 6 join styles (none/space/underscore/dash/camelCase/PascalCase),
  on all 3 paths (329,003 candidates). floflo777 tested only 1- and 2-word forms.
  **0 matches.**

## What is left, and what to run

| Tier | Candidates | Size | Where | Prior | Notes |
|---|---|---|---|---|---|
| A | `rockyou.txt` × `dive` | ~99 B | **GPU only** | low | The rule set `dive` was applied to the 108-word corpus but **never to rockyou**. The largest untested blind region. `python3 run_plan.py A --search gpu` |
| B | `rockyou.txt` × `d3ad0ne` | ~34 B | **GPU only** | low | Same gap, different rule set. |
| C | `xato-10M` / `Pwdb_top-10000000` × `best66` | tens of B | GPU | low | Deeper corpora than the 1 M lists floflo777 used. |
| D | SecLists language-specific lists (his employer Synonym is Nordic) × `best64` | ~10 M | CPU ok | low–med | A corpus angle nobody has tried; cheap. |

These are ordered by cost, not by likelihood — every one is a *blind* sweep with a
low prior, which is exactly why floflo777 stopped before them ("a further blind
sweep has a low prior... the author frames the whole puzzle as a proof of concept").
Run them only on a real GPU, and only if [lead 1 below](#open-leads) yields nothing.

`run_plan.py` wires each tier up and works on **Windows, macOS and Linux** (it sets
up the hashcat→search pipe with `subprocess`, no shell needed). hashcat only
*generates* candidates — it cannot derive the address, so our search does that.
Machine-specific paths are passed by flag or environment variable:

```bash
# point it at your files (once), then pick tiers
export KITTEN_HASHCAT=/path/to/hashcat            # or auto-detected from PATH
export KITTEN_ROCKYOU=/path/to/rockyou.txt
python3 run_plan.py A --search gpu                # tier A on the GPU
python3 run_plan.py --dry-run A                   # print the commands, run nothing
```

```powershell
# Windows PowerShell, GPU box:
$env:KITTEN_HASHCAT="C:\tools\hashcat\hashcat.exe"
$env:KITTEN_ROCKYOU="C:\wordlists\rockyou.txt"
python run_plan.py A --search gpu
```

`--hashcat`, `--rules`, `--rockyou`, `--xato`, `--langdir` override the paths;
the rules directory is auto-detected next to the hashcat binary. hashcat's device
is left to hashcat on Windows/Linux and pinned to `-d 1` on macOS (Apple's OpenCL
GPU cannot build hashcat's kernel); override with `--hashcat-device`. Runs are
resumable via `stats_*.txt`; stop the instant `HITS.txt` appears. (`run_plan.sh`
is the older bash-only version, macOS/Linux, kept for reference.)

**The honest bottom line:** ~1.16 B human-plausible candidates plus the bounded
thematic and alternate-path searches are now exhausted. If the passphrase is a
human-chosen word or short phrase, tiers A–D still have a chance; if it is a
password-manager-random string — which the author's "not meant to be solved" framing
allows — no feasible search finds it, and lead 1 is the only path.

# Open leads

1. **Full `rockyou.txt`, then the larger public leak lists** (`hashes.org`-style dumps, `Have I Been
   Pwned` top-N, SecLists) with hashcat rule sets (`best64.rule`, `dive.rule`) — the standard
   human-password attack, and the one thing that has never actually been finished here.
2. **Run it on a real GPU.** `gpu/gpu_bruteforce.py` is ready and validated; it has only ever been run on
   an Apple GPU, where it is barely faster than the CPU. On a discrete card it should be ~5x that. Run
   `--selftest` first, then `gpu/bench_split.py` to see which half to tune on that device.
3. **Read the two unread replies under the article.** The comments by `FILIPE4OLIVEIRA` (2024-06-07) and
   `MoE` (2025-01-21) each show "1 reply" that is not in the archived copy in `docs/article.txt`. If either
   reply is from Corey, it is the only post-2019 statement from him about this puzzle. Medium currently
   serves 403 to every non-browser fetch, so this needs a real browser.
4. **His other writing.** Part 2/3 (timestamping) and the 2020 audio puzzle may reveal the style of
   passphrase he picks. If anyone solved the audio puzzle, its answer is the best available prior.
5. **Ask him.** [@coreylphillips](https://twitter.com/coreylphillips) /
   [github.com/coreyphillips](https://github.com/coreyphillips). Six years on, a hint costs him nothing.

---

# Usage

```bash
python3.13 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

**Use Python 3.13 or older.** The blocker is `coincurve` (needed by `derive.py` directly and by `bip_utils`
transitively): its newest releases publish wheels up to `cp313` and none for `cp314`, so on Python 3.14 pip
falls back to a source build that fails (`Expected exactly one LICENSE file in cffi distribution`). That is
true of coincurve 20 and 21 alike, so no version pin gets you onto 3.14 — only an older interpreter does.
Verified working: Python 3.13.15 with coincurve 21.0.0 (wheel), `bip_utils` 2.9.3, all self-tests passing.

`pyopencl`/`numpy` are only needed for the GPU search.

### The reference implementation — `main.py`

Readable, one address at a time, unchanged from the original. Set `filename` and `passphrase` at the bottom:

```python
if __name__ == "__main__":

    filename = "kitten.jpeg"
    passphrase = ""

    address = get_address_from_file(filename, passphrase)
```

### The derivation core — `derive.py`

The same computation without `bip_utils`, ~1.5x faster per core, and the shared core of both searches.
Also the thing to run first if you change anything:

```bash
python3 derive.py --selftest       # checks the article's sha256 AND address, the official
                                   # BIP84 test vector, and bech32 round-tripping
python3 derive.py --bench 2000     # single-core rate
python3 derive.py "some passphrase"
```

### CPU search — `bruteforce_fast.py`

Streaming (a 14 M-line list needs no memory), resumable, and it can be fed from stdin:

```bash
python3 bruteforce_fast.py --selftest             # positive control: plants a known
                                                  # passphrase and must find it
python3 bruteforce_fast.py wordlists/             # every *.txt in a directory
python3 bruteforce_fast.py rockyou.txt --mutate   # + case/leet/affix variants
hashcat --stdout -r best64.rule rockyou.txt | python3 bruteforce_fast.py --stdin
```

The `--stdin` form is the recommended way to use real rule sets: it borrows hashcat's entire rules
ecosystem for candidate *generation* without needing hashcat to do the derivation it cannot do.
Finished files are recorded in `stats_fast.txt` and skipped on the next run; hits go to `HITS.txt`.

### GPU search — `gpu/`

```bash
python3 gpu/gpu_bruteforce.py --selftest          # RUN THIS FIRST on any new device
python3 gpu/gpu_bruteforce.py --bench
python3 gpu/bench_split.py --count 300000         # is PBKDF2 or EC the bottleneck here?
hashcat --stdout -r best64.rule rockyou.txt | python3 gpu/gpu_bruteforce.py --stdin
```

`gpu/passphrase_search.cl` is one work-item per candidate: PBKDF2 → `m/84'/0'/0'/0/0` → hash160 →
compare. It reuses `pbkdf2_sha512.cl`, `bip32_tree.cl` and hashcat's vendored secp256k1 (see
`gpu/vendor/NOTICE.md`) unmodified from the sibling "Securing Wealth in Poetry" project, and only
replaces the parts that differ for this puzzle: there the *mnemonic* varies and 46 derivation nodes are
tested, here the mnemonic is fixed and public, the varying bytes live in the PBKDF2 *salt*, and there is
exactly one node to test.

Two correctness rules the kernel is built around, because a search that silently finds nothing is worse
than no search at all:

* **Every GPU hit is re-derived on the CPU before it is reported.** A kernel bug can cost time; it can
  never produce a false "found".
* **`--selftest` is a positive control, not a smoke test.** It plants a known passphrase in the stream and
  fails loudly if the kernel does not find it, checks that an over-length candidate is diverted to the CPU
  rather than dropped, and checks that nothing is falsely flagged against the real target. A "no match"
  from a build that has not passed it means nothing.

### Mnemonic-word variants — `mnemonic_variants.py`

Permutations and subsets of the 24 kitten words used as the passphrase; `--deep` for up to 5 words.

# Reference

* Article: [Part 1/3: Turn Your Photos Into Bitcoin Private Keys/Addresses](https://corey-lyle-phillips.medium.com/part-1-3-turn-your-photos-into-bitcoin-private-keys-addresses-57669771cf7a) (text archived in `docs/article.txt`)
* Reference implementation: [coreyphillips/bitimage](https://github.com/coreyphillips/bitimage) · [live demo](https://coreyphillips.github.io/bitimage/)
* Puzzle listing: [privatekeys.pw](https://privatekeys.pw/puzzles/0.01-btc-corey-phillips-puzzle)
* Other attempt: [HomelessPhD/CorePhylips_CATS](https://github.com/HomelessPhD/CorePhylips_CATS)
* Origin of the image: Andreas Antonopoulos' 2015 steganography tweet — [background](https://bravenewcoin.com/insights/steganography-how-antonopoulos-hid-a-us12m-transaction-in-a-picture-of-kittens)
* Steganography tooling, if you want to rule it out yourself:
  [hacktricks](https://book.hacktricks.xyz/crypto-and-stego/stego-tricks) ·
  [aperisolve](https://www.aperisolve.com/) ·
  [StegOnline](https://georgeom.net/StegOnline/upload)
