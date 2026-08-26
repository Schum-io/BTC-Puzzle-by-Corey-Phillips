# Passphrase analysis — hypotheses, what's ruled out, what's left

Background notes moved out of the README to keep that focused on running the
tools. This is the "why" behind the search: what the passphrase can be, what has
already been eliminated (with measurements), and the remaining plan.

The only unknown in the puzzle is the BIP39 passphrase. The mnemonic, the
derivation path `m/84'/0'/0'/0/0`, and the address type are all fixed and public
(see [algorithm.md](algorithm.md)).

---

## What can the passphrase be?

### Format: technically unconstrained

A BIP39 passphrase is **not** a mnemonic. It is an arbitrary UTF-8 string used as
the PBKDF2 salt suffix:

```
seed = PBKDF2-HMAC-SHA512(password = NFKD(mnemonic), salt = "mnemonic" + NFKD(passphrase), c = 2048, dkLen = 64)
```

Consequences for the search:

* **No wordlist constraint.** It does not have to be BIP39 words, English words, or words at all.
* **No length constraint.** `""`, `"a"`, a 200-character sentence and a 32-byte random string are all valid.
* **Case, spaces, punctuation and Unicode all matter**, but NFKD normalization means visually-equal
  Unicode variants collapse (precomposed vs. decomposed accents, some full-width forms). So a whole
  *class* of equivalent strings maps to one seed — a guesser only needs any one member of the class.
* Corey entered it by hand into an `<input type="text">` on his own demo page, so it is a **typeable
  string**, fixed before 2019-06-28 (the funding date), i.e. before the article was published.

So *"is it one word, several words, or symbols?"* → **all three remain possible**; nothing in the
article, the image or the repo narrows it structurally. What narrows it is the negative evidence below.

### What the author said

The article frames the 0.01 BTC not as a puzzle with a findable answer but as a **demonstration that a
passphrase protects funds even when the file is public**: *"Remember, this is not meant to be solved. It is
meant to prove the viability of this method."* He repeated it on Twitter — *"It's not meant to be solved.
It's meant to prove the viability of the method"*
([x.com/coreylphillips/status/1373248775947481088](https://x.com/coreylphillips/status/1373248775947481088),
surfaced in [bitimage issue #7](https://github.com/coreyphillips/bitimage/issues/7)). He never posted a
hint, never answered when asked in the article comments (2024-04-15), and — unlike his 2020
[Bitcoin Audio Puzzle](https://corey-lyle-phillips.medium.com/a-bitcoin-audio-puzzle-61174b9849ce) — never
called this one a puzzle at all.

**Working conclusion:** most likely a private password of the author's own choosing, not an encoded answer
hidden in the article/image/repo. Treat "find the hidden clue" as low-probability and "guess a human-chosen
password" as the main line — while accepting that if he used a password manager, it is unrecoverable.

### Ranked hypotheses

| # | Hypothesis | Assessment |
|---|---|---|
| 1 | A hand-picked password of his own, not derived from any public material | Most likely. Consistent with "not meant to be solved" and 6+ years of failed dictionary attacks. |
| 2 | A multi-word phrase with case/punctuation from his own writing (e.g. the demo tagline *"A picture is worth a thousand satoshis"*) | Plausible, cheap to test — the obvious forms are already ruled out. Needs rule-based mutation, not plain wordlists. |
| 3 | Machine-random string from a password manager | Plausible and fatal. Unfalsifiable except by exhausting everything else. |
| 4 | Something recoverable from steganography in the image | Very unlikely — see below. |
| 5 | Words of the kitten mnemonic itself, reordered/subset | Ruled out (permutations up to 4–5 words). |

---

## Ruled out by measurement

* **The private key is not a weak/known value.** Bypassing BIP39 entirely: small integer keys 1..1,000,000,
  brainwallet `sha256`/double-`sha256` of thematic + public-data strings used directly as the private key,
  and well-known constants — each tested as both compressed and uncompressed pubkeys against the target
  hash160. 0 matches. The key is genuinely random; there is no shortcut value.
* **No passphrase computable from public data reaches the target.** 22 candidates that would need no
  guessing — the entropy hex `1808d353…`, the full image base64, `sha256` of the file bytes, the mnemonic,
  both addresses, the sister WIF, single/double hashes, the entropy as raw bytes — on all three paths. 0
  matches. Combined with the one-way PBKDF2(2048)/secp256k1/SHA256/RIPEMD160 chain, this confirms there is
  no algorithmic shortcut: the passphrase can only be found by search, not computed from the address.
* **It is not a derivation-path trick.** 25,000 derivation paths of the *no-passphrase* seed were
  enumerated (`m/{84',49',44',0'}/0'/{0..5}'/{0,1}/{0..499}`, plus `m/i` and `m/0/i`). The target is in
  none → a non-empty passphrase really is involved.
* **The image contains no plain stego container.** `kitten.jpeg` has no EXIF, no APP1/APP13/COM segment, no
  bytes after the `FFD9` end-of-image marker, and zero printable ASCII runs ≥20 chars; `binwalk` finds only
  the JPEG. It is a re-encoded 1200-px progressive rendition, so any coefficient-domain (LSB/F5/steghide)
  payload from Antonopoulos' original 2015 tweet would not survive the re-compression — and even in the
  original, that payload was a *signed transaction* Antonopoulos said was *"encrypted first"*, never Corey's
  passphrase. (Not attempted for lack of tooling: `steghide`/`outguess`/`zsteg`. Cheap to try, low value.)
* **Phrase-as-passphrase — 0 matches.** ~121k variants on all three paths: Corey's own words (demo tagline,
  article title, quotable sentences with Medium's curly apostrophes/quotes), Bitcoin/privacy/cypherpunk
  lines (Satoshi, genesis-block headline, Hal Finney's *"Running bitcoin"*, the Cypherpunk Manifesto, common
  mottos), the "not meant to be solved" manifesto broken into every individual word and consecutive word-run,
  and **every id/class/name and word-like identifier + string literal across all 11 commits of
  `coreyphillips/bitimage`** (12,533 tokens, including the minified vendor libs and history-only ids like
  `password`, `passwordHash`, `reveal-password`, `privKey`, `privateKey`, `subStr`) — each in
  straight/curly-apostrophe, quoted, trailing-punctuation, and case forms.
* **The author's own "not meant to be solved" quote is not the passphrase.** 384 variants of both wordings
  (tweet and Medium article), straight/curly apostrophes, with/without trailing period, quoted/unquoted,
  several cases, and the individual sentences, on all three paths. 0 matches.
* **Reordering the mnemonic words is a dead end (bitimage issue #7).** A solver (`jmr2704`) reported that
  swapping some kitten-mnemonic words gave an address "matching the first part" of the target. This is a
  misunderstanding: (a) the puzzle keeps the *same* mnemonic and varies only the passphrase — a reordered
  mnemonic is an unrelated wallet; (b) a leading-character match is worthless — every mainnet P2WPKH address
  starts with `bc1q` (4 free chars) and hashing has no "getting warmer" gradient. Measured: 400,000
  checksum-valid reorderings, the best overlap was 6 characters (`bc1qcy`) — the free prefix plus ~2 lucky
  chars (~1/1024). Ordinary coincidence.
* **The obvious semantic candidates are gone.** 1,414 hand-picked strings (article/repo phrases and
  headings, names/handles/projects, Antonopoulos' handle and tweet id, cat vocabulary, dates, the mnemonic,
  the sha256 hex, both addresses and the WIF) in several cases/separators/suffixes; plus 212,562 themed 1–2
  token combinations over a 48-word vocabulary × separators × cases × suffixes.

---

## Search space & throughput

Measured on a 10-core M1 Max. Per candidate the work is 2048 HMAC-SHA512 iterations plus three secp256k1
multiplications; on this hardware those two halves cost about the same (see `gpu/bench_split.py`).

| Implementation | Rate |
|---|---|
| `derive.py` (`hashlib.pbkdf2_hmac` + `coincurve` + hand-rolled bech32) | ~1,600 candidates/s per core |
| `bruteforce_fast.py`, 9 worker processes | ~13,000 candidates/s |
| `gpu/passphrase_search.cl`, Apple M1 Max (24 CUs) | ~21,000 candidates/s |

| Space | Size | Time at 13k/s |
|---|---|---|
| `rockyou.txt` | 14.3 M | ~18 min |
| every lowercase a–z string ≤ 6 chars | 321 M | ~7 hours |
| every lowercase a–z string ≤ 8 chars | 217 G | ~530 years |
| 8 chars, full 95-char printable ASCII | 6.7 × 10¹⁵ | ~16 million years |

A GPU helps less than the usual "just use hashcat" advice: the per-candidate cost is ~50/50 PBKDF2 vs EC,
and PBKDF2 at 2048 iterations is irreducible, so even a perfect EC half caps overall gains at ~2x on an
Apple GPU. A discrete card (Radeon 7900 XTX etc.) does far better on integer work — extrapolated ~10⁵/s —
but that is still only ~10x a 10-core CPU, i.e. it moves the brute-force wall by roughly one character.

Two things that do *not* work, so nobody re-derives them: hashcat has no BIP39-mnemonic-to-address mode
(`-m 12100` stops at the seed), and `btcrecover` (which does implement exactly this) is CPU-only for BIP39
passphrases. That is why this repo carries its own OpenCL kernel.

**The only realistic attack is a smart, rule-based guess of a human-chosen password.**

---

## Already tested (dead ends)

* **~1.16 billion candidates** by floflo777's
  [open-crypto-puzzles](https://github.com/floflo777/open-crypto-puzzles)
  (`2-mid-prizes/corey-phillips-kitten-passphrase-1msats/`): `rockyou.txt` raw (14.3 M) and × `best64`
  (1.10 B); a 108-word Corey-specific corpus × 8 rule sets (`best64`, `leetspeak`, `T0XlC`, `toggles3`,
  `rockyou-30000`, `OneRuleToRuleThemAll`, `d3ad0ne`, `dive`); human lists (`probable-v2-top12000`,
  `darkweb2017-top10k`, `xato-top-1M`, `ncsc-100k`, raw + `best64`); a 2-word thematic combinator, in-joke
  taglines, famous quotes + the full BIP39 list as a single word; the decoded audio-puzzle message + 32
  variants; alternate BIP84 index paths on the corpus; a `btcrecover` cross-check. All with a planted
  positive control recovered each run.
* **Lead 2 — BIP44/49 safety net** — 421,973 candidates (every bundled wordlist + thematic vocab) on
  BIP44/BIP49/BIP84 at once (target matched as a hash160). 0 matches.
* **Lead 3 — 3-word combinator** — all 3-word permutations of a 39-word puzzle vocabulary × 6 join styles,
  on all three paths (329,003 candidates). 0 matches.
* **Mnemonic-word variants** — permutations/subsets/reversals/joins of the 24 kitten words (up to 4–5),
  plus the mnemonic's own sha256.
* [HomelessPhD/CorePhylips_CATS](https://github.com/HomelessPhD/CorePhylips_CATS) — ~1/3 of `rockyou.txt`
  plus phrases from the article and repo. Author: *"I have not found any clues or hints."*
* skullsecurity lists (~709 K lines: `cain`, `english`, `john`, `500-worst`, `conficker`, `twitter-banned`)
  in 4 case variants each — these were bundled in an earlier version of the repo and have since been removed.
  **Note:** despite an old claim that all skullsecurity lists were tried, full `rockyou.txt` was only covered
  by floflo777, not by those runs.

---

## The plan (what's left)

floflo777 already covered rockyou and the standard rule sets, so **don't re-run those**. What remains:

**Blind GPU sweeps** (low prior by construction — floflo777 deliberately stopped before them), via
`run_plan.py`:

| Tier | Candidates | Note |
|---|---|---|
| A | `rockyou.txt` × `dive` | `dive` was applied to the 108-word corpus but never to rockyou — the largest untested blind region |
| B | `rockyou.txt` × `d3ad0ne` | same gap, different rule set |
| C | `xato-10M` × `best66` | deeper corpus than the 1 M lists floflo777 used |
| D | SecLists language lists × `best66` | a corpus angle nobody tried; his employer Synonym is Nordic |

Run only on a real GPU, and only after the non-computational lead below is exhausted.

**Bottom line:** ~1.16 B human-plausible candidates plus the bounded thematic/alternate-path searches are
exhausted. If the passphrase is a human-chosen word or short phrase, tiers A–D still have a chance; if it is
a password-manager-random string — which the author's framing allows — no feasible search finds it.

---

## Open leads (non-computational)

1. **Ask the author — attempted, no response (as of 2026-08).**
   [@coreylphillips](https://twitter.com/coreylphillips) /
   [github.com/coreyphillips](https://github.com/coreyphillips). This was the only channel that could
   deliver genuinely new information (theme, length, source of the passphrase), and it has not answered.
2. **The two unread article replies.** Comments by `FILIPE4OLIVEIRA` (2024-06-07) and `MoE` (2025-01-21)
   each show "1 reply" not in `docs/article.txt`. If either is from Corey it is his only post-2019 statement
   about this puzzle. Medium serves 403 to non-browser fetches, so this needs a real browser.
3. **His other writing.** Part 2/3 (timestamping) and the 2020 audio puzzle may reveal the style of
   passphrase he picks; a solved audio puzzle would be the best prior.
