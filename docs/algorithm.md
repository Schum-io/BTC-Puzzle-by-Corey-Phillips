# The puzzle — algorithm, canonical image, on-chain facts

Reference facts moved out of the README. For the passphrase search itself see
[analysis.md](analysis.md).

| | |
|---|---|
| Prize | 0.01 BTC (currently 1,001,900 sat) |
| Creator | Corey Phillips ([@coreylphillips](https://twitter.com/coreylphillips), [github](https://github.com/coreyphillips)) |
| Article | [Part 1/3: Turn Your Photos Into Bitcoin Private Keys/Addresses](https://corey-lyle-phillips.medium.com/part-1-3-turn-your-photos-into-bitcoin-private-keys-addresses-57669771cf7a) (2019-07-09) |
| Funded | 2019-06-28 (11 days before the article) |
| Target | `bc1qcyrndzgy036f6ax370g8zyvlw86ulawgt0246r` — unsolved, UTXOs unspent |
| Unknown | only the BIP39 passphrase |

From the article, verbatim:

> To prove the viability of this method, I have also sent 0.01 BTC to the following address,
> "bc1qcyrndzgy036f6ax370g8zyvlw86ulawgt0246r". This address was generated using the kitten image along
> with a BIP39 passphrase. **Remember, this is not meant to be solved. It is meant to prove the viability
> of this method**, but if you somehow manage to claim it, congrats!

> Note: an earlier community README listed the target as `...gt0246` (missing the final `r`). That string is
> not a valid bech32 address (checksum fails). The correct address is 42 chars and ends in `...gt0246r`.

---

## The exact algorithm (verified)

The reference implementation is Corey's own demo page,
[coreyphillips/bitimage](https://github.com/coreyphillips/bitimage) (`index.html`). Verbatim:

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
     var bech32AddressPath = `m/84'/0'/0'/0/0`;      // p2wpkh (bc1q...) <-- the puzzle
  });
```

1. Read the file, base64-encode it (the data-URI prefix before the `,` is discarded).
2. `sha256` **of the base64 string as ASCII text** — not of the raw file bytes. Most common mistake.
3. Feed those 32 bytes to BIP39 `entropyToMnemonic` → a 24-word mnemonic.
4. `mnemonicToSeed(mnemonic, passphrase)` → seed. Both mnemonic and passphrase are NFKD-normalized; the
   PBKDF2 salt is the literal `"mnemonic"` + passphrase.
5. Derive `m/84'/0'/0'/0/0`, compressed pubkey, hash160, encode as bech32 v0 → `bc1q...`.

### Verified against the article

`derive.py --selftest` reproduces the published intermediates and the final address exactly:

| Value | Output | Article |
|---|---|---|
| sha256 of the base64 text | `1808d35318ac7cb98b69ff9779b699d6a631f15e0b353ac89b7c4020774832ed` | same |
| Address `m/84'/0'/0'/0/0` (empty passphrase) | `bc1q57euh23y3qs2f9d5mtwpax5lqecfvrdkqce82a` | same |

The 24-word mnemonic (empty passphrase), also the `MNEMONIC` constant in `derive.py`:

```
blossom educate state course sick fresh color divide number soap please pull
glide weather join grit depart dynamic tenant leopard alter piano slight room
```

JS ↔ Python equivalence checked: `lastIndexOf(",")` vs `split(b",",1)` are equivalent (base64 has no
comma); `Bitcoin.crypto.sha256` on a JS string defaults to UTF-8, and base64 is ASCII, so it equals
`hashlib.sha256(b64_bytes)`; `entropyToMnemonic` == `FromEntropy(digest)`; the NFKD + PBKDF2 + BIP84 chain
matches, verified against an independent from-scratch implementation (identical addresses).

---

## Canonical input file

**The #1 reason people fail to reproduce the puzzle is the wrong rendition of the image.** Every re-encode
(Twitter/Medium/imgur resize, a browser "Save image as…" that recompresses, EXIF stripping) changes the
bytes → the base64 → the sha256 → a completely different mnemonic. Two commenters hit exactly this
(`bc1qasptyrp0xyjxzz95q9cr32y2pdptqlwekgww9x` and a mnemonic starting `elite usual surround kiwi…` are both
wrong-rendition artifacts).

`kitten.jpeg` in this repo is the correct file. Verify before spending any CPU:

```
sha256(base64(file))  1808d35318ac7cb98b69ff9779b699d6a631f15e0b353ac89b7c4020774832ed  <- matches the article
sha256(file bytes)    b988e0881a0211222e83f3e2a4bfac695c951bf96aa33ec112fab6992f5e7343
sha1(file bytes)      fc7477df0b2b1670e19b006a0d319795178708ec
md5(file bytes)       ed08111b53debb7e318ad53ea9c9d3a6
size                  265456 bytes
dimensions            1200 x 667, progressive DCT (SOF2), YCbCr 4:2:0, JFIF only, no EXIF
```

---

## On-chain facts

**Target `bc1qcyrndzgy036f6ax370g8zyvlw86ulawgt0246r`** — 2 UTXOs, 1,001,900 sat, nothing ever spent:

* `c3a8c1eedc3512cc92e8798eb240d81bcb2446dfe91339bbafd5e9687c3c663d` — 2019-06-28, block 582796,
  1,000,000 sat from Corey. Change went to `bc1qzlhye4uzzxfa0mr0h36ksc5mzme4v87wm3qf7z` (Corey's own wallet).
* `1e4c42f9aedfbdea00c2134af18de6d449a1a88565486a4de5b749634ecc07d8` — 2025-04-11, 1,900 sat of spam from
  `1HELPMEyb9z5UrogyyfP6Twpk3Q6H9QJTL` with an OP_RETURN *"Please help me with any money. I am very grateful
  in advance!"*. Unrelated.

**No-passphrase "sister" address `bc1q57euh23y3qs2f9d5mtwpax5lqecfvrdkqce82a`** — empty:

* 2019-07-02: funded 95,133 sat from the same Corey wallet.
* 2019-07-09: swept the day the article went live — 89,787 sat to `bc1qfadx3xadzawp0fzspaglreg332jzfgxsu4gm9w`.
* 2024-09-22: received 320,000 sat in an unrelated batch payout, swept the same day.

**Takeaway:** the demo address is picked clean within hours of anything landing there. Any solver of the
real puzzle is racing bots — use a high fee rate and, ideally, a direct/private broadcast.

---

## Reference

* Article (text archived in [article.txt](article.txt)):
  [medium](https://corey-lyle-phillips.medium.com/part-1-3-turn-your-photos-into-bitcoin-private-keys-addresses-57669771cf7a)
* Reference implementation: [coreyphillips/bitimage](https://github.com/coreyphillips/bitimage) ·
  [live demo](https://coreyphillips.github.io/bitimage/)
* Puzzle listing: [privatekeys.pw](https://privatekeys.pw/puzzles/0.01-btc-corey-phillips-puzzle)
* Other attempts: [HomelessPhD/CorePhylips_CATS](https://github.com/HomelessPhD/CorePhylips_CATS) ·
  [floflo777/open-crypto-puzzles](https://github.com/floflo777/open-crypto-puzzles)
* Image origin: Andreas Antonopoulos' 2015 steganography tweet —
  [background](https://bravenewcoin.com/insights/steganography-how-antonopoulos-hid-a-us12m-transaction-in-a-picture-of-kittens)
