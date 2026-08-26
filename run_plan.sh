#!/usr/bin/env bash
#
# Blind rule sweeps that are still untested (see README "The search plan").
# The cheap thematic/alternate-path leads are done -- run new_ground.py for those.
# The ~1.16B human-plausible candidates are done by floflo777 -- do NOT redo rockyou
# raw or rockyou x best64/dive-on-corpus.
#
# Each tier pipes hashcat's candidate GENERATOR (-d 1 --stdout: device #2/GPU
# kernel build fails on Apple, so pin device 1; --stdout does no cracking) into
# our derivation search, which is the only thing that can turn a BIP39
# mnemonic+passphrase into a BIP84 address.
#
# Usage:  ./run_plan.sh A|B|C|D          (default A)
#         SEARCH=gpu ./run_plan.sh A     use the GPU search (strongly advised for A-C)
set -euo pipefail
cd "$(dirname "$0")"

RULES="/opt/homebrew/Cellar/hashcat/7.1.2/share/doc/hashcat/rules"
SL="/Users/jimraynor/Documents/GitHub/SecLists/Passwords"
ROCKYOU="$SL/Leaked-Databases/rockyou.txt"
XATO10M="$SL/Common-Credentials/xato-net-10-million-passwords-dup.txt"

PY="${PY:-.venv/bin/python}"
if [ "${SEARCH:-cpu}" = "gpu" ]; then SEARCHER="$PY gpu/gpu_bruteforce.py --stdin"
else SEARCHER="$PY bruteforce_fast.py --stdin"; fi

tier="${1:-A}"
echo "### tier $tier  |  searcher: ${SEARCH:-cpu}"
case "$tier" in
  A) hashcat -d 1 --stdout -r "$RULES/dive.rule"    "$ROCKYOU" | $SEARCHER ;;  # ~99B, GPU only
  B) hashcat -d 1 --stdout -r "$RULES/d3ad0ne.rule" "$ROCKYOU" | $SEARCHER ;;  # ~34B, GPU only
  C) hashcat -d 1 --stdout -r "$RULES/best66.rule"  "$XATO10M" | $SEARCHER ;;  # deeper corpus
  D) for wl in "$SL/Common-Credentials/Language-Specific/"*.txt; do            # language lists
        hashcat -d 1 --stdout -r "$RULES/best64.rule" "$wl"; done | $SEARCHER ;;
  *) echo "unknown tier: $tier (expected A|B|C|D)"; exit 1 ;;
esac
