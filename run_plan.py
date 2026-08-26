#!/usr/bin/env python3
r"""
Cross-platform driver for the blind rule-sweep tiers (Windows / macOS / Linux),
with a resumable state file so partial runs pick up where they left off.

Each tier launches hashcat as a candidate GENERATOR (`--stdout`: wordlist x
rules, no cracking) and pipes its output into our derivation search -- the only
thing that can turn a BIP39 mnemonic+passphrase into a BIP84 address. The pipe
is built with subprocess, so no shell is needed and it behaves identically on
Windows.

Resume
------
A tier is split into UNITS: each (rule, wordlist) job is chunked into fixed-size
ranges of base words via hashcat's `--skip`/`--limit`. That chunking is exact --
the union of the chunks is byte-for-byte the whole keyspace, verified against a
full run -- so nothing is skipped or double-counted. Every unit that COMPLETES
(the search drained the whole chunk) is recorded in run_plan_state.json; on the
next run those units are skipped. A unit interrupted midway (Ctrl-C, a crash, a
power cut) is NOT recorded, so it re-runs in full -- correctness over cleverness,
since a silently half-processed chunk would be a false "no match".

Because a unit re-runs whole, keep --chunk-words at a size you are willing to
redo. The default (2,000,000 base words) is a few minutes of candidates per
chunk on a GPU.

Read the README "search plan" first: the cheap thematic/alternate-path work is
already done (new_ground.py), and ~1.16 B human-plausible candidates are done by
floflo777. These tiers are the big blind sweeps that remain -- GPU territory.

Machine-specific paths (flags win over environment):

    --hashcat / KITTEN_HASHCAT     hashcat binary (auto-detected from PATH)
    --rules   / KITTEN_RULES       hashcat rules dir (auto-detected next to hashcat)
    --rockyou / KITTEN_ROCKYOU     rockyou.txt
    --xato    / KITTEN_XATO        xato-net-10-million-passwords-dup.txt
    --langdir / KITTEN_LANGDIR     SecLists .../Language-Specific directory

Examples:

    python run_plan.py A --search gpu           # tier A, resuming automatically
    python run_plan.py A --status               # how many units done / remaining
    python run_plan.py A --dry-run              # print the per-chunk commands
    python run_plan.py A --no-resume            # ignore state, redo everything

    # Windows PowerShell:
    $env:KITTEN_HASHCAT="C:\tools\hashcat\hashcat.exe"
    $env:KITTEN_ROCKYOU="C:\wordlists\rockyou.txt"
    python run_plan.py A --search gpu
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
STATE_FILE = HERE / "run_plan_state.json"
DEFAULT_CHUNK_WORDS = 2_000_000

# Which (rule, wordlist-key) each tier sweeps. Rule names must exist in the
# hashcat rules dir; best64 is NOT shipped by hashcat 7.x (renamed best66).
TIERS = {
    "A": ("dive.rule", "rockyou"),      # ~99 B  GPU only
    "B": ("d3ad0ne.rule", "rockyou"),   # ~34 B  GPU only
    "C": ("best66.rule", "xato"),       # deeper corpus
    "D": ("best66.rule", "langdir"),    # language-specific lists (a folder)
}


# --------------------------------------------------------------------------- #
# locating tools and files
# --------------------------------------------------------------------------- #

def _env_path(name: str) -> Path | None:
    v = os.environ.get(name)
    return Path(v) if v else None


def find_hashcat(explicit: Path | None) -> Path:
    if explicit:
        if explicit.exists():
            return explicit
        sys.exit(f"--hashcat {explicit}: not found")
    env = _env_path("KITTEN_HASHCAT")
    if env and env.exists():
        return env
    found = shutil.which("hashcat") or shutil.which("hashcat.exe")
    if found:
        return Path(found)
    sys.exit("hashcat not found. Put it on PATH, or pass --hashcat "
             r"C:\path\to\hashcat.exe (or set KITTEN_HASHCAT).")


def find_rules(explicit: Path | None, hashcat: Path) -> Path:
    candidates: list[Path] = []
    if explicit:
        candidates.append(explicit)
    env = _env_path("KITTEN_RULES")
    if env:
        candidates.append(env)
    d = hashcat.resolve().parent
    candidates += [
        d / "rules",
        d.parent / "rules",
        d.parent / "share" / "doc" / "hashcat" / "rules",
        d.parent / "share" / "hashcat" / "rules",
    ]
    for c in candidates:
        if c and (c / "dive.rule").exists():
            return c
    sys.exit("hashcat rules dir not found (looked for dive.rule). "
             "Pass --rules <dir> or set KITTEN_RULES.")


def need_file(path: Path | None, flag: str, env: str, what: str) -> Path:
    if path and path.exists():
        return path
    if path:
        sys.exit(f"{flag} {path}: not found")
    sys.exit(f"{what} not set. Pass {flag} <path> or set {env}.")


def default_device_args() -> list[str]:
    # Apple's OpenCL GPU cannot build hashcat's kernel, so pin device 1 there.
    # On Windows/Linux let hashcat use every device.
    return ["-d", "1"] if platform.system() == "Darwin" else []


# --------------------------------------------------------------------------- #
# state
# --------------------------------------------------------------------------- #

def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            data.setdefault("completed", [])
            return data
        except (json.JSONDecodeError, OSError):
            print(f"warning: {STATE_FILE.name} unreadable, starting fresh", file=sys.stderr)
    return {"version": 1, "completed": []}


def save_state(state: dict) -> None:
    """Atomic write, so an interrupt during save cannot corrupt the file."""
    state["completed"] = sorted(set(state["completed"]))
    fd, tmp = tempfile.mkstemp(dir=str(HERE), prefix=".run_plan_state.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=1)
        os.replace(tmp, STATE_FILE)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


# --------------------------------------------------------------------------- #
# hashcat helpers
# --------------------------------------------------------------------------- #

def keyspace(hashcat: Path, device_args: list[str], rule: Path, wordlist: Path) -> int:
    """Base-word count for a dict+rules attack. hashcat counts base words (not
    words x rules), and --skip/--limit index the same way, so this is the exact
    denominator for chunking."""
    cmd = [str(hashcat)] + device_args + ["--keyspace", "-a", "0", "-r", str(rule), str(wordlist)]
    out = subprocess.run(cmd, capture_output=True, text=True)
    for line in reversed(out.stdout.splitlines()):
        line = line.strip()
        if line.isdigit():
            return int(line)
    sys.exit(f"could not read keyspace from hashcat for {wordlist.name}:\n{out.stderr.strip()}")


def stdout_cmd(hashcat: Path, device_args: list[str], rule: Path, wordlist: Path,
               skip: int, limit: int) -> list[str]:
    return ([str(hashcat)] + device_args +
            ["--stdout", "-a", "0", "-r", str(rule),
             "--skip", str(skip), "--limit", str(limit), str(wordlist)])


def searcher_cmd(search: str) -> list[str]:
    py = sys.executable  # same interpreter -> same venv
    script = "gpu/gpu_bruteforce.py" if search == "gpu" else "bruteforce_fast.py"
    return [py, str(HERE / script), "--stdin"]


# --------------------------------------------------------------------------- #
# units
# --------------------------------------------------------------------------- #

def build_units(tier: str, hashcat: Path, device_args: list[str], rules: Path,
                paths: dict, chunk_words: int) -> list[dict]:
    """Every unit of work for a tier: {key, rule, wordlist, skip, limit}.

    A unit's key embeds the wordlist's keyspace, so if the file changes size the
    old units no longer match and are re-run rather than wrongly skipped.
    """
    rule_name, source = TIERS[tier]
    rule = rules / rule_name
    if not rule.exists():
        sys.exit(f"{rule} not found in the rules dir")

    if source == "langdir":
        langdir = need_file(paths.get("langdir"), "--langdir", "KITTEN_LANGDIR",
                             "SecLists Language-Specific directory")
        wordlists = sorted(langdir.glob("*.txt"))
        if not wordlists:
            sys.exit(f"no *.txt lists in {langdir}")
        # Many lists: identify each by its (standard SecLists) filename.
        source_id = {wl: wl.name for wl in wordlists}
    else:
        flag, env = f"--{source}", f"KITTEN_{source.upper()}"
        wl = need_file(paths.get(source), flag, env, f"{source} wordlist")
        wordlists = [wl]
        # One wordlist per tier: identify it by its ROLE ("rockyou"/"xato"), NOT
        # its filename or path, so run_plan_state.json is portable across machines
        # even if the file lives elsewhere or is named differently on each.
        source_id = {wl: source}

    units = []
    for wl in wordlists:
        k = keyspace(hashcat, device_args, rule, wl)
        wl_id = f"{source_id[wl]}:{k}"
        skip = 0
        while skip < k:
            limit = min(chunk_words, k - skip)
            units.append({
                "key": f"{tier}|{rule_name}|{wl_id}|{skip}:{skip + limit}",
                "rule": rule, "wordlist": wl, "skip": skip, "limit": limit,
            })
            skip += limit
        if k == 0:  # empty/odd wordlist: still record a no-op unit so it's "done"
            units.append({
                "key": f"{tier}|{rule_name}|{wl_id}|empty",
                "rule": rule, "wordlist": wl, "skip": 0, "limit": 0,
            })
    return units


# --------------------------------------------------------------------------- #
# running
# --------------------------------------------------------------------------- #

def run_unit(unit: dict, hashcat: Path, device_args: list[str], search: str) -> str:
    """Run one chunk. Returns 'found' | 'exhausted' | 'error'.

    'exhausted' means the searcher drained the whole chunk and reported no match
    (its exit code 1); 'found' means exit code 0 (a hit). Only these two are
    recorded as done. Anything else leaves the unit unrecorded so it re-runs.
    """
    if unit["limit"] == 0:
        return "exhausted"
    gen = stdout_cmd(hashcat, device_args, unit["rule"], unit["wordlist"],
                     unit["skip"], unit["limit"])
    search_proc = subprocess.Popen(searcher_cmd(search), stdin=subprocess.PIPE)
    gen_proc = subprocess.Popen(gen, stdout=search_proc.stdin)
    try:
        gen_proc.wait()
        if search_proc.stdin:
            search_proc.stdin.close()
        search_proc.wait()
    except KeyboardInterrupt:
        for p in (gen_proc, search_proc):
            p.terminate()
        raise
    if gen_proc.returncode not in (0, None):
        print(f"warning: hashcat exited {gen_proc.returncode} for {unit['key']}", file=sys.stderr)
        return "error"
    if search_proc.returncode == 0:
        return "found"
    if search_proc.returncode == 1:
        return "exhausted"
    print(f"warning: search exited {search_proc.returncode} for {unit['key']}", file=sys.stderr)
    return "error"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("tier", choices=list(TIERS))
    ap.add_argument("--search", choices=("cpu", "gpu"), default="cpu")
    ap.add_argument("--hashcat", type=Path)
    ap.add_argument("--rules", type=Path)
    ap.add_argument("--rockyou", type=Path, default=_env_path("KITTEN_ROCKYOU"))
    ap.add_argument("--xato", type=Path, default=_env_path("KITTEN_XATO"))
    ap.add_argument("--langdir", type=Path, default=_env_path("KITTEN_LANGDIR"))
    ap.add_argument("--hashcat-device", default=None,
                    help="override device selection, e.g. '2' or '1,2'")
    ap.add_argument("--chunk-words", type=int, default=DEFAULT_CHUNK_WORDS,
                    help=f"base words per resumable unit (default {DEFAULT_CHUNK_WORDS:,})")
    ap.add_argument("--no-resume", action="store_true", help="ignore the state file, redo everything")
    ap.add_argument("--status", action="store_true", help="print done/remaining and exit")
    ap.add_argument("--dry-run", action="store_true", help="print the per-chunk commands, run nothing")
    args = ap.parse_args()

    hashcat = find_hashcat(args.hashcat)
    rules = find_rules(args.rules, hashcat)
    device_args = ["-d", args.hashcat_device] if args.hashcat_device else default_device_args()
    paths = {"rockyou": args.rockyou, "xato": args.xato, "langdir": args.langdir}

    print(f"### tier {args.tier}  |  search: {args.search}  |  hashcat: {hashcat}")
    units = build_units(args.tier, hashcat, device_args, rules, paths, args.chunk_words)

    state = {"version": 1, "completed": []} if args.no_resume else load_state()
    done = set(state["completed"])
    todo = [u for u in units if u["key"] not in done]
    print(f"units: {len(units)} total, {len(units) - len(todo)} done, {len(todo)} to run "
          f"(chunk = {args.chunk_words:,} base words)")

    if args.status:
        for u in units:
            print(f"  [{'x' if u['key'] in done else ' '}] {u['key']}")
        return 0

    if args.dry_run:
        for u in todo:
            gen = stdout_cmd(hashcat, device_args, u["rule"], u["wordlist"], u["skip"], u["limit"])
            print("  " + subprocess.list2cmdline(gen) + "  |  " + subprocess.list2cmdline(searcher_cmd(args.search)))
        return 0

    for i, unit in enumerate(todo, 1):
        print(f"\n[{i}/{len(todo)}] {unit['key']}", flush=True)
        result = run_unit(unit, hashcat, device_args, args.search)
        if result == "found":
            state["completed"].append(unit["key"]); save_state(state)
            print(f"\n*** HIT in {unit['key']} -- see HITS.txt. Sweep the address now. ***")
            return 0
        if result == "exhausted":
            state["completed"].append(unit["key"]); save_state(state)
        else:  # error: do not record, stop so the user can see what broke
            print(f"stopping: unit {unit['key']} did not complete cleanly and was NOT "
                  f"marked done (it will re-run next time).", file=sys.stderr)
            return 2

    print(f"\ntier {args.tier}: all {len(units)} units complete, 0 matches.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
