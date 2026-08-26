#!/usr/bin/env python3
r"""
Cross-platform driver for the blind rule-sweep tiers (Windows / macOS / Linux).

Replaces run_plan.sh. Each tier launches hashcat as a candidate GENERATOR
(`--stdout`: wordlist x rules, no cracking) and pipes its output into our
derivation search -- the only thing that can turn a BIP39 mnemonic+passphrase
into a BIP84 address. The pipe is set up with subprocess, so no shell is needed
and it behaves identically on Windows.

Read the README "search plan" first: the cheap thematic/alternate-path work is
already done (new_ground.py), and ~1.16 B human-plausible candidates are done by
floflo777. These tiers are the big blind sweeps that remain -- GPU territory.

Machine-specific paths are the only thing you must set. Point them at your files
with flags or environment variables (flags win):

    --hashcat / KITTEN_HASHCAT     hashcat.exe (auto-detected from PATH if omitted)
    --rules   / KITTEN_RULES       hashcat rules dir (auto-detected next to hashcat)
    --rockyou / KITTEN_ROCKYOU     rockyou.txt
    --xato    / KITTEN_XATO        xato-net-10-million-passwords-dup.txt
    --langdir / KITTEN_LANGDIR     SecLists .../Language-Specific directory

Examples (Windows PowerShell):

    python run_plan.py A --search gpu `
        --hashcat C:\tools\hashcat\hashcat.exe `
        --rockyou C:\wordlists\rockyou.txt

    # or set once, then just pick tiers:
    $env:KITTEN_HASHCAT="C:\tools\hashcat\hashcat.exe"
    $env:KITTEN_ROCKYOU="C:\wordlists\rockyou.txt"
    python run_plan.py A --search gpu
    python run_plan.py --dry-run A          # print the commands, run nothing
"""
from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


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
    """Locate the hashcat rules directory, portably.

    On a Windows hashcat release the rules sit in `<hashcat_dir>\rules`; a brew
    install puts them under share/doc/hashcat/rules. Check the obvious spots
    around the binary before giving up.
    """
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
             "Pass --rules <dir> or set KITTEN_RULES. It ships inside the "
             "hashcat release folder as 'rules'.")


def need_file(path: Path | None, flag: str, env: str, what: str) -> Path:
    if path and path.exists():
        return path
    if path:
        sys.exit(f"{flag} {path}: not found")
    sys.exit(f"{what} not set. Pass {flag} <path> or set {env}.")


def searcher_cmd(search: str) -> list[str]:
    """The search process that consumes candidates on stdin."""
    py = sys.executable  # the interpreter running THIS script -> use the same venv
    if search == "gpu":
        return [py, str(HERE / "gpu" / "gpu_bruteforce.py"), "--stdin"]
    return [py, str(HERE / "bruteforce_fast.py"), "--stdin"]


def hashcat_stdout_cmd(hashcat: Path, device_args: list[str], rule: Path | None,
                       wordlist: Path) -> list[str]:
    cmd = [str(hashcat)] + device_args + ["--stdout"]
    if rule:
        cmd += ["-r", str(rule)]
    cmd.append(str(wordlist))
    return cmd


def default_device_args() -> list[str]:
    """Apple's OpenCL GPU fails to build hashcat's kernel, so pin device 1 there.
    On Windows/Linux let hashcat use every device (candidate generation is cheap
    either way, and this avoids guessing device ids)."""
    return ["-d", "1"] if platform.system() == "Darwin" else []


def run_pipeline(gen_cmds: list[list[str]], search: str, dry_run: bool) -> int:
    """Run one or more hashcat generators, all feeding a single search process.

    Multiple generators (tier D) stream into the same searcher's stdin in
    sequence, exactly like the shell `for ... done | search` did.
    """
    scmd = searcher_cmd(search)
    if dry_run:
        for g in gen_cmds:
            print("  " + subprocess.list2cmdline(g) + "  |  " + subprocess.list2cmdline(scmd))
        return 0

    search_proc = subprocess.Popen(scmd, stdin=subprocess.PIPE)
    try:
        for g in gen_cmds:
            gen = subprocess.Popen(g, stdout=search_proc.stdin)
            gen.wait()
            if gen.returncode not in (0, None):
                print(f"warning: generator exited {gen.returncode}: "
                      f"{subprocess.list2cmdline(g)}", file=sys.stderr)
    finally:
        if search_proc.stdin:
            search_proc.stdin.close()
        search_proc.wait()
    return search_proc.returncode or 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("tier", choices=list("ABCD"), help="which sweep to run")
    ap.add_argument("--search", choices=("cpu", "gpu"), default="cpu",
                    help="derivation search backend (default: cpu; use gpu on a real GPU)")
    ap.add_argument("--hashcat", type=Path)
    ap.add_argument("--rules", type=Path)
    ap.add_argument("--rockyou", type=Path, default=_env_path("KITTEN_ROCKYOU"))
    ap.add_argument("--xato", type=Path, default=_env_path("KITTEN_XATO"))
    ap.add_argument("--langdir", type=Path, default=_env_path("KITTEN_LANGDIR"))
    ap.add_argument("--hashcat-device", default=None,
                    help="override device selection, e.g. '2' or '1,2' (default: "
                         "device 1 on macOS, all devices elsewhere)")
    ap.add_argument("--dry-run", action="store_true", help="print commands, run nothing")
    args = ap.parse_args()

    hashcat = find_hashcat(args.hashcat)
    device_args = (["-d", args.hashcat_device] if args.hashcat_device
                   else default_device_args())

    print(f"### tier {args.tier}  |  search: {args.search}  |  hashcat: {hashcat}")

    if args.tier in ("A", "B"):
        rules = find_rules(args.rules, hashcat)
        rockyou = need_file(args.rockyou, "--rockyou", "KITTEN_ROCKYOU", "rockyou.txt")
        rule = rules / ("dive.rule" if args.tier == "A" else "d3ad0ne.rule")
        if not rule.exists():
            sys.exit(f"{rule} not found in the rules dir")
        gens = [hashcat_stdout_cmd(hashcat, device_args, rule, rockyou)]

    elif args.tier == "C":
        rules = find_rules(args.rules, hashcat)
        xato = need_file(args.xato, "--xato", "KITTEN_XATO",
                         "xato-net-10-million-passwords-dup.txt")
        rule = rules / "best66.rule"
        if not rule.exists():
            sys.exit(f"{rule} not found in the rules dir")
        gens = [hashcat_stdout_cmd(hashcat, device_args, rule, xato)]

    else:  # D
        rules = find_rules(args.rules, hashcat)
        langdir = need_file(args.langdir, "--langdir", "KITTEN_LANGDIR",
                            "SecLists Language-Specific directory")
        rule = rules / "best64.rule"
        lists = sorted(langdir.glob("*.txt"))
        if not lists:
            sys.exit(f"no *.txt lists in {langdir}")
        print(f"  {len(lists)} language lists")
        gens = [hashcat_stdout_cmd(hashcat, device_args, rule, wl) for wl in lists]

    return run_pipeline(gens, args.search, args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
