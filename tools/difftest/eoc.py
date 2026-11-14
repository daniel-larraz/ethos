"""Differential testing of the Eunoia compiler: ethos-eoc against a candidate.

eoc is a Python driver (tools/eoc/driver.py) that runs a calculus through the
stages of ethos-eoc, Ethos built with its compiler plugins (desugar,
trim-defs, model-smt, smt-meta, lean-meta). Everything it produces is files.
A case is one driver command (`vc`, `vc --sygus`, `lean`, `desugar`, ...) on
one signature and rule. It runs twice, once with each binary, each time in a
fresh copy of the reference's source tree with the binary as the build
directory's `ethos-eoc`, and the two runs are compared:

- outcome: "ok" (exit 0), "error" or "timeout";
- the driver's stdout and stderr, which include what the stages print,
  without the C++ "Fatal failure within" line (as `run` compares them);
- every file in the source tree and the build directory after the run, byte
  for byte: the stage files and published outputs under tools/eoc/out/ and
  the plugins' files under <build>/out/plugins/. A file only one run wrote is
  a difference too.

The directory of each run is written as <root> in output and in files, so
that the two runs, made in different directories, can be compared.

  ./difftest.py eoc --ref work/ref/<rev>/build-eoc/ethos-eoc \\
      --cand /path/to/pathos-eoc --src work/ref/<rev>/src
"""

import concurrent.futures
import dataclasses
import difflib
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# The semantics eoc's own regression (tools/eoc/test/regress.py) compiles its
# signatures under; the only one in the tree.
SEMANTICS = "tools/eoc/test/semantics.eos"

# Signatures compiled rule by rule, relative to the source tree, when none
# are given: the two tools/eoc/test/regress.py compiles, and every file of
# tests/ that declares a rule. Under the test semantics many of the latter
# end in an error, which is compared like any other output.
REGRESS_SIGNATURES = ["tests/Booleans-rules.eo", "tools/eoc/test/nary-nil.eo"]


def default_signatures(src):
    tests = sorted(str(p.relative_to(src)) for p in (src / "tests").glob("*.eo")
                   if b"declare-rule" in p.read_bytes())
    return REGRESS_SIGNATURES + [t for t in tests if t not in REGRESS_SIGNATURES]

# Driver commands run on each rule: (name, arguments before the signature).
RULE_RUNS = [
    ("vc", ["vc", "--skip-cvc5"]),
    ("sygus", ["vc", "--skip-cvc5", "--sygus"]),
    ("lean", ["lean", "--skip-cvc5"]),
    ("trim-defs", ["trim-defs"]),
]

# Driver commands run on a whole signature.
SIGNATURE_RUNS = [
    ("desugar", ["desugar"]),
    ("desugar-eo", ["desugar", "--natives=eo"]),
]

SKIP_DIRS = {"__pycache__"}

# The line Ethos prints before an error, naming its C++ source; as in
# difftest.FATAL_LOCATION_RE.
FATAL_LOCATION_RE = re.compile(r"^Fatal failure within .* at .*:\d+$")


@dataclasses.dataclass
class EocCase:
    name: str
    args: list         # driver arguments: the command, then its options


@dataclasses.dataclass
class EocRun:
    outcome: str
    stdout: list
    stderr: list
    files: dict        # path relative to the run directory -> bytes
    wall_s: float


def list_rules(src, signature):
    out = subprocess.run(
        [sys.executable, str(src / "tools/eoc/driver.py"), "list-rules", signature],
        cwd=src, check=True, capture_output=True, text=True).stdout
    return [l.strip() for l in out.splitlines() if l.strip()]


def _signature_cases(src, prefix, sig, semantics):
    cases = [EocCase(f"{prefix}/{run}", [*args, *semantics, sig])
             for run, args in SIGNATURE_RUNS]
    for rule in list_rules(src, sig):
        for run, args in RULE_RUNS:
            cases.append(EocCase(f"{prefix}/{run}/{rule}",
                                 [*args, *semantics, sig, rule]))
    return cases


def logos_cases(src, logos):
    """CPC as logos (https://github.com/cvc5/logos) compiles it: the
    flattened signature install/defs/Cpc.cached.eo under logos's semantics
    install/defs/Cpc.eos and smt.eos. `lean --all` is the run logos's
    install/install-cpc.sh makes; the rest are as for the test signatures.
    Named eoc/logos/<run>[/<rule>]."""
    defs = Path(logos).resolve() / "install" / "defs"
    sig = str(defs / "Cpc.cached.eo")
    semantics = ["--semantics", str(defs / "Cpc.eos"),
                 "--smt-semantics", str(defs / "smt.eos")]
    return ([EocCase("eoc/logos/lean-all", ["lean", "--skip-cvc5", *semantics, "--all", sig])]
            + _signature_cases(src, "eoc/logos", sig, semantics))


def eoc_cases(src, signatures=None, logos=None, tests=True):
    """Every rule of each signature under RULE_RUNS, and each signature
    under SIGNATURE_RUNS, under the test semantics; named
    eoc/<signature>/<run>[/<rule>]. With `logos`, also logos_cases."""
    cases = []
    if tests:
        for sig in signatures or default_signatures(src):
            cases += _signature_cases(src, f"eoc/{Path(sig).name}", sig,
                                      ["--semantics", SEMANTICS])
    if logos:
        cases += logos_cases(src, logos)
    return cases


def _copy_source(src, dest):
    """The reference source without what earlier runs or the build wrote
    into it (tools/eoc/out/, caches)."""
    def ignore(d, names):
        skip = {n for n in names if n in SKIP_DIRS}
        if Path(d).resolve() == (src / "tools" / "eoc").resolve():
            skip.add("out")
        return skip
    shutil.copytree(src, dest, ignore=ignore, symlinks=True)


def _snapshot(root):
    files = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for f in filenames:
            p = Path(dirpath) / f
            if p.is_symlink() and p.name == "ethos-eoc":
                continue
            files[str(p.relative_to(root))] = p.read_bytes()
    return files


def _mask(data, root):
    if isinstance(data, bytes):
        return data.replace(str(root).encode(), b"<root>")
    return data.replace(str(root), "<root>")


def run_eoc(binary, src, case, timeout, keep=None):
    """Runs one case with `binary` as ethos-eoc in a fresh directory."""
    with tempfile.TemporaryDirectory(prefix="eoc-") as tmp:
        root = Path(tmp)
        _copy_source(src, root / "src")
        build = root / "build"
        build.mkdir()
        (build / "ethos-eoc").symlink_to(Path(binary).resolve())
        env = dict(os.environ,
                   ETHOS_PLUGIN_ROOT=str(root / "src"),
                   ETHOS_PLUGIN_OUTPUT_DIR=str(build / "out"),
                   PYTHONDONTWRITEBYTECODE="1")
        env.pop("EOC_FINAL_OUT_DIR", None)
        env.pop("CVC5", None)
        cmd = [sys.executable, "tools/eoc/driver.py", case.args[0],
               "--build-dir", str(build), "--no-build", *case.args[1:]]
        start = time.monotonic()
        try:
            done = subprocess.run(cmd, cwd=root / "src", env=env, timeout=timeout,
                                  capture_output=True, stdin=subprocess.DEVNULL)
            outcome = "ok" if done.returncode == 0 else "error"
            out, err = done.stdout, done.stderr
        except subprocess.TimeoutExpired as e:
            outcome, out, err = "timeout", e.stdout or b"", e.stderr or b""
        wall = time.monotonic() - start
        lines = lambda b: [l.rstrip(" \t\r") for l in
                           _mask(b, root).decode("latin-1").split("\n")]
        files = {} if outcome == "timeout" else {
            p: _mask(b, root) for p, b in _snapshot(root).items()}
        if keep is not None:
            if keep.exists():
                shutil.rmtree(keep)
            shutil.copytree(root, keep, symlinks=True)
        o = lines(out)
        e = [l for l in lines(err) if not FATAL_LOCATION_RE.match(l)]
        while o and not o[-1]:
            o.pop()
        while e and not e[-1]:
            e.pop()
        return EocRun(outcome, o, e, files, wall)


def compare_eoc(ref, cand):
    diffs = []
    if ref.outcome != cand.outcome:
        diffs.append("outcome")
    if ref.stdout != cand.stdout:
        diffs.append("stdout")
    if ref.stderr != cand.stderr:
        diffs.append("stderr")
    if ref.files != cand.files:
        diffs.append("files")
    return diffs


def describe(case, ref, cand, diffs, max_lines=40):
    lines = [f"--- {case.name}: differs in {', '.join(diffs)}",
             f"    driver {' '.join(case.args)}",
             f"    outcome: reference={ref.outcome} candidate={cand.outcome}"]

    def udiff(a, b, label):
        for i, l in enumerate(difflib.unified_diff(a, b, f"reference {label}",
                                                   f"candidate {label}",
                                                   lineterm="", n=2)):
            if i >= max_lines:
                lines.append("    ... (diff truncated)")
                break
            lines.append("    " + l)

    for stream in ("stdout", "stderr"):
        if stream in diffs:
            udiff(getattr(ref, stream), getattr(cand, stream), stream)
    if "files" in diffs:
        only_ref = sorted(set(ref.files) - set(cand.files))
        only_cand = sorted(set(cand.files) - set(ref.files))
        changed = sorted(p for p in set(ref.files) & set(cand.files)
                         if ref.files[p] != cand.files[p])
        for p in only_ref:
            lines.append(f"    only the reference wrote {p}")
        for p in only_cand:
            lines.append(f"    only the candidate wrote {p}")
        for p in changed:
            lines.append(f"    differs: {p}")
        if changed:
            p = changed[0]
            text = lambda b: b.decode("latin-1").split("\n")
            udiff(text(ref.files[p]), text(cand.files[p]), p)
    return "\n".join(lines)


def cmd_eoc(dt, args):
    src = Path(args.src).resolve()
    for b in (args.ref, args.cand):
        if not os.access(b, os.X_OK):
            sys.exit(f"error: {b} is not an executable")
    cases = eoc_cases(src, args.signature, args.logos, not args.no_tests)
    if args.filter:
        rx = re.compile(args.filter)
        cases = [c for c in cases if rx.search(c.name)]
    if not cases:
        sys.exit("error: no cases")

    def work(case):
        return (case, run_eoc(args.ref, src, case, args.timeout),
                run_eoc(args.cand, src, case, args.timeout))

    results = []
    started = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for case, ref, cand in pool.map(work, cases):
            results.append((case, ref, cand, compare_eoc(ref, cand)))
    differing = [r for r in results if r[3]]
    shown = differing if args.show_all else differing[:args.show]
    for case, ref, cand, diffs in shown:
        print(describe(case, ref, cand, diffs))
    if len(differing) > len(shown):
        print(f"... {len(differing) - len(shown)} more differing cases "
              f"(use --show-all or read the JSON report)")
    by_outcome = {}
    for _, ref, _, _ in results:
        by_outcome[ref.outcome] = by_outcome.get(ref.outcome, 0) + 1
    print(f"\ncases: {len(results)}  same: {len(results) - len(differing)}  "
          f"different: {len(differing)}  ({time.monotonic() - started:.1f} s)")
    print("reference outcomes: " + ", ".join(
        f"{k} {v}" for k, v in sorted(by_outcome.items())))
    rt = sum(r[1].wall_s for r in results)
    ct = sum(r[2].wall_s for r in results)
    print(f"driver time: reference {rt:.1f} s, candidate {ct:.1f} s "
          "(includes the Python driver)")
    if args.report:
        digest = lambda files: {p: hashlib.sha256(b).hexdigest()
                                for p, b in sorted(files.items())}
        Path(args.report).write_text(json.dumps({
            "reference": str(Path(args.ref).resolve()),
            "candidate": str(Path(args.cand).resolve()),
            "source": str(src),
            "cases": [{
                "name": c.name, "args": c.args, "differs_in": d,
                "reference": {"outcome": r.outcome, "stdout": r.stdout[:1000],
                              "stderr": r.stderr[:1000], "files": digest(r.files),
                              "wall_s": round(r.wall_s, 4)},
                "candidate": {"outcome": k.outcome, "stdout": k.stdout[:1000],
                              "stderr": k.stderr[:1000], "files": digest(k.files),
                              "wall_s": round(k.wall_s, 4)},
            } for c, r, k, d in results],
        }, indent=1))
        print(f"report: {args.report}")
    return 1 if differing else 0


def cmd_eoc_keep(dt, args):
    """Runs one case with one binary and keeps its directory, to look at."""
    src = Path(args.src).resolve()
    case = next((c for c in eoc_cases(src, args.signature, args.logos)
                 if c.name == args.case), None)
    if case is None:
        sys.exit(f"error: no case {args.case}")
    r = run_eoc(args.binary, src, case, args.timeout, keep=Path(args.out).resolve())
    print(f"{r.outcome}; directory: {args.out}")
    return 0


def add_parsers(sub, dt):
    p = sub.add_parser("eoc", help="compare ethos-eoc with a candidate (see eoc.py)")
    p.add_argument("--ref", required=True, help="reference ethos-eoc")
    p.add_argument("--cand", required=True, help="candidate ethos-eoc")
    p.add_argument("--src", required=True,
                   help="the reference's source tree (work/ref/<rev>/src)")
    p.add_argument("--signature", action="append",
                   help="signature to compile, relative to --src (repeatable; "
                        "default: the files of tests/ that declare a rule, "
                        "and tools/eoc/test/nary-nil.eo)")
    p.add_argument("--logos", help="a logos checkout: also compile CPC as logos "
                                    "does (see logos_cases)")
    p.add_argument("--no-tests", action="store_true",
                   help="leave out the signatures of tests/ (with --logos)")
    p.add_argument("--filter", help="only cases whose name matches this regex")
    p.add_argument("--jobs", "-j", type=int, default=os.cpu_count() or 1)
    p.add_argument("--timeout", type=float, default=120.0)
    p.add_argument("--report", help="write a JSON report here")
    p.add_argument("--show", type=int, default=20)
    p.add_argument("--show-all", action="store_true")
    p.set_defaults(func=lambda a: cmd_eoc(dt, a))

    p = sub.add_parser("eoc-keep", help="run one eoc case and keep its directory")
    p.add_argument("case")
    p.add_argument("--binary", required=True)
    p.add_argument("--src", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--signature", action="append")
    p.add_argument("--logos")
    p.add_argument("--timeout", type=float, default=120.0)
    p.set_defaults(func=lambda a: cmd_eoc_keep(dt, a))
