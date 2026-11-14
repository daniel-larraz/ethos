#!/usr/bin/env python3
"""Differential testing for Ethos.

Runs a reference Ethos binary and a candidate binary on the same inputs and
reports every case where their observable behaviour differs. It is meant to
be the definition of "done" for a reimplementation: the candidate matches when
`difftest.py run` reports no differences.

Subcommands:
  build-ref    build a Release reference binary from a git revision
  gen-proofs   generate a corpus of cvc5 CPC proofs from cvc5's regressions
  run          compare a reference and a candidate binary on the inputs
  fuzz         compare them on mutated inputs (fuzz.py)
  fuzz-replay  rerun saved fuzzing findings

See README.md in this directory for what counts as "the same".
Only the Python standard library is used.
"""

import argparse
import concurrent.futures
import dataclasses
import difflib
import hashlib
import json
import os
import re
import resource
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_WORK = HERE / "work"

# ---------------------------------------------------------------------------
# Running one binary on one case
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class Run:
    exit_code: int        # >= 0 exit status; < 0 killed by that signal
    timed_out: bool
    stdout: str
    stderr: str
    wall_s: float
    max_rss_kb: int


def find_gnu_time():
    """Returns the path of GNU time, or None.

    Peak memory has to be measured through it. A process started from Python
    is a copy of the Python process, and Linux keeps a process's peak RSS
    across exec, so wait4 on it reports at least Python's own size (about
    30 MiB). GNU time is small, and it reads the peak of the process it
    starts.
    """
    path = shutil.which("time")
    if not path:
        return None
    try:
        out = subprocess.run([path, "--version"], capture_output=True,
                             text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    return path if "GNU" in out.stdout + out.stderr else None


GNU_TIME = find_gnu_time()

# Part of the reference cache key: change it whenever the way time or memory
# is measured, or output is decoded, changes, so that cached results are not
# mixed with new ones.
MEASUREMENT = ("gnu-time-1" if GNU_TIME else "wait4-1") + "/bytes-1/blocking-wait-1"


def run_binary(binary, args, cwd, timeout):
    """Runs `binary args` in `cwd`; returns its output, time and peak RSS.

    Output goes to temporary files rather than pipes so that a process
    producing a lot of output cannot block. The peak RSS comes from GNU time
    when it is installed (see find_gnu_time), and otherwise from wait4, which
    overstates it by the size of the Python process.
    """
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err, \
            tempfile.NamedTemporaryFile("r") as rss_file:
        command = [str(binary), *args]
        if GNU_TIME:
            command = [GNU_TIME, "-q", "-f", "%M", "-o", rss_file.name, *command]
        start = time.monotonic()
        proc = subprocess.Popen(
            command,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=out,
            stderr=err,
            start_new_session=True,
        )
        # Block in wait4 so that the wall time is exact; a timer kills the
        # process group on timeout. (Polling with growing sleeps rounded
        # times up to the next poll: 33 ms read as 64 ms.)
        lock = threading.Lock()
        state = {"reaped": False, "timed_out": False}

        def kill():
            with lock:
                if state["reaped"]:
                    return
                state["timed_out"] = True
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

        timer = threading.Timer(timeout, kill)
        timer.daemon = True
        timer.start()
        try:
            pid, status, rusage = os.wait4(proc.pid, 0)
        finally:
            wall = time.monotonic() - start
            with lock:
                state["reaped"] = True
            timer.cancel()
        timed_out = state["timed_out"]
        proc.returncode = os.waitstatus_to_exitcode(status)
        maxrss = rusage.ru_maxrss
        if sys.platform == "darwin":  # bytes on macOS, KiB on Linux
            maxrss //= 1024
        if GNU_TIME and not timed_out:
            # GNU time passes the exit status through; a signal becomes
            # 128 + its number. Both are non-zero, as before.
            try:
                maxrss = int(rss_file.read().strip().splitlines()[-1])
            except (ValueError, IndexError):
                pass  # keep the wait4 figure
        out.seek(0)
        err.seek(0)
        return Run(
            exit_code=proc.returncode,
            timed_out=timed_out,
            # surrogateescape keeps every byte: invalid UTF-8 bytes become
            # distinct code points instead of all becoming U+FFFD, so two
            # outputs compare equal only if their bytes are equal.
            stdout=out.read().decode("utf-8", errors="surrogateescape"),
            stderr=err.read().decode("utf-8", errors="surrogateescape"),
            wall_s=wall,
            max_rss_kb=maxrss,
        )


# ---------------------------------------------------------------------------
# Normalization: what counts as "the same"
# ---------------------------------------------------------------------------

# The C++ checker prefixes every fatal error with the C++ function and source
# location that raised it. That line is an implementation detail and is not
# compared.
FATAL_LOCATION_RE = re.compile(r"^Fatal failure within .* at .*:\d+$")


def _clean_lines(text):
    # Only "\n" ends a line and only space, tab and "\r" are trimmed. Python's
    # splitlines() and strip() also act on Unicode characters such as U+0085
    # and U+00A0, which would hide differences in exactly those characters.
    lines = [line.rstrip(" \t\r") for line in text.split("\n")]
    while lines and not lines[0]:
        lines.pop(0)
    while lines and not lines[-1]:
        lines.pop()
    return lines


def normalize(run):
    """Returns the observable behaviour of a run, as compared by `run`.

    - outcome: "timeout", "correct", "incomplete", "success-other" (exit 0
      without a verdict line) or "error" (any non-zero exit or signal).
      The exact exit code and signal are not compared.
    - stdout: compared only when the outcome is not "error". The C++ checker
      aborts on errors, so stdout buffered at that point is lost.
    - stderr: compared always, without the C++ "Fatal failure within" line.
    """
    if run.timed_out:
        return {"outcome": "timeout", "stdout": [], "stderr": []}
    out_lines = _clean_lines(run.stdout)
    err_lines = [
        line
        for line in _clean_lines(run.stderr)
        if not FATAL_LOCATION_RE.match(line)
    ]
    err_lines = _clean_lines("\n".join(err_lines))
    if run.exit_code != 0:
        return {"outcome": "error", "stdout": [], "stderr": err_lines}
    verdict = out_lines[-1] if out_lines else ""
    outcome = verdict if verdict in ("correct", "incomplete") else "success-other"
    return {"outcome": outcome, "stdout": out_lines, "stderr": err_lines}


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class Case:
    name: str        # stable identifier, used in reports and the cache
    args: list       # arguments passed to the binary
    cwd: str         # working directory
    path: Path       # main input file
    root: Path       # directory whose contents the case may include


def regression_cases(tests_dir):
    """Every top-level .eo and .smt2 file of Ethos's tests/ directory.

    Run the way tests/CMakeLists.txt runs them: absolute path, working
    directory = repository root, no options. Files that are only included by
    other tests are run on their own too; the two checkers must agree on
    those as well. tests/smtlib holds cvc5 inputs and is skipped.
    """
    tests_dir = tests_dir.resolve()
    files = sorted(
        p for p in tests_dir.iterdir()
        if p.is_file() and p.suffix in (".eo", ".smt2")
    )
    return [
        Case(
            name=f"tests/{p.name}",
            args=[str(p)],
            cwd=str(tests_dir.parent),
            path=p,
            root=tests_dir,
        )
        for p in files
    ]


# Ethos's options set to their non-default values (src/state.cpp, Options),
# one at a time and then all together. The --stats options are left out:
# their output contains timings, which differ between runs.
_NON_DEFAULT_OPTIONS = [
    "--no-parse-let",
    "--no-print-dag",
    "--no-rule-sym-table",
    "--no-normalize-dec",
    "--no-normalize-hex",
    "--normalize-num",
    "--require-proof-of-false",
    "--reference-define-fun",
]
ETHOS_OPTION_SETS = [[o] for o in _NON_DEFAULT_OPTIONS] + [_NON_DEFAULT_OPTIONS]


def with_options(case, options):
    """The case run with `options` before its input file."""
    if not options:
        return case
    return dataclasses.replace(
        case,
        name=f"{case.name} [{' '.join(options)}]",
        args=[*options, *case.args],
    )


def corpus_cases(corpus_dir):
    """The proofs of a corpus, named `<corpus directory>/<proof file>` so that
    two corpora can be compared in one run without clashing names."""
    corpus_dir = corpus_dir.resolve()
    proofs = sorted((corpus_dir / "proofs").glob("*.cpc"))
    return [
        Case(
            name=f"{corpus_dir.name}/{p.name}",
            args=[str(p)],
            cwd=str(corpus_dir),
            path=p,
            root=corpus_dir,
        )
        for p in proofs
    ]


# ---------------------------------------------------------------------------
# Reference cache
# ---------------------------------------------------------------------------


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


_root_fingerprints = {}


def root_fingerprint(root):
    """Cheap fingerprint of every file a case could include."""
    if root not in _root_fingerprints:
        h = hashlib.sha256()
        for p in sorted(root.rglob("*")):
            if p.is_file():
                st = p.stat()
                h.update(f"{p.relative_to(root)}\0{st.st_size}\0{st.st_mtime_ns}\n".encode())
        _root_fingerprints[root] = h.hexdigest()
    return _root_fingerprints[root]


def cache_key(ref_sha, case, timeout):
    parts = [ref_sha, case.name, " ".join(case.args), case.cwd,
             sha256_file(case.path), root_fingerprint(case.root), str(timeout),
             MEASUREMENT]
    return hashlib.sha256("\0".join(parts).encode()).hexdigest()


class RefCache:
    def __init__(self, path):
        self.path = path
        self.data = {}
        if path and path.exists():
            try:
                self.data = json.loads(path.read_text())
            except (OSError, ValueError):
                self.data = {}

    def get(self, key):
        entry = self.data.get(key)
        return Run(**entry) if entry else None

    def put(self, key, run):
        self.data[key] = dataclasses.asdict(run)

    def save(self):
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.data))
            tmp.replace(self.path)


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


def compare(ref, cand):
    """Returns the list of aspects in which two normalized runs differ."""
    diffs = []
    if ref["outcome"] != cand["outcome"]:
        diffs.append("outcome")
    if ref["stderr"] != cand["stderr"]:
        diffs.append("stderr")
    if ref["stdout"] != cand["stdout"]:
        diffs.append("stdout")
    return diffs


def describe_diff(case_name, ref, cand, diffs):
    lines = [f"--- {case_name}: differs in {', '.join(diffs)}"]
    lines.append(f"    outcome: reference={ref['outcome']} candidate={cand['outcome']}")
    for stream in ("stderr", "stdout"):
        if stream in diffs:
            udiff = difflib.unified_diff(
                ref[stream], cand[stream],
                fromfile=f"reference {stream}", tofile=f"candidate {stream}",
                lineterm="", n=2,
            )
            for i, line in enumerate(udiff):
                if i >= 40:
                    lines.append("    ... (diff truncated; see the JSON report)")
                    break
                lines.append("    " + printable(line[:300]))
    return "\n".join(lines)


def printable(text):
    """Shows bytes that are not valid UTF-8 as \\xNN, and non-printable
    characters such as U+00A0 as \\xNN or \\uNNNN, so that they can be printed
    and told apart."""
    text = text.encode("utf-8", "surrogateescape").decode("utf-8", "backslashreplace")
    return "".join(
        c if c.isprintable() or c == "\t" else c.encode("unicode_escape").decode("ascii")
        for c in text
    )


def cmd_run(args):
    ref_bin = Path(args.ref).resolve()
    cand_bin = Path(args.cand).resolve()
    for b in (ref_bin, cand_bin):
        if not os.access(b, os.X_OK):
            sys.exit(f"error: {b} is not an executable")

    cases = []
    if args.tests:
        cases += regression_cases(Path(args.tests))
    for corpus in args.corpus or []:
        cases += corpus_cases(Path(corpus))
    option_sets = [[]]
    if args.all_option_sets:
        option_sets += ETHOS_OPTION_SETS
    option_sets += [shlex.split(o) for o in args.options or []]
    cases = [with_options(c, opts) for c in cases for opts in option_sets]
    if args.filter:
        rx = re.compile(args.filter)
        cases = [c for c in cases if rx.search(c.name)]
    if not cases:
        sys.exit("error: no cases (give --tests and/or --corpus)")

    # Ethos aborts on every error. Never let that write core files into the
    # working directories (the repository, the corpus): children inherit
    # this limit.
    soft, hard = resource.getrlimit(resource.RLIMIT_CORE)
    resource.setrlimit(resource.RLIMIT_CORE, (0, hard))

    ref_sha = sha256_file(ref_bin)
    cache = RefCache(None if args.no_cache else Path(args.cache))

    def work(case):
        key = cache_key(ref_sha, case, args.timeout)
        ref_run = cache.get(key)
        cached = ref_run is not None
        if not cached:
            ref_run = run_binary(ref_bin, case.args, case.cwd, args.timeout)
        cand_run = run_binary(cand_bin, case.args, case.cwd, args.timeout)
        return case, key, ref_run, cached, cand_run

    results = []
    started = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = [pool.submit(work, c) for c in cases]
        for i, fut in enumerate(concurrent.futures.as_completed(futures), 1):
            case, key, ref_run, cached, cand_run = fut.result()
            if not cached and not ref_run.timed_out:
                cache.put(key, ref_run)
            ref_n, cand_n = normalize(ref_run), normalize(cand_run)
            diffs = compare(ref_n, cand_n)
            results.append((case, ref_run, cand_run, ref_n, cand_n, diffs))
            if not args.quiet and sys.stderr.isatty():
                print(f"\r{i}/{len(cases)}", end="", file=sys.stderr, flush=True)
    if not args.quiet and sys.stderr.isatty():
        print("\r", end="", file=sys.stderr)
    cache.save()
    results.sort(key=lambda r: r[0].name)
    elapsed = time.monotonic() - started

    differing = [r for r in results if r[5]]
    shown = differing if args.show_all else differing[: args.show]
    for case, _, _, ref_n, cand_n, diffs in shown:
        print(describe_diff(case.name, ref_n, cand_n, diffs))
    if len(shown) < len(differing):
        print(f"... {len(differing) - len(shown)} more differing cases "
              f"(use --show-all or read the JSON report)")

    # Summary
    by_outcome = {}
    for _, _, _, ref_n, _, _ in results:
        by_outcome[ref_n["outcome"]] = by_outcome.get(ref_n["outcome"], 0) + 1
    print()
    print(f"cases: {len(results)}  same: {len(results) - len(differing)}  "
          f"different: {len(differing)}  ({elapsed:.1f} s)")
    print("reference outcomes: " +
          ", ".join(f"{k} {v}" for k, v in sorted(by_outcome.items())))

    # Performance, over cases where both checkers succeeded the same way
    both_ok = [r for r in results
               if not r[5] and r[3]["outcome"] in ("correct", "incomplete")]
    if both_ok:
        rt = sum(r[1].wall_s for r in both_ok)
        ct = sum(r[2].wall_s for r in both_ok)
        rm = max(r[1].max_rss_kb for r in both_ok)
        cm = max(r[2].max_rss_kb for r in both_ok)
        print(f"time over {len(both_ok)} agreeing successful cases: "
              f"reference {rt:.2f} s, candidate {ct:.2f} s "
              f"({100 * ct / rt if rt else 0:.0f}%)")
        print(f"largest peak memory: reference {rm / 1024:.1f} MiB, "
              f"candidate {cm / 1024:.1f} MiB")
        if not GNU_TIME:
            print("note: GNU time not found; peak memory includes the "
                  "harness's own Python process (about 30 MiB)")
        if args.jobs > 1:
            print("note: timings with --jobs > 1 are noisy; use --jobs 1 "
                  "--no-cache to compare speed")

    if args.report:
        report = {
            "reference": str(ref_bin),
            "reference_sha256": ref_sha,
            "candidate": str(cand_bin),
            "timeout_s": args.timeout,
            "measurement": MEASUREMENT,
            "cases": [
                {
                    "name": case.name,
                    "args": case.args,
                    "cwd": case.cwd,
                    "differs_in": diffs,
                    "reference": {**ref_n, "exit_code": ref_run.exit_code,
                                  "wall_s": round(ref_run.wall_s, 4),
                                  "max_rss_kb": ref_run.max_rss_kb},
                    "candidate": {**cand_n, "exit_code": cand_run.exit_code,
                                  "wall_s": round(cand_run.wall_s, 4),
                                  "max_rss_kb": cand_run.max_rss_kb},
                }
                for case, ref_run, cand_run, ref_n, cand_n, diffs in results
            ],
        }
        Path(args.report).write_text(json.dumps(report, indent=1))
        print(f"report: {args.report}")

    return 1 if differing else 0


# ---------------------------------------------------------------------------
# build-ref
# ---------------------------------------------------------------------------


def cmd_build_ref(args):
    repo = Path(args.repo).resolve()
    rev = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--verify", args.rev + "^{commit}"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    out = Path(args.out).resolve() / rev[:12]
    binary = out / "build" / "src" / "ethos"
    if binary.exists() and not args.force:
        print(binary)
        return 0
    if out.exists():
        shutil.rmtree(out)
    src = out / "src"
    src.mkdir(parents=True)
    # git archive keeps the reference source independent of the working tree
    # and registers no worktree.
    archive = subprocess.run(
        ["git", "-C", str(repo), "archive", "--format=tar", rev],
        check=True, capture_output=True,
    ).stdout
    with tempfile.TemporaryFile() as f:
        f.write(archive)
        f.seek(0)
        with tarfile.open(fileobj=f) as tar:
            tar.extractall(src, filter="data")
    build = out / "build"
    subprocess.run(
        ["cmake", "-S", str(src), "-B", str(build), "-DCMAKE_BUILD_TYPE=Release"],
        check=True, stdout=subprocess.DEVNULL,
    )
    subprocess.run(
        ["cmake", "--build", str(build), "--target", "ethos", "-j", str(args.jobs)],
        check=True, stdout=subprocess.DEVNULL,
    )
    (out / "REVISION").write_text(rev + "\n")
    print(binary)
    return 0


# ---------------------------------------------------------------------------
# gen-proofs
# ---------------------------------------------------------------------------

def export_tree(repo, rev, subpath, dest):
    """Writes `subpath` of `repo` at `rev` to `dest` (replacing it)."""
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    archive = subprocess.run(
        ["git", "-C", str(repo), "archive", "--format=tar", rev, subpath],
        check=True, capture_output=True,
    ).stdout
    with tempfile.TemporaryFile() as f:
        f.write(archive)
        f.seek(0)
        with tarfile.open(fileobj=f) as tar:
            for member in tar.getmembers():
                member.name = member.name[len(subpath):].lstrip("/")
                if member.name:
                    tar.extract(member, dest, filter="data")


UNSAT_STATUS_RE = re.compile(r"set-info\s*:status\s*(sat|unsat)")


def read_directives(path):
    """Parses the metadata comments of a cvc5 regression, as cvc5's
    test/regress/cli/run_regression.py does."""
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return None
    expect, command_lines, requires, disabled = [], [], [], []
    for line in text.splitlines():
        if not line.startswith(";"):
            continue
        line = line[1:].lstrip()
        if line.startswith("EXPECT:"):
            expect.append(line[len("EXPECT:"):].strip())
        elif line.startswith("COMMAND-LINE:"):
            command_lines.append(line[len("COMMAND-LINE:"):].strip())
        elif line.startswith("REQUIRES:"):
            requires.append(line[len("REQUIRES:"):].strip())
        elif line.startswith("DISABLE-TESTER:"):
            disabled.append(line[len("DISABLE-TESTER:"):].strip())
    expected = "\n".join(expect).strip()
    if not expected:
        expected = "\n".join(UNSAT_STATUS_RE.findall(text))
    return {"expected": expected, "command_lines": command_lines,
            "requires": requires, "disabled": disabled}


def candidate_benchmarks(regress_dir, levels):
    """Benchmarks the cvc5 CPC tester would run, grouped by directory."""
    groups = {}
    for level in levels:
        base = regress_dir / level
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*.smt2")):
            d = read_directives(p)
            if d is None or d["expected"] != "unsat":
                continue
            if "proof" in d["disabled"] or "cpc" in d["disabled"]:
                continue
            if d["requires"]:
                continue  # needs optional cvc5 features; skip rather than guess
            groups.setdefault(str(p.parent.relative_to(regress_dir)), []).append((p, d))
    return groups


def round_robin(groups):
    """Interleaves groups so that a prefix of the result spans all of them."""
    queues = [list(v) for _, v in sorted(groups.items())]
    while queues:
        for q in list(queues):
            yield q.pop(0)
            if not q:
                queues.remove(q)


def cmd_gen_proofs(args):
    cvc5 = Path(args.cvc5).resolve()
    cvc5_src = Path(args.cvc5_src).resolve()
    out = Path(args.out).resolve()
    version = subprocess.run([str(cvc5), "--version"], capture_output=True,
                             text=True).stdout.splitlines()[0]
    rev = args.cvc5_rev
    if rev is None:
        m = re.search(r"\[git ([0-9a-f]+)", version)
        if not m:
            sys.exit("error: cannot read the git revision from "
                     f"`{cvc5} --version`; pass --cvc5-rev")
        rev = m.group(1)
    full_rev = subprocess.run(
        ["git", "-C", str(cvc5_src), "rev-parse", "--verify", rev + "^{commit}"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()

    # The CPC signature and the benchmarks, both frozen at the revision the
    # cvc5 binary was built from, whatever the checkout has checked out.
    sig = out / "cpc"
    export_tree(cvc5_src, full_rev, "proofs/eo/cpc", sig)
    regress = out / ".benchmarks"
    export_tree(cvc5_src, full_rev, "test/regress/cli", regress)

    proofs_dir = out / "proofs"
    if proofs_dir.exists():
        shutil.rmtree(proofs_dir)
    proofs_dir.mkdir(parents=True)
    groups = candidate_benchmarks(regress, args.levels.split(","))
    total = sum(len(v) for v in groups.values())
    print(f"{total} unsat benchmarks in {len(groups)} directories; "
          f"generating up to {args.limit} proofs", file=sys.stderr)

    def generate(item):
        bench, d = item
        name = str(bench.relative_to(regress)).replace("/", "__")
        # Not ".eo": Ethos treats *.eo files as signatures, where `let` is
        # not built in (src/main.cpp). cvc5's own tester uses no suffix.
        name = name[: -len(".smt2")] + ".cpc"
        extra = shlex.split(d["command_lines"][0]) if d["command_lines"] else []
        cvc5_args = ["--dump-proofs", "--proof-print-conclusion", *extra]
        run = run_binary(cvc5, [*cvc5_args, bench.name], str(bench.parent),
                         args.timeout)
        body = run.stdout
        if (run.timed_out or run.exit_code != 0
                or not body.startswith("unsat\n(\n") or not body.endswith("\n)\n")):
            return None
        body = body[len("unsat\n(\n"):-len("\n)\n")]
        if "step" not in body and "assume" not in body:
            return None
        if len(body) < args.min_bytes:
            return None
        header = (f"; generated by difftest.py gen-proofs\n"
                  f"; benchmark: {bench.relative_to(regress)}\n"
                  f"; cvc5: {version}\n"
                  f"; cvc5 args: {shlex.join(cvc5_args)}\n"
                  f"(include \"../cpc/Cpc.eo\")\n"
                  f"(include \"../cpc/expert/CpcExpert.eo\")\n")
        (proofs_dir / name).write_text(header + body + "\n")
        return {"proof": name, "benchmark": str(bench.relative_to(regress)),
                "cvc5_args": cvc5_args, "bytes": len(body)}

    made = []
    items = round_robin(groups)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        pending = set()
        exhausted = False
        while True:
            # Keep enough work in flight to reach the limit even if some
            # benchmarks yield no proof.
            while not exhausted and len(pending) < args.jobs * 2 \
                    and len(made) + len(pending) < args.limit:
                try:
                    pending.add(pool.submit(generate, next(items)))
                except StopIteration:
                    exhausted = True
            if not pending:
                break
            done, pending = concurrent.futures.wait(
                pending, return_when=concurrent.futures.FIRST_COMPLETED)
            for fut in done:
                r = fut.result()
                if r and len(made) < args.limit:
                    made.append(r)
                    if sys.stderr.isatty():
                        print(f"\r{len(made)} proofs", end="", file=sys.stderr,
                              flush=True)
    if sys.stderr.isatty():
        print(file=sys.stderr)
    made.sort(key=lambda r: r["proof"])
    manifest = {
        "cvc5": version,
        "cvc5_binary": str(cvc5),
        "cvc5_revision": full_rev,
        "levels": args.levels,
        "min_bytes": args.min_bytes,
        "timeout_s": args.timeout,
        "proofs": made,
    }
    (out / "MANIFEST.json").write_text(json.dumps(manifest, indent=1))
    shutil.rmtree(regress)
    print(f"wrote {len(made)} proofs to {proofs_dir}")
    return 0


# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("run", help="compare a reference and a candidate binary")
    p.add_argument("--ref", required=True, help="reference ethos binary")
    p.add_argument("--cand", required=True, help="candidate binary")
    p.add_argument("--tests", help="Ethos tests/ directory (regressions)")
    p.add_argument("--corpus", action="append",
                   help="proof corpus made by gen-proofs (repeatable)")
    p.add_argument("--filter", help="only cases whose name matches this regex "
                                    "(option variants end in ' [<options>]')")
    p.add_argument("--options", action="append", metavar="OPTS",
                   help="also run every case with these options, e.g. "
                        "'--no-print-dag' (repeatable)")
    p.add_argument("--all-option-sets", action="store_true",
                   help="also run every case with each option set in "
                        "ETHOS_OPTION_SETS")
    p.add_argument("--jobs", "-j", type=int, default=os.cpu_count() or 1)
    p.add_argument("--timeout", type=float, default=120.0,
                   help="seconds per binary per case (default 120)")
    p.add_argument("--report", help="write a JSON report here")
    p.add_argument("--show", type=int, default=20,
                   help="print at most this many differing cases (default 20)")
    p.add_argument("--show-all", action="store_true")
    p.add_argument("--cache", default=str(DEFAULT_WORK / "ref-cache.json"),
                   help="reference results cache (default work/ref-cache.json)")
    p.add_argument("--no-cache", action="store_true",
                   help="always rerun the reference")
    p.add_argument("--quiet", "-q", action="store_true")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("build-ref", help="build a reference binary")
    p.add_argument("rev", help="git revision, e.g. origin/main or 9217112f")
    p.add_argument("--repo", default=str(HERE.parent.parent),
                   help="Ethos repository (default: this one)")
    p.add_argument("--out", default=str(DEFAULT_WORK / "ref"))
    p.add_argument("--jobs", "-j", type=int, default=os.cpu_count() or 1)
    p.add_argument("--force", action="store_true", help="rebuild if present")
    p.set_defaults(func=cmd_build_ref)

    p = sub.add_parser("gen-proofs", help="generate a cvc5 proof corpus")
    p.add_argument("--cvc5", required=True, help="cvc5 binary")
    p.add_argument("--cvc5-src", required=True,
                   help="cvc5 git checkout containing the binary's revision")
    p.add_argument("--cvc5-rev",
                   help="revision for the CPC signature (default: read from "
                        "cvc5 --version)")
    p.add_argument("--out", default=str(DEFAULT_WORK / "corpus"))
    p.add_argument("--levels", default="regress0,regress1",
                   help="comma-separated regression levels")
    p.add_argument("--limit", type=int, default=400)
    p.add_argument("--min-bytes", type=int, default=0,
                   help="keep only proofs at least this large, e.g. 1000000 "
                        "for a corpus of large proofs (default 0)")
    p.add_argument("--timeout", type=float, default=30.0,
                   help="seconds per cvc5 run (default 30)")
    p.add_argument("--jobs", "-j", type=int, default=os.cpu_count() or 1)
    p.set_defaults(func=cmd_gen_proofs)

    import fuzz  # differential fuzzing: fuzz.py, next to this file
    fuzz.add_parsers(sub, sys.modules[__name__])

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
