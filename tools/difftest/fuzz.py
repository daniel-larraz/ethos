"""Differential fuzzing for Ethos: the `fuzz` and `fuzz-replay` subcommands of
difftest.py.

`fuzz` mutates real inputs (Ethos's regressions and small cvc5 proofs), runs
the reference and the candidate on each mutant, and keeps every mutant on
which they behave differently, compared exactly as `difftest.py run` compares
(see normalize() in difftest.py). Findings are grouped by a signature so that
one bug is reported once; the first example of each group is minimized.
`fuzz-replay` reruns saved findings, to see which are fixed.

Everything depends on --seed, so a run can be repeated exactly (given the same
binaries and the same number of iterations per worker).
"""

import dataclasses
import hashlib
import json
import random
import re
import shutil
import threading
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------
#
# Inputs are handled as Latin-1 text, so every byte round-trips.

TOKEN_RE = re.compile(
    r"""
      (?P<ws>[ \t\r\n]+)
    | (?P<comment>;[^\n]*)
    | (?P<lpar>\()
    | (?P<rpar>\))
    | (?P<string>"(?:[^"]|"")*"?)
    | (?P<quoted>\|[^|]*\|?)
    | (?P<atom>[^ \t\r\n()";|]+)
    | (?P<other>.)
    """,
    re.VERBOSE | re.DOTALL,
)


@dataclasses.dataclass
class Token:
    kind: str
    text: str


def tokenize(text):
    return [Token(m.lastgroup, m.group()) for m in TOKEN_RE.finditer(text)]


def untokenize(tokens):
    return "".join(t.text for t in tokens)


def significant(tokens):
    return [i for i, t in enumerate(tokens) if t.kind not in ("ws", "comment")]


def subexpressions(tokens):
    """(start, end) token index ranges of balanced parenthesized terms."""
    out, stack = [], []
    for i, t in enumerate(tokens):
        if t.kind == "lpar":
            stack.append(i)
        elif t.kind == "rpar" and stack:
            out.append((stack.pop(), i + 1))
    return out


# Literals and symbols chosen to hit edge cases: limits of 32- and 64-bit
# integers, empty and malformed literals, escapes, non-ASCII and non-UTF-8
# bytes, and Eunoia keywords.
INTERESTING_ATOMS = [
    "0", "1", "-1", "2", "31", "32", "63", "64",
    "4294967295", "4294967296", "18446744073709551615", "18446744073709551616",
    "99999999999999999999999999999999",
    "0.0", "1.5", "-0.5", "1/2", "0/1", "1/0", "-1/3", "00", "01", "1.",
    "#b", "#b0", "#b1", "#x", "#x0", "#xF", "#xffffffff", "#xG",
    "_", "!", "->", "Type", "Bool", "true", "false",
    "eo::?", "eo::add", "eo::nil", "eo::cons", "eo::list_concat", "eo::requires",
    "eo::ite", "eo::eq", "eo::is_eq", "eo::len", "eo::extract", "eo::to_z",
    ":var", ":implicit", ":requires", ":right-assoc-nil", ":left-assoc-nil",
    ":chainable", ":pairwise", ":binder", ":list", ":type", ":opaque",
    ":premises", ":args", ":conclusion", ":rule",
    "let", "lambda", "@list", "@", "caf\xe9", "\xff", "\x00", "a\x85b",
]
INTERESTING_STRINGS = [
    '""', '"a"', '""""', '"\\u{0}"', '"\\u{2FFFF}"', '"\\u{30000}"', '"\\u{"',
    '"\\u{zz}"', '"\\ud800"', '"\xe9\xff"', '"\\"', '"' + "a" * 300 + '"',
]
INTERESTING_BYTES = ["(", ")", '"', "|", ";", "\\", ":", "#", "\x00", "\x80",
                     "\xa0", "\xff", "\n"]


class Mutator:
    """Mutations of token lists, using a dictionary built from the seeds."""

    def __init__(self, seed_tokens):
        atoms, subs = set(), []
        for tokens in seed_tokens:
            for t in tokens:
                if t.kind in ("atom", "quoted", "string"):
                    atoms.add(t.text)
            for a, b in subexpressions(tokens):
                if b - a <= 40:
                    subs.append(tokens[a:b])
        self.atoms = sorted(atoms) + INTERESTING_ATOMS
        self.subexprs = subs
        self.ops = [
            self.delete_token, self.duplicate_token, self.swap_tokens,
            self.replace_atom, self.interesting_atom, self.interesting_string,
            self.delete_subexpr, self.duplicate_subexpr, self.replace_subexpr,
            self.wrap_subexpr, self.unbalance, self.truncate, self.insert_byte,
        ]

    def mutate(self, rng, tokens, other):
        tokens = list(tokens)
        if rng.random() < 0.1 and other:
            return self.splice(rng, tokens, other)
        for _ in range(rng.choice([1, 1, 1, 2, 2, 3])):
            tokens = rng.choice(self.ops)(rng, tokens) or tokens
        return tokens

    @staticmethod
    def _pick(rng, tokens, kinds=None):
        idx = [i for i, t in enumerate(tokens)
               if t.kind not in ("ws", "comment") and (kinds is None or t.kind in kinds)]
        return rng.choice(idx) if idx else None

    def delete_token(self, rng, tokens):
        i = self._pick(rng, tokens)
        if i is not None:
            del tokens[i]
        return tokens

    def duplicate_token(self, rng, tokens):
        i = self._pick(rng, tokens)
        if i is not None:
            tokens[i:i] = [tokens[i], Token("ws", " ")]
        return tokens

    def swap_tokens(self, rng, tokens):
        i, j = self._pick(rng, tokens, ("atom",)), self._pick(rng, tokens, ("atom",))
        if i is not None and j is not None:
            tokens[i], tokens[j] = tokens[j], tokens[i]
        return tokens

    def replace_atom(self, rng, tokens):
        i = self._pick(rng, tokens, ("atom", "quoted"))
        if i is not None:
            tokens[i] = Token("atom", rng.choice(self.atoms))
        return tokens

    def interesting_atom(self, rng, tokens):
        i = self._pick(rng, tokens, ("atom",))
        if i is not None:
            tokens[i] = Token("atom", rng.choice(INTERESTING_ATOMS))
        return tokens

    def interesting_string(self, rng, tokens):
        i = self._pick(rng, tokens, ("atom", "string"))
        if i is not None:
            tokens[i] = Token("string", rng.choice(INTERESTING_STRINGS))
        return tokens

    def delete_subexpr(self, rng, tokens):
        subs = subexpressions(tokens)
        if subs:
            a, b = rng.choice(subs)
            del tokens[a:b]
        return tokens

    def duplicate_subexpr(self, rng, tokens):
        subs = subexpressions(tokens)
        if subs:
            a, b = rng.choice(subs)
            tokens[b:b] = [Token("ws", " ")] + tokens[a:b]
        return tokens

    def replace_subexpr(self, rng, tokens):
        subs = subexpressions(tokens)
        if subs and self.subexprs:
            a, b = rng.choice(subs)
            tokens[a:b] = list(rng.choice(self.subexprs))
        return tokens

    def wrap_subexpr(self, rng, tokens):
        subs = subexpressions(tokens)
        if subs:
            a, b = rng.choice(subs)
            head = rng.choice(["", "_ ", "eo::nil ", "eo::requires ", "! ", "eo::ite "])
            tokens[a:b] = [Token("lpar", "("), Token("atom", head)] + tokens[a:b] + [Token("rpar", ")")]
        return tokens

    def unbalance(self, rng, tokens):
        i = self._pick(rng, tokens, ("lpar", "rpar"))
        if i is not None:
            if rng.random() < 0.5:
                del tokens[i]
            else:
                tokens.insert(i, Token(tokens[i].kind, tokens[i].text))
        return tokens

    def truncate(self, rng, tokens):
        if tokens:
            del tokens[rng.randrange(len(tokens)):]
        return tokens

    def insert_byte(self, rng, tokens):
        i = rng.randrange(len(tokens) + 1)
        tokens.insert(i, Token("other", rng.choice(INTERESTING_BYTES)))
        return tokens

    def splice(self, rng, tokens, other):
        i, j = rng.randrange(len(tokens) + 1), rng.randrange(len(other) + 1)
        return tokens[:i] + other[j:]


# ---------------------------------------------------------------------------
# Seeds and the directories mutants run in
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class Seed:
    name: str      # e.g. tests/simple.eo
    context: str   # "tests" or "corpus"
    suffix: str    # ".eo", ".smt2" or ".cpc": Ethos treats .eo as a signature
    tokens: list


def load_seeds(tests_dir, corpus_dir, n_proofs):
    seeds = []
    if tests_dir:
        for p in sorted(Path(tests_dir).iterdir()):
            if p.is_file() and p.suffix in (".eo", ".smt2"):
                seeds.append(Seed(f"tests/{p.name}", "tests", p.suffix,
                                  tokenize(p.read_bytes().decode("latin-1"))))
    if corpus_dir and n_proofs:
        proofs = sorted((Path(corpus_dir) / "proofs").glob("*.cpc"),
                        key=lambda p: p.stat().st_size)[:n_proofs]
        for p in proofs:
            seeds.append(Seed(f"{Path(corpus_dir).name}/{p.name}", "corpus", ".cpc",
                              tokenize(p.read_bytes().decode("latin-1"))))
    return seeds


def make_contexts(root, tests_dir, corpus_dir):
    """Directories where mutants run, so that their includes resolve as in
    the originals: a copy of tests/, and a corpus with the CPC signature."""
    root = Path(root)
    if root.exists():
        shutil.rmtree(root)
    ctx = {}
    if tests_dir:
        shutil.copytree(tests_dir, root / "tests")
        ctx["tests"] = (root / "tests", root)            # (file dir, cwd)
    if corpus_dir:
        (root / "corpus" / "proofs").mkdir(parents=True)
        (root / "corpus" / "cpc").symlink_to(Path(corpus_dir).resolve() / "cpc")
        ctx["corpus"] = (root / "corpus" / "proofs", root / "corpus")
    return ctx


# ---------------------------------------------------------------------------
# Classifying a pair of runs
# ---------------------------------------------------------------------------

CRASH_CODES = {
    132: "SIGILL", 135: "SIGBUS", 136: "SIGFPE", 137: "SIGKILL", 139: "SIGSEGV",
    -4: "SIGILL", -7: "SIGBUS", -8: "SIGFPE", -9: "SIGKILL", -11: "SIGSEGV",
    # Windows: NTSTATUS exception codes as exit statuses. An abort, Ethos's
    # ordinary way to stop on an error, is not among them: it is exit status
    # 3 with the MSVCRT runtime (MINGW64) and 0xC0000409, a fast fail, with
    # the UCRT one (CLANGARM64), which is why that code is left out.
    0xC0000005: "ACCESS_VIOLATION", 0xC00000FD: "STACK_OVERFLOW",
    0xC000001D: "ILLEGAL_INSTRUCTION", 0xC0000094: "INTEGER_DIVIDE_BY_ZERO",
}

_MASK_PATH = re.compile(r"/\S*?(\.eo|\.cpc|\.smt2)")
_MASK_NUM = re.compile(r"\d+")


def _mask(line):
    line = _MASK_PATH.sub("<file>", line)
    return _MASK_NUM.sub("0", line)[:100]


def _exhausted(run):
    """The run ran out of time or of memory (--memory): a mutant on which
    both binaries do counts as agreeing, whichever limit each one hit."""
    return run.timed_out or run.out_of_memory


def classify(dt, ref_run, cand_run):
    """Returns (category, signature) for a pair of runs, or None if they
    agree. The signature groups findings that are probably the same bug."""
    if _exhausted(ref_run) and _exhausted(cand_run):
        return None
    ref_n, cand_n = dt.normalize(ref_run), dt.normalize(cand_run)
    if ref_run.timed_out:
        category = "reference-timeout"
    elif cand_run.timed_out:
        category = "candidate-timeout"
    elif ref_run.out_of_memory:
        category = "reference-out-of-memory"
    elif cand_run.out_of_memory:
        category = "candidate-out-of-memory"
    elif ref_run.exit_code in CRASH_CODES:
        category = "reference-crash"   # an Ethos bug; not for the candidate to match
    elif cand_run.exit_code in CRASH_CODES or any("panicked at" in l for l in cand_n["stderr"]):
        category = "candidate-crash"
    else:
        diffs = dt.compare(ref_n, cand_n)
        if not diffs:
            return None
        category = "differ-" + "-".join(diffs)
    first = lambda n: _mask(n["stderr"][0]) if n["stderr"] else _mask(n["outcome"])
    if category == "reference-crash":
        key = f"{category}|{CRASH_CODES[ref_run.exit_code]}"
    elif category == "candidate-crash":
        panic = next((l for l in cand_n["stderr"] if "panicked at" in l), "")
        key = f"{category}|{_mask(panic)}"
    else:
        key = f"{category}|{first(ref_n)}|{first(cand_n)}"
    return category, key


# ---------------------------------------------------------------------------
# Fuzzing
# ---------------------------------------------------------------------------


class Fuzzer:
    def __init__(self, dt, args, seeds, ctx, out):
        self.dt, self.args, self.seeds, self.ctx, self.out = dt, args, seeds, ctx, out
        self.mutator = Mutator([s.tokens for s in seeds])
        self.lock = threading.Lock()
        self.findings = {}           # signature -> info
        self.runs = self.agree = self.both_timeout = 0
        # --no-print-dag is left out: it can make a single error message
        # gigabytes long (see the harness README, test 3).
        self.option_sets = [o for o in dt.ETHOS_OPTION_SETS
                            if "--no-print-dag" not in o]

    def run_pair(self, path, cwd, options):
        a = [*options, str(path)]
        ref = self.dt.run_binary(self.args.ref, a, str(cwd), self.args.timeout,
                                 memory_mb=getattr(self.args, "memory", None))
        cand = self.dt.run_binary(self.args.cand, a, str(cwd), self.args.timeout,
                                  memory_mb=getattr(self.args, "memory", None))
        return ref, cand

    def worker(self, wid, deadline, iterations):
        rng = random.Random(f"{self.args.seed}/{wid}")
        i = 0
        while time.monotonic() < deadline and (iterations is None or i < iterations):
            i += 1
            seed = rng.choice(self.seeds)
            other = rng.choice(self.seeds).tokens if rng.random() < 0.5 else None
            tokens = self.mutator.mutate(rng, seed.tokens, other)
            options = rng.choice(self.option_sets) if rng.random() < self.args.option_rate else []
            fdir, cwd = self.ctx[seed.context]
            path = fdir / f"fuzz-w{wid}{seed.suffix}"
            path.write_bytes(untokenize(tokens).encode("latin-1"))
            ref, cand = self.run_pair(path, cwd, options)
            result = classify(self.dt, ref, cand)
            with self.lock:
                self.runs += 1
                if result is None:
                    if _exhausted(ref) and _exhausted(cand):
                        self.both_timeout += 1
                    else:
                        self.agree += 1
                    continue
                category, key = result
                info = self.findings.get(key)
                if info is None:
                    info = {"signature": key, "category": category, "count": 0,
                            "seed": seed.name, "context": seed.context,
                            "suffix": seed.suffix, "options": options,
                            "iteration": f"worker {wid}, iteration {i}"}
                    self.findings[key] = info
                    new = True
                else:
                    new = False
                info["count"] += 1
            if new:
                self.save(info, tokens, path, cwd, ref, cand)

    def save(self, info, tokens, path, cwd, ref, cand):
        sid = hashlib.sha256(info["signature"].encode()).hexdigest()[:12]
        d = self.out / sid
        d.mkdir(parents=True, exist_ok=True)
        (d / f"original{info['suffix']}").write_bytes(untokenize(tokens).encode("latin-1"))
        if self.args.minimize:
            tokens = self.minimize(info, tokens, path, cwd)
        (d / f"input{info['suffix']}").write_bytes(untokenize(tokens).encode("latin-1"))
        # rerun the minimized input for the record
        path.write_bytes(untokenize(tokens).encode("latin-1"))
        ref, cand = self.run_pair(path, cwd, info["options"])
        info["id"] = sid
        info["reference"] = {**self.dt.normalize(ref), "exit_code": ref.exit_code}
        info["candidate"] = {**self.dt.normalize(cand), "exit_code": cand.exit_code}
        (d / "info.json").write_text(json.dumps(info, indent=1))

    def minimize(self, info, tokens, path, cwd):
        """Removes tokens and subexpressions while the pair of runs keeps the
        same signature (delta debugging, within a budget of runs)."""
        budget = [self.args.minimize_runs]

        def keeps(cand_tokens):
            if budget[0] <= 0:
                return False
            budget[0] -= 1
            path.write_bytes(untokenize(cand_tokens).encode("latin-1"))
            ref, cand = self.run_pair(path, cwd, info["options"])
            r = classify(self.dt, ref, cand)
            return r is not None and r[1] == info["signature"]

        changed = True
        while changed and budget[0] > 0:
            changed = False
            # whole subexpressions, largest first
            for a, b in sorted(subexpressions(tokens), key=lambda r: r[0] - r[1]):
                if b <= len(tokens) and keeps(tokens[:a] + tokens[b:]):
                    tokens = tokens[:a] + tokens[b:]
                    changed = True
                    break
            if changed:
                continue
            # chunks of tokens, halving the chunk size
            n = len(tokens) // 2
            while n >= 1 and not changed:
                for start in range(0, len(tokens), n):
                    trial = tokens[:start] + tokens[start + n:]
                    if trial and keeps(trial):
                        tokens, changed = trial, True
                        break
                n //= 2
        return tokens


def cmd_fuzz(dt, args):
    args.ref = Path(args.ref).resolve()
    args.cand = Path(args.cand).resolve()
    work = Path(args.work).resolve()
    out = work / "findings"
    out.mkdir(parents=True, exist_ok=True)
    seeds = load_seeds(args.tests, args.corpus, args.corpus_seeds)
    if not seeds:
        raise SystemExit("error: no seeds (give --tests and/or --corpus)")
    ctx = make_contexts(work / "ctx", args.tests, args.corpus)
    fz = Fuzzer(dt, args, seeds, ctx, out)

    # Ethos aborts on errors; never leave core files behind.
    dt.disable_core_dumps()

    deadline = time.monotonic() + args.time
    per_worker = None if args.iterations is None else -(-args.iterations // args.jobs)
    threads = [threading.Thread(target=fz.worker, args=(w, deadline, per_worker))
               for w in range(args.jobs)]
    for t in threads:
        t.start()
    started = time.monotonic()
    while any(t.is_alive() for t in threads):
        time.sleep(1)
        if not args.quiet:
            print(f"\r{fz.runs} runs, {len(fz.findings)} findings, "
                  f"{time.monotonic() - started:.0f} s", end="", flush=True)
    if not args.quiet:
        print()
    for t in threads:
        t.join()

    summary = sorted(fz.findings.values(), key=lambda f: (f["category"], -f["count"]))
    (work / "summary.json").write_text(json.dumps({
        "seed": args.seed, "runs": fz.runs, "agree": fz.agree,
        "both_timed_out": fz.both_timeout,
        "reference": str(args.ref), "candidate": str(args.cand),
        "findings": [{k: f.get(k) for k in ("id", "category", "count", "seed", "options", "signature")}
                     for f in summary],
    }, indent=1))
    print(f"{fz.runs} runs: {fz.agree} agree, {fz.both_timeout} run out of time or memory on both, "
          f"{sum(f['count'] for f in summary)} differ, in {len(summary)} groups")
    for f in summary:
        print(f"  {f.get('id', '?'):12}  {f['category']:28} x{f['count']:<5} "
              f"{dt.printable(f['signature'].split('|', 1)[-1])[:90]}")
    print(f"findings: {out}")
    real = [f for f in summary if f["category"] != "reference-crash"]
    return 1 if real else 0


ACCEPTED_FILE = "accepted.json"


def _load_accepted(findings):
    f = findings / ACCEPTED_FILE
    return json.loads(f.read_text()) if f.exists() else {}


def _run_finding(dt, args, ctx, d, info, which):
    """Runs a saved finding in a fresh copy of its context. Returns the
    runs of the binaries named in `which` and the input's path."""
    fdir, cwd = ctx[info["context"]]
    path = fdir / f"fuzz-w0{info['suffix']}"
    shutil.copyfile(d / f"input{info['suffix']}", path)
    a = [*info["options"], str(path)]
    runs = [dt.run_binary(Path(b).resolve(), a, str(cwd), args.timeout) for b in which]
    return runs, path


def _expected_form(dt, run, path):
    """The normalized output of a run with the input's path as <input>, as
    stored in accepted.json."""
    n = dt.normalize(run)
    sub = lambda lines: [l.replace(str(path), "<input>") for l in lines]
    return {"outcome": n["outcome"], "stdout": sub(n["stdout"]), "stderr": sub(n["stderr"])}


def _prepare_replay(dt, args):
    findings = Path(args.findings).resolve()
    ctx = make_contexts(Path(args.work).resolve() / "replay-ctx", args.tests, args.corpus)
    dt.disable_core_dumps()
    return findings, ctx


def cmd_fuzz_replay(dt, args):
    """Reruns saved findings in the same kind of directory they came from.

    A finding listed in the directory's accepted.json is a difference the
    candidate keeps on purpose (typically: Ethos has undefined behaviour and
    the candidate reports an error). It passes when the candidate's output
    is exactly the one recorded there, whatever Ethos does."""
    findings, ctx = _prepare_replay(dt, args)
    accepted = _load_accepted(findings)
    still, fixed, crashes, skipped, ok_accepted = [], [], [], [], []
    for d in sorted(p for p in findings.iterdir() if (p / "info.json").exists()):
        info = json.loads((d / "info.json").read_text())
        if info["category"] == "reference-crash":
            crashes.append(d.name)
            continue
        if info["context"] not in ctx:
            skipped.append(d.name)  # needs --tests or --corpus, not given
            continue
        if d.name in accepted:
            (cand,), path = _run_finding(dt, args, ctx, d, info, [args.cand])
            got = _expected_form(dt, cand, path)
            want = accepted[d.name]["candidate"]
            if got == want:
                ok_accepted.append(d.name)
                continue
            still.append(d.name)
            if not args.quiet:
                print(dt.describe_diff(
                    f"{d.name} ({info['seed']}): accepted difference, but the "
                    f"candidate's output changed (- recorded, + now)",
                    want, got, dt.compare(want, got) or ["outcome"]))
            continue
        (ref, cand), _ = _run_finding(dt, args, ctx, d, info, [args.ref, args.cand])
        if classify(dt, ref, cand) is None:
            fixed.append(d.name)
        else:
            still.append(d.name)
            if not args.quiet:
                ref_n, cand_n = dt.normalize(ref), dt.normalize(cand)
                print(dt.describe_diff(f"{d.name} ({info['seed']})", ref_n, cand_n,
                                       dt.compare(ref_n, cand_n) or ["outcome"]))
    stale = sorted(set(accepted) - {d.name for d in findings.iterdir()})
    for name in stale:
        print(f"accepted.json names {name}, which is not a finding here")
    print(f"findings: {len(still)} still differ, {len(fixed)} fixed, "
          f"{len(ok_accepted)} accepted differences, "
          f"{len(crashes)} Ethos crashes (not compared)"
          + (f", {len(skipped)} skipped (need --tests or --corpus)" if skipped else ""))
    return 1 if still or stale else 0


def cmd_fuzz_accept(dt, args):
    """Records the candidate's current output on findings as accepted
    differences, with a reason, in the findings directory's accepted.json."""
    findings, ctx = _prepare_replay(dt, args)
    accepted = _load_accepted(findings)
    for fid in args.ids:
        d = findings / fid
        if not (d / "info.json").exists():
            raise SystemExit(f"no finding {fid} in {findings}")
        info = json.loads((d / "info.json").read_text())
        if info["category"] == "reference-crash":
            raise SystemExit(f"{fid} is an Ethos crash; replay never compares it")
        if info["context"] not in ctx:
            raise SystemExit(f"{fid} needs --{info['context']}")
        (cand,), path = _run_finding(dt, args, ctx, d, info, [args.cand])
        if cand.timed_out:
            raise SystemExit(f"{fid}: the candidate times out; that cannot be accepted")
        accepted[fid] = {"reason": args.reason,
                         "candidate": _expected_form(dt, cand, path)}
        print(f"{fid}: accepted ({_expected_form(dt, cand, path)['outcome']})")
    (findings / ACCEPTED_FILE).write_text(
        json.dumps(dict(sorted(accepted.items())), indent=1) + "\n")
    return 0


def add_parsers(sub, dt):
    import os
    p = sub.add_parser("fuzz", help="differential fuzzing (see fuzz.py)")
    p.add_argument("--ref", required=True)
    p.add_argument("--cand", required=True)
    p.add_argument("--tests", help="Ethos tests/ directory: seeds and their includes")
    p.add_argument("--corpus", help="proof corpus; its smallest proofs are seeds too")
    p.add_argument("--corpus-seeds", type=int, default=20,
                   help="how many of the smallest proofs to use (default 20)")
    p.add_argument("--time", type=float, default=600, help="seconds to fuzz (default 600)")
    p.add_argument("--iterations", type=int, help="stop after this many mutants")
    p.add_argument("--seed", default="0", help="random seed (default 0)")
    p.add_argument("--jobs", "-j", type=int, default=os.cpu_count() or 1)
    p.add_argument("--timeout", type=float, default=10, help="seconds per run (default 10)")
    p.add_argument("--memory", type=int, default=4096,
                   help="address-space limit per run, in MiB (default 4096; 0: none). "
                        "A runaway mutant then stops one run instead of the campaign"),
    p.add_argument("--option-rate", type=float, default=0.15,
                   help="share of mutants run under a non-default option set")
    p.add_argument("--no-minimize", dest="minimize", action="store_false")
    p.add_argument("--minimize-runs", type=int, default=300,
                   help="run budget for minimizing each finding (default 300)")
    p.add_argument("--work", default=str(dt.DEFAULT_WORK / "fuzz"),
                   help="working directory; findings go to <work>/findings")
    p.add_argument("--quiet", "-q", action="store_true")
    p.set_defaults(func=lambda a: cmd_fuzz(dt, a))

    p = sub.add_parser("fuzz-replay", help="rerun saved fuzzing findings")
    p.add_argument("--ref", required=True)
    p.add_argument("--cand", required=True)
    p.add_argument("--findings", required=True, help="a findings directory of `fuzz`")
    p.add_argument("--tests", help="Ethos tests/ directory (for findings from tests)")
    p.add_argument("--corpus", help="proof corpus (for findings from proofs)")
    p.add_argument("--timeout", type=float, default=10)
    p.add_argument("--work", default=str(dt.DEFAULT_WORK / "fuzz"))
    p.add_argument("--quiet", "-q", action="store_true")
    p.set_defaults(func=lambda a: cmd_fuzz_replay(dt, a))

    p = sub.add_parser("fuzz-accept",
                       help="record findings as accepted differences (see fuzz.py)")
    p.add_argument("ids", nargs="+", help="finding ids")
    p.add_argument("--cand", required=True)
    p.add_argument("--reason", required=True, help="why the difference is kept")
    p.add_argument("--findings", required=True, help="a findings directory")
    p.add_argument("--tests", help="Ethos tests/ directory (for findings from tests)")
    p.add_argument("--corpus", help="proof corpus (for findings from proofs)")
    p.add_argument("--timeout", type=float, default=10)
    p.add_argument("--work", default=str(dt.DEFAULT_WORK / "fuzz"))
    p.set_defaults(func=lambda a: cmd_fuzz_accept(dt, a))
