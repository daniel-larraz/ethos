# difftest: differential testing for Ethos

`difftest.py` runs a reference Ethos binary and a candidate binary on the same
inputs and reports every input on which they behave differently. It exists to
check a reimplementation of Ethos against the C++ checker: the candidate
matches the reference when `difftest.py run` reports no differences.

It needs Python 3.12 or later and nothing outside the standard library, plus
GNU `time` for accurate memory figures (see "Performance").
Everything it builds or generates goes under `work/`, which git ignores.

## Quick start

```sh
cd tools/difftest

# 1. Build the reference checker from a pinned revision.
./difftest.py build-ref origin/main
#    -> work/ref/<rev>/build/src/ethos

# 2. Generate a corpus of cvc5 proofs (see "The proof corpus" below).
./difftest.py gen-proofs --cvc5 /path/to/cvc5 --cvc5-src /path/to/cvc5-checkout

# 3. Compare.
./difftest.py run --ref work/ref/<rev>/build/src/ethos --cand /path/to/candidate \
    --tests ../../tests --corpus work/corpus --report work/report.json
```

`run` exits with status 0 when every case agrees and 1 otherwise. It prints
the first 20 differences as unified diffs (`--show N`, `--show-all`), then a
summary. `--filter REGEX` restricts the cases by name, for example
`--filter 'tests/.*list'`.

## What is compared

Each case runs once per binary with the same arguments and working directory.
The output is reduced to three parts, which must all be equal:

| Part | Rule |
| --- | --- |
| Outcome | `correct`, `incomplete`, `success-other` (exit 0 without a verdict line), `error` (any non-zero exit or signal) or `timeout`. The exact exit code and signal are **not** compared. |
| stderr | Compared byte for byte, line by line (lines end at `\n` only), after removing trailing spaces, tabs and `\r`, and leading and trailing blank lines. The C++ line `Fatal failure within <function> at <file>:<line>` is dropped first: it names C++ source code. |
| stdout | Compared the same way, **except when the outcome is `error`**. The C++ checker aborts on errors, so its buffered stdout is lost at that point. |

What this means for a reimplementation:

- Error messages must match the C++ exactly, including the
  `Error: <file>:<line>.<col>: ` prefix and any following lines. Some of
  Ethos's own regressions match them with regular expressions.
- A distinct exit code for each kind of failure is allowed, and so is not
  dumping core.
- A panic or crash is an `error` outcome whose message differs from the
  reference, so it is reported.

Bytes are compared exactly, including bytes that are not valid UTF-8, and
non-ASCII whitespace such as U+00A0 is never trimmed: Ethos works on bytes, so
a reimplementation that handles text differently must show up. In printed
diffs, such bytes and characters appear as `\xNN` or `\uNNNN`.

The logic is in `normalize()` in `difftest.py`. Change it there, and only
deliberately: it defines what "the same" means.

## Inputs

- **Regressions** (`--tests`): every top-level `.eo` and `.smt2` file in
  Ethos's `tests/` directory. Each is run the way `tests/CMakeLists.txt` runs
  it: by absolute path, from the repository root, with no options. Files that
  other tests include and the `.smt2` reference files are run on their own
  too; the checkers must agree on those as well. `tests/smtlib/` holds cvc5
  inputs and is skipped. Today: 230 cases.
- **cvc5 proofs** (`--corpus`, repeatable): the `proofs/*.cpc` files of a
  corpus made by `gen-proofs`. Today: 400 cases.

Options other than the defaults are not exercised yet.

## The proof corpus

`gen-proofs` copies what cvc5's own CPC tester does
(`test/regress/cli/run_regression.py` in cvc5, class `CpcTester`):

- It takes the CPC signature (`proofs/eo/cpc`) and the regression benchmarks
  (`test/regress/cli`) from the cvc5 checkout **at the revision the cvc5
  binary was built from**, whatever is checked out there. The revision comes
  from `cvc5 --version`, or from `--cvc5-rev`.
- It considers the benchmarks in `regress0` and `regress1` (`--levels`) whose
  expected result is `unsat`. It skips those that disable the `proof` or
  `cpc` tester and those with `REQUIRES:` lines.
- It runs `cvc5 --dump-proofs --proof-print-conclusion <first COMMAND-LINE
  args> <benchmark>` from the benchmark's directory, strips the `unsat` line
  and the outer parentheses, and prepends includes of `Cpc.eo` and
  `expert/CpcExpert.eo`.
- It takes benchmarks round-robin across directories, so that `--limit N`
  spans the theories rather than taking the first directory in full.
- It writes `MANIFEST.json`, which records the cvc5 version, the revision and
  the benchmark behind each proof.

Two things to watch out for:

- **Proof files must not end in `.eo`.** Ethos treats `*.eo` files as
  signatures (`src/main.cpp`), and in a signature `let` is not built in, so
  many cvc5 proofs fail to parse. The corpus uses `.cpc`.
- **A cvc5 built from a source tree inside another git repository reports
  that repository's commit** in `--version`. Pass `--cvc5-rev` in that case.
  `gen-proofs` stops if the revision is not in the cvc5 checkout.

Current corpus: cvc5 `2107a00359cb` (main, 2026-11-13). 400 proofs from 52
regression directories in 29 top-level areas (bv, sets, strings, quantifiers,
arith, nl and others): 394 `correct` and 6 `incomplete` (proofs with trusted
steps). The largest proof is 3.4 MB.

## Reference cache

`run` caches the reference's results in `work/ref-cache.json`, so repeated runs
execute only the candidate. A cache entry is keyed on:

- the reference binary's SHA-256;
- the case's arguments and working directory;
- the main input's SHA-256;
- the size and modification time of every file under the case's root
  (`tests/` or the corpus);
- the timeout;
- how time and memory are measured.

Use `--no-cache` to rerun the reference anyway.

## Performance

`run` also reports total time and the largest peak memory, over the cases
where both checkers succeeded the same way.

Wall time is exact: `run` blocks until the process exits, and a timer kills
it on timeout. Each run includes a constant 7 to 8 ms for starting the
process, the same for both binaries, so ratios for very short runs lean
towards 100%. Earlier versions polled with growing sleeps instead, which
rounded times up to 32, 64, 114 ms and so on; the pathos gate-5 session found
this.

Peak memory is measured through GNU `time` (`time -f %M`), which reads the
peak of the process it starts. Without GNU `time`, `run` falls back to `wait4`
and says so: that figure is at least the size of the harness's Python process
(about 30 MiB), because each binary starts as a copy of that process and Linux
keeps a process's peak across `exec`. Found by the pathos milestone-1 session:
it reported 31 MiB for a run that `/usr/bin/time` measured at 3 MiB. Those figures are only useful
with `--jobs 1 --no-cache`. With parallel jobs, or with cached reference
timings from another run, the comparison is noise: in one test, a candidate
that differed only in one arithmetic line showed as 214% slower.

## How the harness was checked

Two self-tests, on 2026-11-13, against reference `9217112f`:

1. **Reference against itself:** 630 cases, 0 differences.
2. **Reference against a mutant** in which `eo::add` on numerals adds each
   argument twice (`src/literal.cpp`). A probe build of the reference
   recorded every case where that line runs with a non-zero argument, which
   is where the mutation can change a result:
   - the mutation fired on 206 cases;
   - `run` flagged 189 of them, and nothing else, so there were no false
     alarms;
   - in the other 17 the changed value did not reach the output. That is
     expected for values computed inside branches whose result is discarded,
     but those 17 were not inspected one by one.

   The mutant test ran on an earlier corpus, made with cvc5 `1fb1038`.

To repeat test 2, copy `work/ref/<rev>/src`, change one line, build it with
`cmake -S . -B ../build -DCMAKE_BUILD_TYPE=Release`, and run it as `--cand`.
