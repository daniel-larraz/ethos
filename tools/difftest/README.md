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
The JSON report (`--report`) has every case with both normalized outputs,
exit codes, times and peak memory. Each stream is cut to its first 1,000
lines and each line to 2,000 characters, with the full line count in
`stderr_lines` or `stdout_lines`; some runs print gigabytes. Comparisons
always use the whole output.

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
  corpus made by `gen-proofs`, named `<corpus directory>/<file>`, for example
  `corpus/regress0__uf__cnf_abc.cpc`. Today: 400 cases, plus 43 in the corpus
  of large proofs.

## Option variants

By default every case runs once, with Ethos's default options.
`--all-option-sets` also runs every case with each option set to its
non-default value, one at a time, and once with all eight together:

`--no-parse-let`, `--no-print-dag`, `--no-rule-sym-table`,
`--no-normalize-dec`, `--no-normalize-hex`, `--normalize-num`,
`--require-proof-of-false`, `--reference-define-fun`

That is ten runs per case. `--options '<opts>'` (repeatable) adds a set of
your own. `--cand-options '<opts>'` (repeatable) gives options to the
candidate only, before every case's arguments, for options Ethos does not
have; the reference runs as usual. A variant's name ends in ` [<options>]`, for example
`tests/simple.eo [--no-print-dag]`, which `--filter` can match.

`--stats-option-sets` adds four more runs per case: `--stats`,
`--stats-all`, `--stats-compact`, and the last two together. Their output
contains timings, so the statistics after the verdict are compared with
every number masked except how many times each rule and program was used;
the counters of Ethos's term store (`mkExprCount`, `deleteExprCount`, ...)
are masked too, as they depend on how terms are stored. Rows are sorted by
name, since Ethos orders them by time. Running Ethos against a copy of
itself on the regressions and the corpus gives no difference.

## Command-line cases

`--cli` adds 38 hand-written invocations (`CLI_CASES` in `difftest.py`),
named `cli/<name>`, run in `cli/` on the small files there: `--help` in
various positions, `-t` and `-v` (an error in a release build), unknown
options, two files, missing files and directories, input on standard
input, `--include=` (missing, empty, twice, after the file, together with
an `include` command) and `--reference=` (before its signature, twice,
missing, and from standard input, the one case where reference checking
stays on). They do not run under the option sets. `--show-config` is left
out: it prints the checker's own name and version.

## Large-number cases

`--bignum` adds 7 cases, `bignum/<op>.eo`, generated by `bignum.py` into
`work/bignum` (a fixed seed; several megabytes, so not committed): `eo::add`,
`neg`, `gt`, `is_neg`, `mul`, `pow`, `zdiv`, `zmod`, `qdiv`, `to_z`, `to_q`,
`to_bin`, `len` and the bit-vector operations, on operands of 64 bits to one
million bits, below, at and above the size where a big-number library
changes algorithm (malachite's FFT multiplication starts at 24,960 bits).
Each term is defined with `:is_eq` and its value computed by Python, so a
wrong value stops the file with the value the checker computed; the last
define of each file is wrong on purpose, so both checkers print one large
value in full and the harness compares it. Nothing else reaches these
sizes: the regressions, the proofs and the fuzzer use small numbers. They do
not run under the option sets.

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

## A corpus of large proofs

The default corpus comes from `regress0` and `regress1`, where most proofs are
small: the largest takes Ethos about a second. For performance, and for
behaviour that only shows on large inputs, build a second corpus of large
proofs and pass both with `--corpus`:

```sh
./difftest.py gen-proofs --cvc5 /path/to/cvc5 --cvc5-src /path/to/cvc5-checkout \
    --out work/corpus-large --levels regress1,regress2,regress3,regress4 \
    --min-bytes 1000000 --limit 60 --timeout 300
```

`--min-bytes` keeps only proofs of at least that many bytes. Generating it
runs cvc5 on every unsat benchmark of those levels and takes a long time.

## Differential fuzzing

`fuzz` (in `fuzz.py`) runs both checkers on mutated inputs and keeps every
mutant on which they differ, compared as `run` compares them:

```sh
./difftest.py fuzz --ref <ethos> --cand <candidate> --tests ../../tests \
    --corpus work/corpus --time 600 --seed 1
```

- **Seeds:** every top-level file of `tests/` and the 20 smallest proofs of
  the corpus (`--corpus-seeds`). Mutants are written into a copy of `tests/`,
  or next to the corpus's CPC signature, so their includes resolve.
- **Mutations** work on tokens and balanced subexpressions: delete, duplicate,
  swap or replace tokens and subexpressions (from all seeds), edge-case
  literals (32- and 64-bit limits, empty and malformed literals, escapes,
  non-ASCII and non-UTF-8 bytes), unbalanced parentheses, stray bytes,
  truncation, and splicing two seeds. A share of mutants (`--option-rate`,
  15%) runs under a non-default option set; `--no-print-dag` is left out
  because it can make one error message gigabytes long.
- **Findings:** any difference, a timeout on one side only (`--timeout`, 10 s),
  a crash or panic of the candidate, or a crash of Ethos other than its
  normal abort. Ethos crashes are Ethos bugs: they are reported, but not
  counted as failures. Findings are grouped by a signature (category and
  first error line, with numbers and paths masked); the first example of each
  group is minimized by removing subexpressions and tokens while the
  signature stays the same.
- **Output:** `<work>/findings/<id>/` holds `input.<ext>` (minimized),
  `original.<ext>` and `info.json` (seed, options, both normalized outputs);
  `<work>/summary.json` lists the groups with their counts. `fuzz` exits 1 if
  there is a finding other than an Ethos crash.
- **Reproducibility:** `--seed` fixes the mutants; with `--iterations` instead
  of `--time` and the same `--jobs`, a run is repeated exactly.

`fuzz-replay --findings <dir>` reruns saved findings in the same kind of
directory and reports which still differ, for example after a fix. It exits 1
if any does.

Some differences are kept on purpose: where Ethos has undefined behaviour
(it reads past the end of a vector, as in cvc5/ethos#257), its output is
whatever memory held, and the candidate should stop with an error instead.
`fuzz-accept <id>... --cand <candidate> --reason <text> --findings <dir>`
records such findings in `<dir>/accepted.json`, with the reason and the
candidate's current output (the input's path shown as `<input>`). Replay
then does not run Ethos on them; it passes them when the candidate's output
is exactly the recorded one, and fails otherwise, so a change to it is
noticed.

Findings worth keeping are copied into `fuzz-findings/<date>-seed<N>/`, which
is under version control, so that they serve as regression tests. Paths in
their `info.json` are shortened to `<ctx>/`; `SUMMARY.json` has the counts.
`fuzz-findings/2026-11-14-seed1/` holds the first run against pathos: 888,900
mutants in 10 minutes, 99.95% agreeing, 40 groups of differences and one
Ethos crash.
Four of the groups were accepted differences: `eo::` operators evaluated
without an argument they read, where Ethos read past the end of its
argument vector and the candidate stopped with an error. cvc5/ethos#272
(Ethos `c7d3db90`) fixed that: Ethos now checks the arity first, as the
candidate does, so against that revision those findings agree and are no
longer accepted (two of them now run out of time in both).

## The Eunoia compiler (eoc)

`eoc` (in `eoc.py`) compares `ethos-eoc`, Ethos built with its compiler
plugins (`plugins/`), with a candidate. `build-ref <rev> --eoc` also builds
the reference's `ethos-eoc` in `work/ref/<rev>/build-eoc/`.

```sh
./difftest.py eoc --ref work/ref/<rev>/build-eoc/ethos-eoc \
    --cand /path/to/candidate-eoc --src work/ref/<rev>/src
```

- **Cases:** eoc's driver, `tools/eoc/driver.py` of the reference source,
  run on every file of `tests/` that declares a rule and on
  `tools/eoc/test/nary-nil.eo`, under the test semantics
  `tools/eoc/test/semantics.eos`: `desugar` and `desugar --natives=eo` on
  each signature, and `vc`, `vc --sygus`, `lean` and `trim-defs` on each rule
  (1,052 cases, about 110 s). Named `eoc/<signature>/<run>[/<rule>]`.
  `--signature` (repeatable) compiles other signatures instead.
- **Runs:** each case runs once per binary, in a fresh copy of the reference
  source (without `tools/eoc/out/`), with the binary as the build
  directory's `ethos-eoc` and `ETHOS_PLUGIN_ROOT` and
  `ETHOS_PLUGIN_OUTPUT_DIR` pointing into that copy. The driver is called
  with `--no-build` and `--skip-cvc5`.
- **Compared:** the outcome (`ok`, `error`, `timeout`), the driver's stdout
  and stderr (without the C++ `Fatal failure within` line), and every file
  of the source tree and the build directory after the run, byte for byte,
  including the stage files under `tools/eoc/out/` and the plugins' files
  under `<build>/out/plugins/`. The run's directory is written `<root>`.
- **Checks of the harness:** `ethos-eoc` against a copy of itself agrees on
  all 1,052 cases (872 ok, 180 errors, such as `no model semantics found for
  String`). A wrapper that appends a line to `model_smt_gen.eo` after each
  stage, and one that writes an extra file, are both reported.
- **CPC, as logos compiles it:** `--logos <checkout of
  https://github.com/cvc5/logos>` adds the cases of logos's flattened CPC
  signature, `install/defs/Cpc.cached.eo`, under logos's semantics
  (`install/defs/Cpc.eos`, `smt.eos`): `lean --all`, which is what logos's
  `install/install-cpc.sh` runs, `desugar` and `desugar --natives=eo`, and
  `vc`, `vc --sygus`, `lean` and `trim-defs` on each of its 610 rules (2,455
  cases, about 5 minutes on 16 cores). Named `eoc/logos/<run>[/<rule>]`;
  `--no-tests` leaves out the test signatures. At logos a3232131 and the
  reference 9217112f, `ethos-eoc` against a copy of itself agrees on all of
  them (2,450 ok; 5 errors for `beta-reduce` and `trust`, which logos's
  semantics leave out), and the 13 signature-wide modules `lean --all` writes
  are byte-identical to logos's checked-in `Cpc/` package, apart from the
  header its install script adds. Logos pins Ethos at d99865cd, and
  `tools/eoc` and `plugins` are unchanged from there to 9217112f.
- **Not covered:** `batch`, and the cvc5 parse checks of the generated
  SMT-LIB.

`eoc-keep <case> --binary <bin> --src <src> --out <dir>` runs one case with
one binary and keeps its directory, to look at what it wrote.

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

3. **Option variants, reference against itself:** 6,300 runs (630 cases with
   ten option sets each), 0 differences. One run takes Ethos 179 s, because
   `--no-print-dag` makes it print 1.77 GB of error output; option runs need a
   timeout well above the default 120 s.

4. **Fuzzer, reference against itself:** 93,924 mutants in one minute, no
   differences. The only finding was an Ethos crash: a segmentation fault on
   `eo::requires` applied to one argument inside a rule's `:requires`.

To repeat test 2, copy `work/ref/<rev>/src`, change one line, build it with
`cmake -S . -B ../build -DCMAKE_BUILD_TYPE=Release`, and run it as `--cand`.
