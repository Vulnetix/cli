# Benchmarks

Wall-clock benchmarks of the `vulnetix` CLI subcommands run against **this repo**
as a realistic, CVE-dense Go target.

## Run

```bash
just benchmark
```

or directly:

```bash
./benchmark/run.sh
```

By default it benchmarks the `vulnetix` on your `PATH` (i.e. the `brew install`ed
release). Override with environment variables:

| Var | Default | Purpose |
|-----|---------|---------|
| `VULNETIX_BIN` | `vulnetix` (PATH) | Benchmark a different binary, e.g. `VULNETIX_BIN=./bin/vulnetix just benchmark` |
| `RUNS` | `3` | Timed iterations per scenario (run 1 is the cold run) |
| `BENCH_TIMEOUT` | `900` | Per-run timeout in seconds |
| `GOPROXY` | inherited | Autofix runs the package manager (`go mod tidy`); set `GOPROXY=https://proxy.golang.org,direct` to isolate CLI time from a slow/cooldown-prone proxy |

Examples:

```bash
RUNS=5 just benchmark
VULNETIX_BIN=./bin/vulnetix RUNS=3 just benchmark
GOPROXY=https://proxy.golang.org,direct just benchmark
```

## Scenarios

Run in order; each iteration runs on a **fresh copy** of the repo (autofix
mutates `go.mod`, so every run starts clean):

1. **sca** — `vulnetix sca` (Software Composition Analysis only)
2. **sast** — `vulnetix sast` (Static Application Security Testing only)
3. **sca + autofix:safest** — `vulnetix sca --sca-autofix --sca-autofix-strategy safest --yes`
4. **scan** — `vulnetix scan` (full local scan)
5. **scan + autofix:safest** — `vulnetix scan --sca-autofix --sca-autofix-strategy safest --yes`

`safest` is the conservative autofix target strategy (vs `latest` / `stable`).

## Output

A timestamped Markdown report and per-run logs are written to
`benchmark/results/` (git-ignored). The report records, per scenario, the
**min / median / max** wall-clock time across `RUNS`, the finding count, and the
exit code.

Reported times are end-to-end for the whole subcommand and therefore include the
cold start, the VDB API round-trip, and — for the autofix scenarios — the
package-manager resolve (which depends on `GOPROXY`). The first run of each
scenario is cold (uncached); subsequent runs are warm.

## SCA fixture timings and result parity

`benchmark/sca-fixtures.sh` times `vulnetix sca` across every project in the
[SCA manifest fixtures](https://github.com/Vulnetix/sca-manifest-fixtures)
(checked out at `../Vulnetix-extra/sca-manifest-fixtures`, or set
`VULNETIX_SCA_FIXTURES`). Use it to check that a faster build still finds the
same things:

```bash
./benchmark/sca-fixtures.sh ./old-vulnetix before      # every fixture
./benchmark/sca-fixtures.sh ./bin/vulnetix after npm-lock go-mod   # or a few
./benchmark/sca-fixtures.sh --compare before after
```

Each fixture is scanned from a fresh copy with no `.vulnetix` directory. For each
run, `benchmark/results/sca/<label>/` gets `timings.tsv` (wall ms, exit code,
component and vulnerability counts, HTTP request count), each fixture's
CycloneDX output, its stderr with the `VULNETIX_HTTP_TRACE=1` request timeline,
and a `.fp` fingerprint. The fingerprint is the sorted list of component purls,
plus each vulnerability with its affected refs, ratings and `vulnetix:*`
properties. `--compare` diffs the fingerprints and prints per-fixture and total
timings.

Vulnerability data changes while you work: an advisory can be withdrawn or
re-imported between two runs. When comparing builds, run them back to back, and
check any difference against the same baseline build run twice before blaming
the change.
