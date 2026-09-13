# Benchmarks

Run from the project root with Python 3, Zsh, Git, and fswatch on `PATH`;
`just bench` runs both benchmarks with default settings. Both are
warm-filesystem measurements of the plugin's synchronous overhead in a fresh
`zsh -f`, timed with Zsh's `EPOCHREALTIME`; they exclude prompt rendering, user
shell configuration, and other plugins. They are diagnostic benchmarks without
timing pass/fail thresholds: run again to check variability, avoid concurrent
builds or tests while benchmarking, and keep output JSON outside version
control. The driver sets `TMPDIR` to the fixture directory, which keeps the
watcher's temporary files inside the fixture lifetime on systems where
`mktemp -t` honors it; on macOS, `mktemp -t` uses the per-user temporary
directory regardless of `TMPDIR`, and the plugin's own exit hook cleans up there.

## Worktree switching

```sh
just bench-worktree
python3 benchmarks/worktree-switch.py --ignored-files 0 1000 10000 50000 --profile --output /tmp/gpw-synthetic.json
python3 benchmarks/worktree-switch.py --worktrees /path/to/main /path/to/linked-worktree --profile --output /tmp/gpw-existing.json
```

The default creates two temporary linked worktrees for each of three sizes:
0, 1,000, and 10,000 ignored dependency files per worktree. Each package has ten
files and one additional `.gitignore`. Existing worktrees are read without
changing their files or Git metadata; their normal Git configuration applies.
Synthetic fixtures use isolated Git configuration. Fixtures, watcher processes,
and watcher temporary files are cleaned up after each run.

Each mode runs in a fresh `zsh -f`, changes to the first worktree, and then
alternates between the two destinations. The default is two warmup round trips
and ten measured round trips (20 individual `cd` samples). Timing uses Zsh's
`EPOCHREALTIME` around `builtin cd`, including synchronous `chpwd` hooks. Shell
startup, plugin sourcing, validation, and final cleanup are outside the timer.
The benchmark checks that the watcher has a live PID after each change and
restarts only when expected.

| Mode | What it measures |
| --- | --- |
| `off` | Plain `cd` without the plugin. |
| `on` | Worktree switches with the unmodified plugin and real fswatch processes. |
| `without-find` | Optional historical control enabled by `--without-find`: bypasses the recursive scan in older plugin versions. This omits nested ignore watches in those versions; it has no effect on versions using Git-aware discovery. |
| `same-worktree` | Repeated `cd` to the first directory with the plugin loaded, exercising repository detection without a restart. |
| `profile` | Optional separate instrumented run, measuring startup, shutdown, `find`, and Git command groups. |

The report shows the median, nearest-rank p95, and maximum in milliseconds per
`cd`. Existing-worktree runs also show medians by destination, since entering a
main checkout containing other worktrees can cost more than entering a linked
worktree. `--output` saves environment metadata, the plugin SHA-256, all samples,
destination summaries, and optional profiling traces as JSON. It writes after
each mode so completed measurements survive a later timeout. Use `--plugin` to
compare another plugin file, and `--iterations`, `--warmup`, or `--timeout` to
adjust the run.

For a before/after comparison, save the original plugin outside the source tree
and run once with `--plugin /path/to/original.plugin.zsh`, then run the same
arguments with the current plugin.

Profile timings are separate from the uninstrumented `on` measurements.
`start` includes `stop` and most Git commands; the components are nested and
must not be added together. Commands with the same label are summed within
each switch before calculating their median.

The measurements exclude worktree creation or checkout. The modes run
sequentially in the listed order.

## Shell startup

```sh
just bench-startup
python3 benchmarks/startup.py --ignored-files 0 10000 --profile --output /tmp/gpw-startup.json
python3 benchmarks/startup.py --repos /path/to/repo /path/to/another --profile
```

This measures what the plugin adds to shell startup: the repository check that
runs when the plugin is sourced and, inside a repository, the synchronous watcher
start. Every sample is a fresh `zsh -f` that changes to the start directory,
sources the plugin once, and exits. The timer wraps only `source`; shell startup,
validation, and exit cleanup are outside it. The first two scenarios start in an
empty temporary directory outside any repository, once plainly and once with
`GIT_DIR` pointing at a repository, which makes Git find that repository even
though no `.git` exists above the start directory. The default synthetic
scenarios then start in the root of a repository with 0, 1,000, or 10,000
ignored dependency files laid out like the worktree fixtures, with isolated Git
configuration; for the smallest size they also start four directories below the
root and in a linked worktree, whose `.git` is a file rather than a directory.
`--repos` starts in existing repositories instead, without changing their files
or Git metadata; their normal Git configuration applies, and `GIT_DIR` points at
the first of them. After each sample the benchmark checks that a watcher is
running whenever a repository applies and that none was started otherwise, so a
detection regression fails the run rather than looking fast. The default is 3
warmup and 30 measured shells per scenario.

| Mode | What it measures |
| --- | --- |
| `on` | Sourcing the unmodified plugin, with a real fswatch start inside repositories. |
| `profile` | Optional separate instrumented run reporting the cost and call count per startup of each external command the plugin forks: `git-<subcommand>`, `mktemp`, `mkfifo`, and `sed`. |

The report shows the median, nearest-rank p95, and maximum in milliseconds per
startup. Profile components are measured inside an instrumented shell and are
not comparable to the uninstrumented `on` total. fswatch is not wrapped, because
a wrapper started in the background would replace the PID the plugin records,
and the plugin's own functions cannot be wrapped because they first run while the
plugin is being sourced; the gap between the total and the components is mostly
forking fswatch and its reader. Commands that run inside a pipeline overlap
with each other, so components must not be added together. Use `--plugin` to
compare another plugin file, and `--iterations`, `--warmup`, or `--timeout` to
adjust the run. `--output` saves environment metadata, the plugin SHA-256, all
samples with their components, and the summaries as JSON, written after each mode.
