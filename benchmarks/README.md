# Worktree switching benchmark

Run from the project root with Python 3, Zsh, Git, and fswatch on `PATH`:

```sh
just bench
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
arguments with the current plugin. Keep the output JSON outside version control.

Profile timings are separate from the uninstrumented `on` measurements.
`start` includes `stop` and most Git commands; the components are nested and
must not be added together. Commands with the same label are summed within
each switch before calculating their median.

These are warm-filesystem measurements of the plugin's synchronous overhead.
They exclude prompt rendering, user shell configuration, other plugins, and
worktree creation or checkout. The modes run sequentially in the listed order;
run again to check variability and avoid concurrent builds or tests while
benchmarking. This is a diagnostic benchmark without timing pass/fail thresholds.
