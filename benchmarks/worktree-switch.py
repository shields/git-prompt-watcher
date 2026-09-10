#!/usr/bin/env python3
# Copyright 2026 Michael Shields. Licensed under the Apache License, Version 2.0.
"""Measure synchronous worktree cd overhead using only Python's standard library."""

import argparse
import collections
import datetime
import hashlib
import json
import math
import os
import platform
import shutil
import signal
import statistics
import subprocess
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent


def run(argv, *, cwd=None, env=None):
    return subprocess.run(
        argv, cwd=cwd, env=env, check=True, text=True, capture_output=True
    ).stdout.strip()


def summary(values):
    ordered = sorted(values)
    return {
        "n": len(values),
        "median_ms": statistics.median(values) * 1000,
        "p95_ms": ordered[math.ceil(len(values) * 0.95) - 1] * 1000,
        "max_ms": max(values) * 1000,
    }


def fixture(base, ignored_files, env):
    """Two linked worktrees, with ignored dependency trees in each."""
    repo = base / "main"
    repo.mkdir(parents=True)
    run(["git", "init", "-q", str(repo)], env=env)
    (repo / ".gitignore").write_text("dependencies/\n")
    (repo / "src").mkdir()
    (repo / "src" / "tracked.txt").write_text("benchmark\n")
    run(["git", "add", "."], cwd=repo, env=env)
    run(
        [
            "git",
            "-c",
            "user.name=Benchmark",
            "-c",
            "user.email=bench@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "benchmark fixture",
        ],
        cwd=repo,
        env=env,
    )
    trees = (base / "worktree-a", base / "worktree-b")
    for tree in trees:
        run(["git", "worktree", "add", "-q", "--detach", str(tree)], cwd=repo, env=env)
        for i in range(ignored_files):
            # Many small package directories resemble dependency installations.
            package = tree / "dependencies" / f"package-{i // 10:06d}"
            if i % 10 == 0:
                package.mkdir(parents=True)
                # Real dependency trees often contain nested .gitignore files.
                (package / ".gitignore").write_text("cache/\n")
            (package / f"file-{i % 10}.txt").touch()
    return trees


def measure(plugin, mode, trees, iterations, warmup, env, temp, timeout):
    trace = temp / "trace.tsv"
    trace.write_text("")
    # Regular output files prevent a leaked background writer from keeping
    # communicate() blocked. A dedicated process group bounds failure cleanup.
    with (
        tempfile.TemporaryFile(mode="w+") as stdout,
        tempfile.TemporaryFile(mode="w+") as stderr,
    ):
        child = subprocess.Popen(
            [
                "zsh",
                "-f",
                str(HERE / "worktree-switch.zsh"),
                str(plugin),
                mode,
                *map(str, trees),
                str(iterations),
                str(warmup),
                str(trace),
            ],
            cwd=temp,
            env=env,
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
        )
        try:
            child.wait(timeout=timeout)
        finally:
            # This group contains only the benchmark shell and its descendants.
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
        stdout.seek(0)
        stderr.seek(0)
        if child.returncode:
            raise RuntimeError(f"{mode} failed ({child.returncode}): {stderr.read()}")
        samples = []
        for line in stdout:
            index, elapsed = line.split()
            index = int(index)
            samples.append(
                {
                    "index": index,
                    "destination": str(trees[1] if index % 2 else trees[0]),
                    "seconds": float(elapsed),
                }
            )
    if len(samples) != iterations * 2:
        raise RuntimeError(
            f"{mode}: expected {iterations * 2} samples, got {len(samples)}"
        )
    if mode == "same-worktree":
        for sample in samples:
            sample["destination"] = str(trees[0])
    result = {
        "mode": mode,
        "samples": samples,
        **summary([s["seconds"] for s in samples]),
    }
    result["by_destination"] = {
        destination: summary(
            [s["seconds"] for s in samples if s["destination"] == destination]
        )
        for destination in dict.fromkeys(s["destination"] for s in samples)
    }
    if mode == "profile":
        # Sum repeated commands within a switch, then summarize per-switch cost.
        totals = collections.defaultdict(lambda: collections.defaultdict(float))
        for line in trace.read_text().splitlines():
            index, label, elapsed = line.split("\t")
            totals[label][int(index)] += float(elapsed)
        result["components"] = {
            label: summary(list(values.values())) for label, values in totals.items()
        }
        result["trace"] = trace.read_text()
    return result


def nonnegative(value):
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be nonnegative")
    return parsed


def positive(value):
    parsed = nonnegative(value)
    if parsed == 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--worktrees",
        nargs=2,
        type=Path,
        metavar=("A", "B"),
        help="benchmark existing worktrees without modifying their files or Git metadata",
    )
    parser.add_argument(
        "--ignored-files",
        nargs="+",
        type=nonnegative,
        default=[0, 1000, 10000],
        help="synthetic dependency file counts per worktree (default: 0 1000 10000)",
    )
    parser.add_argument(
        "--iterations", type=positive, default=10, help="measured round trips per mode"
    )
    parser.add_argument(
        "--warmup", type=nonnegative, default=2, help="unrecorded round trips per mode"
    )
    parser.add_argument(
        "--timeout", type=positive, default=300, help="maximum seconds per mode"
    )
    parser.add_argument(
        "--profile", action="store_true", help="add a separate instrumented run"
    )
    parser.add_argument(
        "--without-find",
        action="store_true",
        help="add a diagnostic control bypassing find in older plugin versions",
    )
    parser.add_argument(
        "--plugin", type=Path, default=HERE.parent / "git-prompt-watcher.plugin.zsh"
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="save metadata, summaries and individual samples as JSON",
    )
    args = parser.parse_args()
    for tool in ("zsh", "fswatch", "git"):
        if not shutil.which(tool):
            parser.error(f"required executable not found: {tool}")
    plugin = args.plugin.resolve(strict=True)
    env = os.environ.copy()
    # Repository discovery should follow cd, even when called from a Git tool.
    for key in list(env):
        if key.startswith("GIT_"):
            env.pop(key)
    env["GIT_OPTIONAL_LOCKS"] = "0"
    report = {
        "date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "platform": platform.platform(),
        "plugin": str(plugin),
        "plugin_sha256": hashlib.sha256(plugin.read_bytes()).hexdigest(),
        "zsh": run(["zsh", "--version"]),
        "git": run(["git", "--version"]),
        "fswatch": run(["fswatch", "--version"]).splitlines()[0],
        "iterations": args.iterations,
        "warmup": args.warmup,
        "scenarios": [],
    }
    print(f"{report['platform']}; {report['zsh']}; {report['fswatch']}", flush=True)
    print(
        "Milliseconds per cd (shell startup and prompt rendering excluded).", flush=True
    )
    with tempfile.TemporaryDirectory(prefix="gpw-bench-") as directory:
        temp = Path(directory).resolve()
        # Keep every watcher-created temporary file inside the fixture lifetime.
        env["TMPDIR"] = str(temp)
        if args.worktrees:
            trees = tuple(p.resolve(strict=True) for p in args.worktrees)
            git_dirs = [
                run(["git", "rev-parse", "--absolute-git-dir"], cwd=p, env=env)
                for p in trees
            ]
            common_dirs = [
                run(
                    ["git", "rev-parse", "--path-format=absolute", "--git-common-dir"],
                    cwd=p,
                    env=env,
                )
                for p in trees
            ]
            if git_dirs[0] == git_dirs[1] or common_dirs[0] != common_dirs[1]:
                parser.error(
                    "--worktrees requires two different worktrees of the same repository"
                )
            cases = [("existing worktrees", trees)]
        else:
            # Synthetic runs should not depend on user hooks, ignores or signing.
            env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
            env["GIT_CONFIG_COUNT"] = "2"
            env["GIT_CONFIG_KEY_0"] = "core.hooksPath"
            env["GIT_CONFIG_VALUE_0"] = os.devnull
            env["GIT_CONFIG_KEY_1"] = "init.templateDir"
            env["GIT_CONFIG_VALUE_1"] = ""
            cases = [
                (f"{count} ignored files/tree", count) for count in args.ignored_files
            ]
        for case_index, (label, spec) in enumerate(cases):
            print(f"\n{label}", flush=True)
            trees = (
                spec
                if args.worktrees
                else fixture(temp / f"case-{case_index}", spec, env)
            )
            scenario = {
                "name": label,
                "worktrees": list(map(str, trees)),
                "results": [],
            }
            report["scenarios"].append(scenario)
            modes = ["off", "on", "same-worktree"]
            if args.without_find:
                modes.insert(2, "without-find")
            if args.profile:
                modes.append("profile")
            for mode in modes:
                result = measure(
                    plugin,
                    mode,
                    trees,
                    args.iterations,
                    args.warmup,
                    env,
                    temp,
                    args.timeout,
                )
                scenario["results"].append(result)
                print(
                    f"  {mode:16s} median {result['median_ms']:9.3f}"
                    f"  p95 {result['p95_ms']:9.3f}  max {result['max_ms']:9.3f}",
                    flush=True,
                )
                if args.worktrees and mode != "same-worktree":
                    for destination, stats in result["by_destination"].items():
                        print(
                            f"    -> {destination}: median {stats['median_ms']:.3f} ms",
                            flush=True,
                        )
                for component, stats in result.get("components", {}).items():
                    print(
                        f"    {component:16s} median {stats['median_ms']:9.3f}",
                        flush=True,
                    )
                if args.output:
                    args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
