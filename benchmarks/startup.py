#!/usr/bin/env python3
# Copyright 2026 Michael Shields. Licensed under the Apache License, Version 2.0.
"""Measure the synchronous cost of sourcing the plugin at shell startup."""

import argparse
import collections
import contextlib
import dataclasses
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
from typing import Any

HERE = Path(__file__).resolve().parent

# Several levels below a repository root, so repository detection has to walk.
NESTED = Path("src/nested/deeper/deepest")


@dataclasses.dataclass(frozen=True, kw_only=True)
class Scenario:
    name: str
    start: Path
    expect_watcher: bool
    env: dict[str, str]


def run(
    argv: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None
) -> str:
    return subprocess.run(
        argv, cwd=cwd, env=env, check=True, text=True, capture_output=True
    ).stdout.strip()


def is_repository(directory: Path, env: dict[str, str]) -> bool:
    probe = subprocess.run(
        ["git", "rev-parse", "--git-dir"],
        cwd=directory,
        env=env,
        check=False,
        capture_output=True,
    )
    return probe.returncode == 0


def summary(values: list[float]) -> dict[str, float]:
    ordered = sorted(values)
    return {
        "n": len(values),
        "median_ms": statistics.median(values) * 1000,
        "p95_ms": ordered[math.ceil(len(values) * 0.95) - 1] * 1000,
        "max_ms": max(values) * 1000,
    }


def fixture(base: Path, ignored_files: int, env: dict[str, str]) -> tuple[Path, Path]:
    """A repository with an ignored dependency tree, plus a linked worktree of it."""
    repo = base / "repo"
    repo.mkdir(parents=True)
    run(["git", "init", "-q", str(repo)], env=env)
    (repo / ".gitignore").write_text("dependencies/\n")
    (repo / NESTED).mkdir(parents=True)
    (repo / NESTED / "tracked.txt").write_text("benchmark\n")
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
    worktree = base / "worktree"
    run(["git", "worktree", "add", "-q", "--detach", str(worktree)], cwd=repo, env=env)
    for i in range(ignored_files):
        # Many small package directories resemble dependency installations.
        package = repo / "dependencies" / f"package-{i // 10:06d}"
        if i % 10 == 0:
            package.mkdir(parents=True)
            # Real dependency trees often contain nested .gitignore files.
            (package / ".gitignore").write_text("cache/\n")
        (package / f"file-{i % 10}.txt").touch()
    return repo, worktree


def sample(
    plugin: Path, mode: str, scenario: Scenario, temp: Path, timeout: int
) -> tuple[float, dict[str, dict[str, float]]]:
    """Source the plugin once in a fresh shell; return its cost and components."""
    trace = temp / "trace.tsv"
    trace.write_text("")
    # Regular output files prevent a leaked background writer from keeping the
    # parent blocked. A dedicated process group bounds failure cleanup.
    with (
        tempfile.TemporaryFile(mode="w+") as stdout,
        tempfile.TemporaryFile(mode="w+") as stderr,
    ):
        child = subprocess.Popen(
            [
                "zsh",
                "-f",
                str(HERE / "startup.zsh"),
                str(plugin),
                mode,
                str(scenario.start),
                str(int(scenario.expect_watcher)),
                str(trace),
            ],
            cwd=temp,
            env=scenario.env,
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
        )
        try:
            child.wait(timeout=timeout)
        finally:
            # This group contains only the benchmark shell and its descendants.
            with contextlib.suppress(ProcessLookupError):
                os.killpg(child.pid, signal.SIGKILL)
            child.wait()
        stdout.seek(0)
        stderr.seek(0)
        if child.returncode:
            message = f"{mode} failed ({child.returncode}): {stderr.read()}"
            raise RuntimeError(message)
        lines = stdout.read().split()
    if len(lines) != 1:
        message = f"{mode}: expected one sample, got {lines!r}"
        raise RuntimeError(message)
    components: dict[str, dict[str, float]] = collections.defaultdict(
        lambda: {"calls": 0, "seconds": 0.0}
    )
    for line in trace.read_text().splitlines():
        label, seconds = line.split("\t")
        components[label]["calls"] += 1
        components[label]["seconds"] += float(seconds)
    return float(lines[0]), dict(components)


def measure(
    plugin: Path,
    mode: str,
    scenario: Scenario,
    *,
    iterations: int,
    warmup: int,
    temp: Path,
    timeout: int,
) -> dict[str, Any]:
    samples: list[dict[str, Any]] = []
    for index in range(1, warmup + iterations + 1):
        seconds, components = sample(plugin, mode, scenario, temp, timeout)
        if index > warmup:
            samples.append(
                {"index": index - warmup, "seconds": seconds, "components": components}
            )
    result: dict[str, Any] = {
        "mode": mode,
        "samples": samples,
        **summary([s["seconds"] for s in samples]),
    }
    if mode == "profile":
        # Repeated commands are summed within a shell, so each label's summary
        # is that command's cost per startup; calls is its count per startup.
        labels = dict.fromkeys(label for s in samples for label in s["components"])
        result["components"] = {
            label: {
                "calls": statistics.median(
                    s["components"].get(label, {"calls": 0})["calls"] for s in samples
                ),
                **summary(
                    [
                        s["components"].get(label, {"seconds": 0.0})["seconds"]
                        for s in samples
                    ]
                ),
            }
            for label in labels
        }
    return result


def nonnegative(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        message = "must be nonnegative"
        raise argparse.ArgumentTypeError(message)
    return parsed


def positive(value: str) -> int:
    parsed = nonnegative(value)
    if parsed == 0:
        message = "must be positive"
        raise argparse.ArgumentTypeError(message)
    return parsed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repos",
        nargs="+",
        type=Path,
        metavar="DIR",
        help="start inside existing repositories without modifying their files"
        " or Git metadata",
    )
    parser.add_argument(
        "--ignored-files",
        nargs="+",
        type=nonnegative,
        default=[0, 1000, 10000],
        help="synthetic dependency file counts per repository (default: 0 1000 10000)",
    )
    parser.add_argument(
        "--iterations",
        type=positive,
        default=30,
        help="measured shells per scenario and mode",
    )
    parser.add_argument(
        "--warmup",
        type=nonnegative,
        default=3,
        help="unrecorded shells per scenario and mode",
    )
    parser.add_argument(
        "--timeout", type=positive, default=30, help="maximum seconds per shell"
    )
    parser.add_argument(
        "--profile", action="store_true", help="add a separate instrumented run"
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
    # Repository discovery should depend on the start directory alone, even
    # when the benchmark is launched from a Git tool.
    for key in list(env):
        if key.startswith("GIT_"):
            env.pop(key)
    env["GIT_OPTIONAL_LOCKS"] = "0"
    report: dict[str, Any] = {
        "date": datetime.datetime.now(datetime.UTC).isoformat(),
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
        "Milliseconds to source the plugin in a fresh zsh"
        " (shell startup and exit excluded).",
        flush=True,
    )
    with tempfile.TemporaryDirectory(prefix="gpw-bench-") as directory:
        temp = Path(directory).resolve()
        # Keep watcher-created temporary files inside the fixture lifetime where
        # mktemp honors TMPDIR.
        env["TMPDIR"] = str(temp)
        outside = temp / "outside"
        outside.mkdir()
        if is_repository(outside, env):
            parser.error(f"{temp} is inside a Git repository; set TMPDIR elsewhere")
        scenarios = [
            Scenario(
                name="outside any repository",
                start=outside,
                expect_watcher=False,
                env=env,
            )
        ]
        if args.repos:
            repos: list[Path] = []
            for repo in args.repos:
                try:
                    resolved = repo.resolve(strict=True)
                except FileNotFoundError:
                    parser.error(f"not a directory: {repo}")
                if not is_repository(resolved, env):
                    parser.error(f"not a Git repository: {repo}")
                repos.append(resolved)
            git_dir = run(
                ["git", "rev-parse", "--absolute-git-dir"], cwd=repos[0], env=env
            )
            root_scenarios = [
                Scenario(name=str(repo), start=repo, expect_watcher=True, env=env)
                for repo in repos
            ]
        else:
            # Synthetic runs should not depend on user hooks, ignores or signing.
            env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
            env["GIT_CONFIG_COUNT"] = "2"
            env["GIT_CONFIG_KEY_0"] = "core.hooksPath"
            env["GIT_CONFIG_VALUE_0"] = os.devnull
            env["GIT_CONFIG_KEY_1"] = "init.templateDir"
            env["GIT_CONFIG_VALUE_1"] = ""
            counts = list(dict.fromkeys(args.ignored_files))
            fixtures = {
                count: fixture(temp / f"ignored-{count}", count, env)
                for count in counts
            }
            smallest = min(counts)
            repo, worktree = fixtures[smallest]
            git_dir = str(repo / ".git")
            root_scenarios = [
                Scenario(
                    name=f"{count} ignored files",
                    start=fixtures[count][0],
                    expect_watcher=True,
                    env=env,
                )
                for count in counts
            ]
            # Starts that repository detection must handle without seeing a
            # .git directory at the start directory itself.
            root_scenarios += [
                Scenario(
                    name=f"{smallest} ignored files, nested subdirectory",
                    start=repo / NESTED,
                    expect_watcher=True,
                    env=env,
                ),
                Scenario(
                    name=f"{smallest} ignored files, linked worktree",
                    start=worktree,
                    expect_watcher=True,
                    env=env,
                ),
            ]
        # GIT_DIR makes Git find a repository from a directory with no .git
        # above it, so this start must cost a repository start, not an outside one.
        scenarios.append(
            Scenario(
                name="outside, GIT_DIR set",
                start=outside,
                expect_watcher=True,
                env=env | {"GIT_DIR": git_dir},
            )
        )
        scenarios += root_scenarios
        for scenario in scenarios:
            print(f"\n{scenario.name}", flush=True)
            record: dict[str, Any] = {
                "name": scenario.name,
                "directory": str(scenario.start),
                "expect_watcher": scenario.expect_watcher,
                "env": {k: v for k, v in scenario.env.items() if k.startswith("GIT_")},
                "results": [],
            }
            report["scenarios"].append(record)
            modes = ["on"]
            if args.profile:
                modes.append("profile")
            for mode in modes:
                result = measure(
                    plugin,
                    mode,
                    scenario,
                    iterations=args.iterations,
                    warmup=args.warmup,
                    temp=temp,
                    timeout=args.timeout,
                )
                record["results"].append(result)
                print(
                    f"  {mode:16s} median {result['median_ms']:9.3f}"
                    f"  p95 {result['p95_ms']:9.3f}  max {result['max_ms']:9.3f}",
                    flush=True,
                )
                for component, stats in result.get("components", {}).items():
                    print(
                        f"    {component:16s} median {stats['median_ms']:9.3f}"
                        f"  calls {stats['calls']:g}",
                        flush=True,
                    )
                if args.output:
                    args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
