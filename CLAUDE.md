# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# Testing and Quality Requirements

Always run all tests and all linters after making changes. Ensure 100% pass rate before considering any task complete.

Test command:

- `just ci`

All tests and lints must pass without exception.

# Project Overview

Git Prompt Watcher is a **zsh plugin** (oh-my-zsh compatible) that provides real-time git status monitoring for shell prompts. The project uses **Rust for comprehensive testing infrastructure** while the core plugin is implemented in **zsh**.

Key characteristics:

- Core functionality: `git-prompt-watcher.plugin.zsh` (162 lines)
- Test suite: `tests/git_prompt_watcher_tests.rs` (1,439 lines, 27 tests)
- Uses `fswatch` for file system monitoring and POSIX signals (`SIGUSR1`, `SIGUSR2`) for shell communication
- Production-quality security testing including command injection prevention

# Development Commands

## Primary Workflow

```bash
just ci              # Full CI pipeline (lint + check + test-verbose)
just test-main       # Run main Rust test suite only
just test-one <name> # Run specific test by name
just fix             # Auto-fix formatting and clippy issues
```

## Testing Commands

```bash
just test            # Basic test run
just test-verbose    # Tests with full output (single-threaded)
just test-simple     # Run only simple_test suite
```

## Code Quality

```bash
just lint            # Aggressive linting with clippy
just lint-aggressive # Even more strict linting (may be too restrictive)
just fmt             # Format code
just check           # Check code compilation
```

## Build and Clean

```bash
just build           # Debug build
just build-release   # Release build
just clean           # Clean all artifacts (Rust + legacy Python)
```

# Architecture and Code Structure

## Core Plugin Logic (`git-prompt-watcher.plugin.zsh`)

- **Watcher lifecycle**: `_gpw_start_watcher()`, `_gpw_stop_watcher()`, `_gpw_restart_watcher()`
- **Signal handling**: `SIGUSR1` for prompt updates, `SIGUSR2` for watcher restarts
- **Git detection**: Monitors `.git/index`, `.git/HEAD`, `.git/refs`, working directory
- **Gitignore integration**: Respects ignore patterns, restarts watcher when `.gitignore` changes
- **Process management**: Clean job control with `disown` and proper cleanup

## Test Infrastructure (`tests/git_prompt_watcher_tests.rs`)

Uses modern Rust testing with these key dependencies:

- **expectrl**: Shell interaction testing (Rust pexpect equivalent)
- **git2**: Git repository manipulation
- **sysinfo**: Process monitoring and management
- **nix**: POSIX signal handling
- **tempfile**: Isolated test environments

## Test Categories

1. **Plugin lifecycle**: Loading, fswatch management, process cleanup
2. **File monitoring**: Change detection, gitignore respect, watcher restarts
3. **Git operations**: Staging, commits, branch switches, repository changes
4. **Security**: Command injection prevention, malicious gitignore handling
5. **Signal delivery**: Prompt update mechanisms, signal handling safety

# Security Considerations

The codebase includes extensive security testing:

- Command injection prevention in gitignore pattern processing
- Safe signal handling to prevent shell interference
- Malicious input validation (particularly in gitignore files)
- Process isolation and cleanup to prevent resource leaks

When modifying the plugin, always test security scenarios with malicious input patterns.

# Dependencies and External Tools

## Runtime Dependencies

- **fswatch**: File system monitoring (install via `brew install fswatch`)
- **zsh/oh-my-zsh**: Shell framework
- **git**: Version control system
- **Starship** (optional): Modern shell prompt

## Development Dependencies (Rust)

All managed via Cargo:

- Testing: `expectrl`, `assert_cmd`, `serial_test`, `tempfile`
- Git operations: `git2`
- System interaction: `sysinfo`, `nix`, `tokio`
- Utilities: `anyhow`, `regex`, `log`, `env_logger`

# Important Notes

- Tests are **serialized** (`serial_test`) due to shared shell state and signal handling
- The project has **no main Rust application code** - only comprehensive test infrastructure
- Plugin is designed for **oh-my-zsh compatibility** but may work with other zsh frameworks
- File system monitoring focuses on **git metadata** and **working directory changes** while respecting gitignore
- All prompt updates are **signal-driven** to avoid polling and minimize system impact
