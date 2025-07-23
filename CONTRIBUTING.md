# Contributing to Git Prompt Watcher

Contributions are welcome! This document provides details on the development and testing environment to help you get started.

## Development Workflow

The project uses `just` as a command runner. Here are the primary commands:

- `just ci`: Run all tests with aggressive linting (recommended before submitting a PR).
- `just test-main`: Run the main Rust test suite.
- `just fmt`: Format the codebase.
- `just lint`: Run the linter.

## Testing

The project includes a comprehensive test suite that validates the `zsh` plugin's functionality in a real shell environment.

### Rust Test Suite

The main test suite is implemented in **Rust** using the `cargo test` framework. It provides a robust and reliable way to test the shell script's behavior.

- **20 comprehensive tests** - All tests passing (100% success rate).
- **Real shell interaction** using `expectrl` (a Rust equivalent of `pexpect`).
- **Git operations** with the `git2` crate for repository management.
- **Process management** using the `sysinfo` crate for `fswatch` monitoring.
- **Signal handling** with the `nix` crate for `SIGUSR1`/`SIGUSR2` delivery.
- **Security testing**, including malicious `.gitignore` pattern validation.
- **Starship integration** with custom configuration for prompt testing.
- **Isolated environments** with temporary directories and automatic cleanup.

**Key test categories:**

- Plugin loading and `fswatch` lifecycle management.
- File change detection and monitoring.
- Git operations (staging, commits, branch switches, `.gitignore` changes).
- Repository navigation and watcher persistence.
- Shell job management and process cleanup.
- Signal delivery and prompt update mechanisms.
- Security resilience against command injection attacks.

To run the Rust tests:

```bash
just test-main
```

### Docker CI

The project includes a fully reproducible Docker CI setup to ensure consistency.

- **Base image**: Python 3.13-slim with a pinned SHA256 digest.
- **Reproducible builds**: Uses Debian snapshot archives with specific timestamps.
- **Pinned dependencies**: All system packages and tools are locked to exact versions.
- **Complete toolchain**: Includes Rust, cargo, `just`, `starship`, and all testing dependencies.

To run the full CI suite inside Docker:

```bash
just docker-ci
```
