# Git Prompt Watcher

An oh-my-zsh plugin that automatically updates your prompt when git status changes, using fswatch to monitor repository files in real-time.

## Features

- **Real-time prompt updates** when git status changes (staging, commits, branch switches, new files)
- **Respects gitignore** - only watches files that git actually tracks or considers untracked
- **Efficient monitoring** - watches git metadata and working directory while excluding ignored files
- **Gitignore-aware** - automatically restarts when `.gitignore` files change
- **Repository detection** - only runs when inside git repositories
- **Clean job control** - doesn't clutter `jobs` output

## Requirements

- **fswatch** - File system monitoring utility
- **oh-my-zsh** - Zsh framework
- **Starship** or compatible prompt that responds to `zle reset-prompt`
- **macOS/Linux** - Uses POSIX signals for prompt updates

Install fswatch via Homebrew:

```bash
brew install fswatch
```

## Installation

### Manual Installation

1. Clone this repository to your oh-my-zsh custom plugins directory:

   ```bash
   git clone https://github.com/shields/git-prompt-watcher.git ~/.oh-my-zsh/custom/plugins/git-prompt-watcher
   ```

2. Add the plugin to your `.zshrc`:

   ```bash
   plugins=(... git-prompt-watcher)
   ```

3. Restart your shell or source your `.zshrc`:
   ```bash
   source ~/.zshrc
   ```

## How it Works

The plugin monitors these git-related files and directories:

- `.git/index` (staging area changes)
- `.git/HEAD` (branch switches, commits)
- `.git/refs` (branch and tag changes)
- `.git/info/exclude` (repository-specific ignore rules)
- All `.gitignore` files in the repository
- Working directory (for new untracked files)

When changes are detected, it sends `SIGUSR1` to the shell to trigger a prompt redraw via `zle reset-prompt`.

When gitignore files change, it restarts the watcher with updated ignore patterns.

## Configuration

The plugin works out of the box with Starship and other prompts that respond to `zle reset-prompt`. No additional configuration is required.

## Troubleshooting

### Prompt not updating

- Ensure fswatch is installed and in your PATH
- Check that your prompt supports `zle reset-prompt`
- Verify you're inside a git repository

### High CPU usage

- The plugin excludes `.git/objects/` and `.git/logs/` to avoid monitoring frequently changing files
- Large repositories with many files may still cause some overhead

### Permission errors

- Ensure fswatch has permission to monitor your repository directories

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

## Testing

The project includes comprehensive test suites that validate functionality in real shell environments with **100% test coverage**.

**Run tests:**

```bash
just ci
```

**Development workflow:**

```bash
# Run main Rust test suite
just test-main

# Run all tests with aggressive linting
just ci

# Format code
just fmt

# Run linter
just lint
```

### Rust Test Suite (Primary)

The main test suite is implemented in **Rust** using cargo test framework with complete coverage:

- **20 comprehensive tests** - All tests passing (100% success rate)
- **Real shell interaction** using expectrl (Rust equivalent of pexpect)
- **Git operations** with git2 crate for repository management
- **Process management** using sysinfo crate for fswatch monitoring
- **Signal handling** with nix crate for SIGUSR1/SIGUSR2 delivery
- **Security testing** including malicious gitignore pattern validation
- **Starship integration** with custom configuration for prompt testing
- **Isolated environments** with temporary directories and automatic cleanup

**Key test categories:**

- Plugin loading and fswatch lifecycle management
- File change detection and monitoring
- Git operations (staging, commits, branch switches, gitignore changes)
- Repository navigation and watcher persistence
- Shell job management and process cleanup
- Signal delivery and prompt update mechanisms
- Security resilience against command injection attacks

### Python Test Suite (Legacy)

The original Python test suite is preserved for reference and compatibility:

```bash
pytest tests/test_git_prompt_watcher.py -v
```

**Features:**

- Uses pexpect for shell interaction and GitPython for git operations
- Comprehensive coverage of plugin functionality
- Docker CI support for reproducible testing environments

### Docker CI

The project includes a fully reproducible Docker CI setup:

- **Base image**: Python 3.13-slim with pinned SHA256 digest
- **Reproducible builds**: Uses Debian snapshot archives with specific timestamps
- **Pinned dependencies**: All system packages and tools locked to exact versions
- **Complete toolchain**: Includes Rust, cargo, just, starship, and all testing dependencies

```bash
just docker-ci
```

## Contributing

Contributions are welcome! Please ensure tests pass before submitting pull requests.
