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

The plugin includes a comprehensive pytest test suite that validates functionality in real shell environments.

**Run tests:**

```bash
just ci
```

**Test coverage:**

- Plugin loading and watcher lifecycle
- File monitoring with real fswatch processes
- Git operations (staging, commits, branch switches)
- Signal handling (TRAPUSR1/TRAPUSR2)
- Gitignore handling and directory navigation
- Cleanup and resilience testing

Tests use pexpect for real zsh interaction, GitPython for git operations, and run in isolated temporary directories with automatic cleanup.

## Contributing

Contributions are welcome! Please ensure tests pass before submitting pull requests.
