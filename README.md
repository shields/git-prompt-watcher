# Git Prompt Watcher

[![CI](https://github.com/shields/git-prompt-watcher/actions/workflows/test.yaml/badge.svg)](https://github.com/shields/git-prompt-watcher/actions/workflows/test.yaml)

An oh-my-zsh plugin that automatically updates your prompt when git status changes, using `fswatch` to monitor repository files in real-time.

It solves the problem of slow shell prompts in large Git repositories by avoiding shell-based file system scanning. Instead, it uses a dedicated, high-performance file system watcher (`fswatch`) to instantly detect changes and refresh the prompt on demand.

## Features

- **Real-time Prompt Updates**: Your prompt refreshes instantly when you change branches, commit, or modify files.
- **Efficient**: Uses `fswatch` for low-latency monitoring, avoiding slow shell commands in your prompt.
- **Git-Aware**: Respects your `.gitignore` files and automatically re-indexes when they change.
- **Stable**: Won't clutter your `jobs` output or leave orphaned processes behind.
- **Heavily Tested**: A comprehensive test suite validates functionality in a real shell environment to guarantee reliability.

## Requirements

- **oh-my-zsh**
- **fswatch** (e.g., `brew install fswatch`)
- A prompt that supports `zle reset-prompt` (like Starship, Powerlevel10k, etc.)
- macOS or Linux

## Installation

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/shields/git-prompt-watcher.git ~/.oh-my-zsh/custom/plugins/git-prompt-watcher
    ```

2.  **Add the plugin to your `.zshrc`:**

    ```zsh
    plugins=(... git-prompt-watcher)
    ```

3.  **Restart your shell.**

## How It Works

The plugin runs `fswatch` in the background to monitor key Git files (`.git/index`, `.git/HEAD`, `.git/refs`), your `.gitignore` files, and the working directory. When a change is detected, it sends a `SIGUSR1` signal to the parent Zsh process, which triggers `zle reset-prompt` to redraw your prompt.

## Contributing

Contributions are welcome! The plugin is rigorously tested using a custom-built test suite in Rust. For more details on testing and development, please see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
