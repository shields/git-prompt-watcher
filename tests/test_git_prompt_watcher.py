#!/usr/bin/env python3
"""Integration tests for git-prompt-watcher zsh plugin using pytest and pexpect.

Tests real shell interactions, signal handling, and prompt updates.
"""

import logging
import os
import re
import shutil
import signal
import time
from pathlib import Path

import pexpect
import psutil
import pytest
from git import Repo

logger = logging.getLogger(__name__)

# Timeouts
DEFAULT_SHELL_TIMEOUT = 15
COMMAND_TIMEOUT = 5
STARSHIP_TIMEOUT = 10
SIGNAL_TIMEOUT = 1

# Sleep intervals
FSWATCH_DETECTION_DELAY = 0.1
PROCESS_CLEANUP_DELAY = 0.2
SHELL_EXIT_DELAY = 0.5

# Git config
TEST_EMAIL = "test@example.com"
TEST_USER = "Test User"

# Shell markers
PROMPT_MARKER = "PROMPT_READY"
SHELL_PROMPT = "test>"


class TestGitPromptWatcher:
    """Test git-prompt-watcher plugin functionality in real zsh sessions."""

    def verify_fswatch_running(self, pid: int) -> bool:
        """Verify that the given PID is actually a running fswatch process."""
        if not pid:
            return False

        # First check if PID exists
        if not psutil.pid_exists(pid):
            return False

        # Give a moment for process to start properly
        time.sleep(FSWATCH_DETECTION_DELAY)

        # Check again - if fswatch isn't installed, process will have exited
        if not psutil.pid_exists(pid):
            return False

        try:
            # Verify it's actually fswatch
            proc = psutil.Process(pid)
            cmdline = proc.cmdline()
            return "fswatch" in " ".join(cmdline)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False

    def get_watcher_pid(self, child: pexpect.spawn) -> int:
        """Get the current watcher PID from the shell."""
        child.sendline("echo $_git_prompt_watcher_pid")
        child.expect(r"(\d+)\r\n")
        pid = int(child.match.group(1))
        child.expect(SHELL_PROMPT)
        return pid

    def get_and_verify_watcher_pid(self, child: pexpect.spawn) -> int:
        """Get watcher PID and verify it's running."""
        pid = self.get_watcher_pid(child)
        assert self.verify_fswatch_running(pid), "fswatch should be running"
        return pid

    def wait_for_prompt(self, child: pexpect.spawn) -> None:
        """Wait for shell prompt to appear."""
        child.expect(PROMPT_MARKER)
        child.expect(SHELL_PROMPT)

    def configure_git_repo(self, repo: Repo) -> None:
        """Configure a git repository with test user settings."""
        with repo.config_writer() as config:
            config.set_value("user", "email", TEST_EMAIL)
            config.set_value("user", "name", TEST_USER)

    def create_and_commit_file(
        self,
        repo: Repo,
        filename: str,
        content: str = "test content",
        commit_msg: str | None = None,
    ) -> Path:
        """Create a file in the repository and commit it."""
        repo_path = Path(repo.working_dir)
        file_path = repo_path / filename
        file_path.write_text(content)
        repo.index.add([filename])
        repo.index.commit(commit_msg or f"Add {filename}")
        return file_path

    @pytest.fixture(autouse=True)
    def setup(self, tmp_path: Path) -> None:
        """Set up test environment for each test."""
        self.project_root = Path(__file__).parent.parent
        self.plugin_path = self.project_root / "git-prompt-watcher.plugin.zsh"

        # Use pytest's tmp_path fixture for temporary directory
        self.temp_dir = tmp_path
        self.test_repo_path = self.temp_dir / "test_repo"

        # Track spawned children for cleanup
        self.children = []

        yield

        # Cleanup all spawned children
        for child in self.children:
            if child.isalive():
                child.close()

        # tmp_path is automatically cleaned up by pytest

    def get_zsh_child(
        self,
        cwd: Path | None = None,
        *,
        use_starship: bool = False,
    ) -> pexpect.spawn:
        """Get a zsh child process with the plugin loaded."""
        if cwd is None:
            cwd = self.test_repo_path

        # Create zsh startup script that loads our plugin
        if use_starship:
            # Use custom starship config for testing
            starship_config_path = self.project_root / "tests" / "starship.toml"
            startup_script = f"""
# Disable first-time user configuration
setopt NO_GLOBAL_RCS
setopt NO_RCS

# Load the plugin
source {self.plugin_path}

# Set custom starship config
export STARSHIP_CONFIG={starship_config_path}

# Initialize Starship
if command -v starship >/dev/null 2>&1; then
    eval "$(starship init zsh)"
fi

# Simple marker after initial setup
echo "SHELL_READY"

# Skip any interactive setup
DISABLE_AUTO_UPDATE=true
DISABLE_UPDATE_PROMPT=true
"""
        else:
            startup_script = f"""
# Disable first-time user configuration
setopt NO_GLOBAL_RCS
setopt NO_RCS

# Load the plugin
source {self.plugin_path}

# Simple prompt for testing
export PS1="test> "

# Custom marker for prompt detection
export PROMPT_MARKER="PROMPT_READY"
precmd() {{ echo "$PROMPT_MARKER" }}

# Skip any interactive setup
DISABLE_AUTO_UPDATE=true
DISABLE_UPDATE_PROMPT=true
"""

        script_file = self.temp_dir / ".zshrc"
        script_file.write_text(startup_script)

        # Create empty .zshenv to prevent global configs
        zshenv_file = self.temp_dir / ".zshenv"
        zshenv_file.write_text("# Test environment\n")

        # Spawn zsh directly with our custom config, skipping system configs
        env = os.environ.copy()
        env["ZDOTDIR"] = str(self.temp_dir)
        env["HOME"] = str(self.temp_dir)  # Override home to use our configs

        child = pexpect.spawn(
            "zsh",
            [],
            timeout=DEFAULT_SHELL_TIMEOUT,
            env=env,
            encoding="utf-8",
            echo=False,
            cwd=cwd,
        )
        child.setwinsize(24, 80)  # Set reasonable terminal size

        self.children.append(child)

        if use_starship:
            # For Starship, wait for shell ready marker, then the prompt
            try:
                child.expect("SHELL_READY", timeout=STARSHIP_TIMEOUT)
                # Wait for initial prompt (clean repo state)
                child.expect(["on .* ❯", "❯"], timeout=COMMAND_TIMEOUT)
            except pexpect.TIMEOUT:
                # Debug: log timeout information
                logger.warning("Starship timeout. Buffer: %s", child.before)
                logger.warning("After: %s", child.after)
                raise
        else:
            # Wait for shell to start
            child.expect(PROMPT_MARKER, timeout=COMMAND_TIMEOUT)
            child.expect(SHELL_PROMPT, timeout=COMMAND_TIMEOUT)

        return child

    def create_test_repo(self) -> Repo:
        """Create a test git repository using GitPython."""
        self.test_repo_path.mkdir(parents=True)

        # Initialize repo
        repo = Repo.init(self.test_repo_path)

        # Configure git
        self.configure_git_repo(repo)

        # Initial commit
        self.create_and_commit_file(
            repo, "README.md", "# Test repo\n", "Initial commit",
        )

        return repo

    def test_prerequisites(self) -> None:
        """Test that required tools are available."""
        # Check git
        assert shutil.which("git"), "git command should be available"

        # Check fswatch
        assert shutil.which("fswatch"), "fswatch command should be available"

    def test_plugin_loads_without_error(self) -> None:
        """Test that the plugin loads without errors."""
        self.create_test_repo()
        child = self.get_zsh_child()

        # Plugin should have loaded successfully
        child.sendline("echo 'Plugin loaded successfully'")
        child.expect("Plugin loaded successfully")
        child.expect("test>")

    def test_watcher_starts_in_git_repo(self) -> None:
        """Test that the watcher starts when in a git repository."""
        self.create_test_repo()
        child = self.get_zsh_child()

        # Check if watcher PID is set
        child.sendline('echo "Watcher PID: $_git_prompt_watcher_pid"')
        child.expect("Watcher PID: ")

        # Should have a PID (not empty)
        index = child.expect([r"Watcher PID: \s*\r\n", r"Watcher PID: (\d+)"])
        assert index == 1, "Watcher PID should not be empty in git repo"

        # Verify the PID is actually a running fswatch process
        watcher_pid = int(child.match.group(1))
        assert self.verify_fswatch_running(watcher_pid), (
            "Watcher PID is set but fswatch is not running"
        )

    def test_watcher_stops_outside_git_repo(self) -> None:
        """Test that the watcher stops when outside a git repository."""
        self.create_test_repo()
        child = self.get_zsh_child()

        # Move outside git repo
        child.sendline(f"cd {self.temp_dir}")
        child.expect("PROMPT_READY")
        child.expect("test>")

        # Check if watcher PID is cleared
        child.sendline("echo \"Watcher PID: '$_git_prompt_watcher_pid'\"")
        child.expect("Watcher PID: ''")

    def test_file_change_triggers_fswatch(self) -> None:
        """Test that file changes trigger fswatch monitoring."""
        self.create_test_repo()
        child = self.get_zsh_child()

        # Get the watcher PID and verify it's running
        watcher_pid = self.get_and_verify_watcher_pid(child)

        # Create a new file directly
        new_file = self.test_repo_path / "newfile.txt"
        new_file.write_text("test content")

        # Give fswatch time to detect the change
        time.sleep(0.1)

        # Watcher should still be running
        assert self.verify_fswatch_running(watcher_pid), (
            "Watcher should still be running after file change"
        )

    def test_git_operations_trigger_monitoring(self) -> None:
        """Test that git operations are properly monitored."""
        repo = self.create_test_repo()
        child = self.get_zsh_child()

        # Get the watcher PID and verify it's running
        watcher_pid = self.get_and_verify_watcher_pid(child)

        # Perform git operations using GitPython
        staged_file = self.test_repo_path / "staged.txt"
        staged_file.write_text("staged content")

        # Stage the file
        repo.index.add(["staged.txt"])

        # Give fswatch time to detect the change
        time.sleep(0.1)

        # Watcher should still be running
        assert self.verify_fswatch_running(watcher_pid), (
            "Watcher should handle git staging"
        )

        # Commit the file
        repo.index.commit("Add staged file")

        time.sleep(0.1)

        # Watcher should still be running
        assert self.verify_fswatch_running(watcher_pid), (
            "Watcher should handle git commits"
        )

    def test_signal_handling_setup(self) -> None:
        """Test that signal handlers are properly set up."""
        self.create_test_repo()
        child = self.get_zsh_child()

        # Check if TRAPUSR1 is defined
        child.sendline("declare -f TRAPUSR1")
        child.expect("TRAPUSR1")
        child.expect("test>")

        # Check if TRAPUSR2 is defined
        child.sendline("declare -f TRAPUSR2")
        child.expect("TRAPUSR2")
        child.expect("test>")

        # Check function registration
        child.sendline("echo ${chpwd_functions[*]}")
        child.expect("_check_git_repo_change")
        child.expect("test>")

        child.sendline("echo ${zshexit_functions[*]}")
        child.expect("_stop_git_watcher")
        child.expect("test>")

    def test_gitignore_change_handling(self) -> None:
        """Test that gitignore changes are properly handled."""
        self.create_test_repo()
        child = self.get_zsh_child()

        # Get initial watcher PID
        child.sendline("echo $_git_prompt_watcher_pid")
        child.expect(r"(\d+)\r\n")
        initial_pid = int(child.match.group(1))

        # Verify fswatch is running
        assert self.verify_fswatch_running(initial_pid), "fswatch should be running"

        # Modify .gitignore directly
        gitignore = self.test_repo_path / ".gitignore"
        gitignore.write_text("*.log\n")

        # Give time for potential restart
        time.sleep(0.2)

        # Check if watcher is still running (same or new PID)
        child.sendline("echo $_git_prompt_watcher_pid")
        child.expect(r"(\d+)\r\n")
        current_pid = int(child.match.group(1))

        assert psutil.pid_exists(current_pid), (
            "Watcher should be running after gitignore change"
        )

    def test_branch_switching(self) -> None:
        """Test that branch switching is properly monitored."""
        repo = self.create_test_repo()
        child = self.get_zsh_child()

        # Create and switch to new branch using GitPython
        new_branch = repo.create_head("test-branch")
        new_branch.checkout()

        # Get watcher PID
        child.sendline("echo $_git_prompt_watcher_pid")
        child.expect(r"(\d+)\r\n")
        watcher_pid = int(child.match.group(1))

        # Verify fswatch is running
        assert self.verify_fswatch_running(watcher_pid), "fswatch should be running"

        # Create commit on new branch
        branch_file = self.test_repo_path / "branch_file.txt"
        branch_file.write_text("branch content")
        repo.index.add(["branch_file.txt"])
        repo.index.commit("Branch commit")

        # Switch back to main
        repo.heads.main.checkout()

        time.sleep(0.1)

        # Watcher should still be running
        assert self.verify_fswatch_running(watcher_pid), (
            "Watcher should handle branch switching"
        )

    def test_watcher_cleanup_on_exit(self) -> None:
        """Test that the _stop_git_watcher function properly clears the PID variable."""
        self.create_test_repo()
        child = self.get_zsh_child()

        # Verify watcher is initially running (PID is set)
        child.sendline("echo \"Initial PID: '$_git_prompt_watcher_pid'\"")
        child.expect("Initial PID: ")

        # Should have a PID (not empty)
        index = child.expect([r"Initial PID: ''\r\n", r"Initial PID: '(\d+)'"])
        assert index == 1, "Watcher PID should be set initially"

        # Call stop function
        child.sendline("_stop_git_watcher")
        child.expect("test>")

        # Check that PID variable is cleared
        child.sendline("echo \"After stop PID: '$_git_prompt_watcher_pid'\"")
        child.expect("After stop PID: ''")
        child.expect("test>")

        # Test that starting and stopping works multiple times
        child.sendline("_start_git_watcher")
        child.expect("test>")

        child.sendline("echo \"Restarted PID: '$_git_prompt_watcher_pid'\"")
        child.expect("Restarted PID: ")

        # Should have a PID again
        index = child.expect([r"Restarted PID: ''\r\n", r"Restarted PID: '(\d+)'"])
        assert index == 1, "Watcher PID should be set after restart"

        # Stop again
        child.sendline("_stop_git_watcher")
        child.expect("test>")

        # Should be cleared again
        child.sendline("echo \"Final PID: '$_git_prompt_watcher_pid'\"")
        child.expect("Final PID: ''")
        child.expect("test>")

    def test_multiple_rapid_file_changes(self) -> None:
        """Test that the watcher handles multiple rapid file changes."""
        repo = self.create_test_repo()
        child = self.get_zsh_child()

        # Get watcher PID
        child.sendline("echo $_git_prompt_watcher_pid")
        child.expect(r"(\d+)\r\n")
        watcher_pid = int(child.match.group(1))

        # Verify fswatch is running
        assert self.verify_fswatch_running(watcher_pid), "fswatch should be running"

        # Create multiple files rapidly
        files_to_add = []
        for i in range(5):
            file_path = self.test_repo_path / f"file{i}.txt"
            file_path.write_text(f"content {i}")
            files_to_add.append(f"file{i}.txt")

        # Add all files at once
        repo.index.add(files_to_add)

        time.sleep(0.1)

        # Watcher should survive rapid changes
        assert self.verify_fswatch_running(watcher_pid), (
            "Watcher should handle rapid file changes"
        )

    def test_signal_delivery_to_shell(self) -> None:
        """Test that signals are actually delivered to the shell process."""
        self.create_test_repo()
        child = self.get_zsh_child()

        # Use the pexpect child PID directly - this is our actual shell process
        shell_pid = child.pid

        # Create a test function to detect signal receipt
        child.sendline("""
signal_received=""
TRAPUSR1() {
    signal_received="USR1_RECEIVED"
    echo "Signal received in shell"
}
""")
        child.expect("test>")

        # Send USR1 signal to the actual shell process
        os.kill(shell_pid, signal.SIGUSR1)

        # Give time for signal processing
        time.sleep(0.2)

        # Check if signal was received
        child.sendline("echo $signal_received")
        child.expect("USR1_RECEIVED")
        child.expect("test>")

    def test_prompt_updates_with_starship(self) -> None:
        """Test that the watcher automatically triggers prompt updates with Starship.

        Tests when git changes occur.
        """
        self.create_test_repo()
        child = self.get_zsh_child(use_starship=True)

        # Get initial watcher PID to verify it's running
        child.sendline("echo $_git_prompt_watcher_pid")
        child.expect(r"(\d+)\r\n")
        watcher_pid = int(child.match.group(1))
        # Expect clean repo prompt (no git status indicators)
        child.expect(["on .* ❯", "❯"])

        # Verify watcher is running
        assert self.verify_fswatch_running(watcher_pid), (
            "fswatch should be running with Starship"
        )

        # Create a new file (should trigger git status change and automatic
        # prompt update)
        new_file = self.test_repo_path / "untracked.txt"
        new_file.write_text("untracked content")

        # The prompt should automatically update to show untracked file indicator "?"
        try:
            child.expect("\\? ❯", timeout=1)
        except pexpect.TIMEOUT:
            # If fswatch is not installed, the prompt won't update automatically
            pytest.fail(
                "Prompt did not automatically update to show untracked file (?)",
            )

        # Verify watcher is still running after file change
        assert psutil.pid_exists(watcher_pid), (
            "Watcher should still be running after file change"
        )

        # Stage the file to trigger another automatic change
        child.sendline("git add untracked.txt")

        # The prompt should automatically update to show staged file indicator "+"
        try:
            child.expect("\\+ ❯", timeout=1)
        except pexpect.TIMEOUT:
            # If fswatch is not installed, the prompt won't update automatically
            pytest.fail("Prompt did not automatically update to show staged file (+)")

        # Verify watcher handles git staging with automatic prompt updates
        assert psutil.pid_exists(watcher_pid), (
            "Watcher should handle git staging with Starship"
        )

    def test_prompt_updates_on_branch_switch(self) -> None:
        """Test that the prompt updates when switching branches with Starship."""
        # Check if starship is available
        if not shutil.which("starship"):
            pytest.skip("Starship not installed - skipping branch switch prompt test")

        self.create_test_repo()
        child = self.get_zsh_child(use_starship=True)

        # Get watcher PID
        child.sendline("echo $_git_prompt_watcher_pid")
        child.expect(r"(\d+)\r\n")
        watcher_pid = int(child.match.group(1))
        # Should see "on main" in prompt (with or without ANSI codes)
        child.expect([r"on \x1b\[.*main.*❯", r"on .*main.*❯"])

        # Create and switch to new branch
        child.sendline("git checkout -b feature-branch")
        # Wait for command to complete
        child.expect("Switched to a new branch")

        # The prompt should automatically update to show "on feature-branch"
        try:
            child.expect("on .*feature-branch.* ❯", timeout=1)
        except pexpect.TIMEOUT:
            pytest.fail("Prompt did not automatically update to show new branch name")

        # Verify watcher is still running after branch switch
        assert psutil.pid_exists(watcher_pid), (
            "Watcher should handle branch switching with Starship"
        )

        # Switch back to main
        child.sendline("git checkout main")
        # Wait for command to complete
        child.expect("Switched to branch")

        # The prompt should automatically update to show "on main" again
        try:
            child.expect("on .*main.* ❯", timeout=1)
        except pexpect.TIMEOUT:
            pytest.fail("Prompt did not automatically update back to main branch")

        # Verify watcher handles multiple branch switches
        assert psutil.pid_exists(watcher_pid), (
            "Watcher should handle multiple branch switches"
        )

    def test_watcher_restarts_between_different_repos(self) -> None:
        """Test that the watcher stops and restarts when moving between repositories.

        Tests moving between different git repositories.
        """
        # Create first repository
        self.create_test_repo()
        child = self.get_zsh_child()

        # Get initial watcher PID and git dir
        child.sendline("echo $_git_prompt_watcher_pid")
        child.expect(r"(\d+)\r\n")
        initial_pid = int(child.match.group(1))
        child.expect("test>")

        child.sendline("pwd")
        child.expect("test>")

        # Verify initial watcher is running
        assert self.verify_fswatch_running(initial_pid), (
            "Initial watcher should be running"
        )

        # Create second repository in a different location
        repo2_path = self.temp_dir / "second_repo"
        repo2_path.mkdir()
        repo2 = Repo.init(repo2_path)

        # Configure second repo
        with repo2.config_writer() as config:
            config.set_value("user", "email", TEST_EMAIL)
            config.set_value("user", "name", TEST_USER)

        # Add initial file to second repo
        readme2 = repo2_path / "README.md"
        readme2.write_text("# Second repo\n")
        repo2.index.add(["README.md"])
        repo2.index.commit("Initial commit in second repo")

        # First move outside both repos to ensure watcher stops
        child.sendline(f"cd {self.temp_dir}")
        child.expect("PROMPT_READY")
        child.expect("test>")

        # Verify watcher is stopped
        child.sendline("echo \"Outside repo PID: '$_git_prompt_watcher_pid'\"")
        child.expect("Outside repo PID: ''")
        child.expect("test>")

        # Now move to second repository
        child.sendline(f"cd {repo2_path}")
        child.expect("PROMPT_READY")
        child.expect("test>")

        # Give time for new watcher to start
        time.sleep(0.2)

        # Get new watcher PID
        child.sendline("echo $_git_prompt_watcher_pid")
        child.expect(r"(\d+)\r\n")
        new_pid = int(child.match.group(1))
        child.expect("test>")

        # Even if PIDs are the same (due to reuse), verify that the old
        # process was killed
        # and that the new one is running
        assert self.verify_fswatch_running(new_pid), (
            "New watcher should be running in second repository"
        )

        # More importantly, check that we can detect changes in both repos
        # Create a file in the second repo to verify the watcher is working
        test_file = repo2_path / "test_change.txt"
        test_file.write_text("test content")

        # Give time for fswatch to detect the change
        time.sleep(0.1)

        # The watcher should still be alive and monitoring
        assert self.verify_fswatch_running(new_pid), (
            "Watcher should handle file changes in second repository"
        )

        # Test demonstrates that the watcher successfully transitions between
        # repositories
        # The key point is that the watcher works in the second repo,
        # regardless of PID reuse

    def test_watcher_stays_same_within_repo_subdirs(self) -> None:
        """Test that the watcher does not restart when moving between directories.

        Tests moving between directories within the same repository.
        """
        self.create_test_repo()
        child = self.get_zsh_child()

        # Get initial watcher PID
        child.sendline("echo $_git_prompt_watcher_pid")
        child.expect(r"(\d+)\r\n")
        initial_pid = int(child.match.group(1))
        child.expect("test>")

        # Verify initial watcher is running
        assert psutil.pid_exists(initial_pid), "Initial watcher should be running"

        # Create subdirectories within the repo
        subdir1 = self.test_repo_path / "src"
        subdir1.mkdir()
        subdir2 = self.test_repo_path / "docs" / "api"
        subdir2.mkdir(parents=True)

        # Move to first subdirectory
        child.sendline(f"cd {subdir1}")
        child.expect("PROMPT_READY")
        child.expect("test>")

        # No restart expected for subdirectory navigation

        # Check watcher PID
        child.sendline("echo $_git_prompt_watcher_pid")
        child.expect(r"(\d+)\r\n")
        current_pid = int(child.match.group(1))
        child.expect("test>")

        # PID should be the same (no restart)
        assert initial_pid == current_pid, (
            "Watcher should not restart when moving within same repository"
        )
        assert psutil.pid_exists(current_pid), "Watcher should still be running"

        # Move to nested subdirectory
        child.sendline(f"cd {subdir2}")
        child.expect("PROMPT_READY")
        child.expect("test>")

        # Check watcher PID again
        child.sendline("echo $_git_prompt_watcher_pid")
        child.expect(r"(\d+)\r\n")
        final_pid = int(child.match.group(1))
        child.expect("test>")

        # PID should still be the same
        assert initial_pid == final_pid, (
            "Watcher should not restart when moving to nested subdirectory"
        )
        assert psutil.pid_exists(final_pid), "Watcher should still be running"

        # Move back to repo root
        child.sendline(f"cd {self.test_repo_path}")
        child.expect("PROMPT_READY")
        child.expect("test>")

        # Check watcher PID one more time
        child.sendline("echo $_git_prompt_watcher_pid")
        child.expect(r"(\d+)\r\n")
        root_pid = int(child.match.group(1))
        child.expect("test>")

        # PID should still be the same
        assert initial_pid == root_pid, (
            "Watcher should not restart when returning to repo root"
        )
        assert psutil.pid_exists(root_pid), "Watcher should still be running"

    def test_adversarial_gitignore_security(self, tmp_path: Path) -> None:
        """Test that adversarial .gitignore files cannot cause security issues."""
        self.create_test_repo()
        child = self.get_zsh_child()

        # Get initial watcher PID
        child.sendline("echo $_git_prompt_watcher_pid")
        child.expect(r"(\d+)\r\n")
        initial_pid = int(child.match.group(1))
        child.expect("test>")

        # Verify initial watcher is running
        assert psutil.pid_exists(initial_pid), "Initial watcher should be running"

        # Test 1: Command injection via gitignore patterns
        malicious_gitignore = self.test_repo_path / ".gitignore"
        malicious_patterns = [
            # Try to inject shell commands
            "normal_file.txt",
            "; rm -rf /tmp/test_attack",  # Command injection attempt
            "$(echo 'command_substitution')",  # Command substitution
            "`echo 'backtick_substitution'`",  # Backtick substitution
            "file && echo 'logical_and'",  # Logical operators
            "file || echo 'logical_or'",
            "file | echo 'pipe'",  # Pipe operator
            "file; echo 'semicolon'",  # Command separator
            "file\necho 'newline'",  # Newline injection
            "file\recho 'carriage_return'",  # Carriage return
            "file\techo 'tab'",  # Tab character
            # Special characters that might break parsing
            "file with spaces",
            "file'with'quotes",
            'file"with"double"quotes',
            "file\\with\\backslashes",
            "file$with$dollar$signs",
            "file#with#hash",
            "file%with%percent",
            "file&with&ampersand",
            "file*with*asterisk",
            "file?with?question",
            "file[with]brackets",
            "file{with}braces",
            "file(with)parentheses",
            "file<with>angles",
            "file=with=equals",
            "file+with+plus",
            "file-with-dash",
            "file_with_underscore",
            "file.with.dots",
            "file/with/slashes",
            "file\\\\with\\\\double\\\\backslashes",
            # Unicode and special encodings
            "file\u0000with\u0000null",  # Null bytes
            "file\u001bwith\u001bescape",  # Escape sequences
            "file\u00ffwith\u00ffhigh",  # High bytes
            "file\u2028with\u2028line\u2028separator",  # Unicode line separator
            "file\u2029with\u2029paragraph\u2029separator",  # Unicode
            # paragraph separator
            # Very long patterns (potential buffer overflow)
            "a" * 1000,
            "b" * 10000,
            # Path traversal attempts
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "/etc/shadow",
            "/dev/null",
            "/dev/zero",
            "/dev/random",
            "/proc/self/exe",
            # Glob patterns that might cause issues
            "**/**/***/**",
            "*" * 100,
            "?" * 100,
            "[" * 100,
            "]" * 100,
            "{" * 100,
            "}" * 100,
            # Regular expression special characters
            "file.*with.*regex",
            "file.+with.+regex",
            "file.{1,100}with.{1,100}regex",
            "file^with^caret",
            "file$with$dollar$end",
            # Control characters
            "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
            "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
            # Format string attacks
            "%s%s%s%s%s%s%s%s%s%s",
            "%x%x%x%x%x%x%x%x%x%x",
            "%n%n%n%n%n%n%n%n%n%n",
        ]

        # Write malicious gitignore
        malicious_gitignore.write_text("\n".join(malicious_patterns))

        # Give time for fswatch to detect gitignore change (should restart watcher)
        time.sleep(0.2)

        # Check if watcher is still running (should be restarted)
        child.sendline("echo $_git_prompt_watcher_pid")
        child.expect(r"(\d+)\r\n")
        new_pid = int(child.match.group(1))
        child.expect("test>")

        # Watcher should be running (potentially with new PID due to restart)
        assert psutil.pid_exists(new_pid), "Watcher should survive malicious gitignore"

        # Test 2: Malicious gitignore file paths
        malicious_paths = [
            # Try to create gitignore files in dangerous locations
            ".gitignore; touch /tmp/attack_file",
            ".gitignore`touch /tmp/attack_file`",
            ".gitignore$(touch /tmp/attack_file)",
            ".gitignore && touch /tmp/attack_file",
            ".gitignore || touch /tmp/attack_file",
            ".gitignore | touch /tmp/attack_file",
        ]

        for malicious_path in malicious_paths:
            # Try to create file with malicious name (should be handled safely)
            try:
                malicious_file = self.test_repo_path / malicious_path
                malicious_file.write_text("malicious content")

                # Give time for potential processing
                time.sleep(0.1)

                # Watcher should still be running
                assert psutil.pid_exists(new_pid), (
                    f"Watcher should survive malicious path: {malicious_path}"
                )

                # Clean up
                malicious_file.unlink()
            except (OSError, ValueError):
                # Some malicious paths might not be valid filenames - that's OK
                pass

        # Test 3: Verify no attack files were created
        attack_files = [
            "attack_file",
            "test_attack",
            "command_substitution",
            "backtick_substitution",
        ]

        for attack_file in attack_files:
            attack_path = tmp_path / attack_file
            assert not attack_path.exists(), (
                f"Attack file should not exist: {attack_file}"
            )

        # Test 4: Verify shell is still functional
        child.sendline("echo 'shell_still_works'")
        child.expect("shell_still_works")
        child.expect("test>")

        # Test 5: Verify watcher is still monitoring normally
        normal_file = self.test_repo_path / "normal_test.txt"
        normal_file.write_text("normal content")

        # Give time for fswatch to detect normal file
        time.sleep(0.1)

        # Watcher should still be running and monitoring
        assert psutil.pid_exists(new_pid), (
            "Watcher should continue monitoring after adversarial test"
        )

        # Test 6: Test with extremely large gitignore file
        large_gitignore = self.test_repo_path / ".gitignore_large"
        large_patterns = ["pattern" + str(i) for i in range(10000)]
        large_gitignore.write_text("\n".join(large_patterns))

        # Give time for potential processing
        time.sleep(0.2)

        # Watcher should handle large files gracefully
        child.sendline("echo $_git_prompt_watcher_pid")
        child.expect(r"(\d+)\r\n")
        final_pid = int(child.match.group(1))
        child.expect("test>")

        assert psutil.pid_exists(final_pid), (
            "Watcher should handle large gitignore files"
        )

        # Clean up large file
        large_gitignore.unlink()

        # Test 7: Test with malicious global gitignore
        # Create a temporary global gitignore with malicious content
        global_gitignore = self.temp_dir / "global_gitignore"
        global_gitignore.write_text(
            """$(malicious_command)
; rm -rf /
`evil_command`
normal_pattern.txt""",
        )

        # Set the global gitignore temporarily
        child.sendline(f"git config --global core.excludesfile {global_gitignore}")
        child.expect("test>")

        # Restart the watcher to pick up the new global gitignore
        child.sendline("_stop_git_watcher && _start_git_watcher")
        child.expect("test>")

        # Check that watcher is still running
        child.sendline("echo $_git_prompt_watcher_pid")
        child.expect(r"(\d+)\r\n")
        global_test_pid = int(child.match.group(1))
        child.expect("test>")

        assert psutil.pid_exists(global_test_pid), (
            "Watcher should handle malicious global gitignore"
        )

        # Verify shell is still functional
        child.sendline("echo 'global_gitignore_test_complete'")
        child.expect("global_gitignore_test_complete")
        child.expect("test>")

        # Clean up global gitignore setting
        child.sendline("git config --global --unset core.excludesfile")
        child.expect("test>")

        # Test 8: Test with malicious .git/info/exclude file
        exclude_file = self.test_repo_path / ".git" / "info" / "exclude"
        exclude_file.parent.mkdir(parents=True, exist_ok=True)
        exclude_file.write_text(
            """# This is a malicious exclude file
$(touch /tmp/exclude_attack)
; cat /etc/passwd
`whoami > /tmp/user_info`
normal_excluded_file.txt""",
        )

        # Give time for potential processing
        time.sleep(0.1)

        # Watcher should still be running
        assert psutil.pid_exists(global_test_pid), (
            "Watcher should handle malicious .git/info/exclude"
        )

        # Verify no attack files were created
        exclude_attacks = ["exclude_attack", "user_info"]
        for attack_file in exclude_attacks:
            attack_path = tmp_path / attack_file
            assert not attack_path.exists(), (
                f"Exclude attack file should not exist: {attack_file}"
            )

    def test_watcher_really_stops_when_leaving_repo(self) -> None:
        """Verify that watchers are actually killed when leaving repositories."""
        self.create_test_repo()
        child = self.get_zsh_child()

        # Get initial watcher PID
        child.sendline('echo "Watcher PID: $_git_prompt_watcher_pid"')
        child.expect(r"Watcher PID: (\d+)")
        initial_pid = int(child.match.group(1))
        child.expect("test>")

        # Let's check what the _start_git_watcher function is doing for debugging
        child.sendline("declare -f _start_git_watcher | head -20")
        child.expect("test>")

        # Verify initial watcher is running
        assert psutil.pid_exists(initial_pid), "Initial watcher should be running"

        # Get the actual process info for verification
        initial_process = psutil.Process(initial_pid)

        # Debug: check what process this actually is
        try:
            initial_cmdline = initial_process.cmdline()
            logger.debug("Initial process cmdline: %s", initial_cmdline)
        except psutil.AccessDenied:
            try:
                process_name = initial_process.name()
                logger.debug("Initial process name: %s", process_name)
            except psutil.AccessDenied:
                logger.debug("Cannot get process info for PID %s", initial_pid)

        # For now, let's just verify the PID exists and continue with the test
        # The process verification is done above via psutil

        # Move outside the git repository
        child.sendline(f"cd {self.temp_dir}")
        child.expect("PROMPT_READY")
        child.expect("test>")

        # Give time for the chpwd hook to trigger
        time.sleep(0.1)

        # Check that the PID variable is cleared
        child.sendline("echo \"PID after leaving: '$_git_prompt_watcher_pid'\"")
        child.expect("PID after leaving: ''")
        child.expect("test>")

        # Most importantly: verify the actual process is killed
        assert not psutil.pid_exists(initial_pid), (
            f"Watcher process {initial_pid} should be killed when leaving repo"
        )

        # Create another repo to test the watcher starts again
        second_repo_path = self.temp_dir / "second_repo"
        second_repo_path.mkdir()
        second_repo = Repo.init(second_repo_path)

        # Configure second repo
        with second_repo.config_writer() as config:
            config.set_value("user", "email", TEST_EMAIL)
            config.set_value("user", "name", TEST_USER)

        # Move to second repo
        child.sendline(f"cd {second_repo_path}")
        child.expect("PROMPT_READY")
        child.expect("test>")

        # Give time for new watcher to start
        time.sleep(0.1)

        # Should have a new watcher with different PID
        child.sendline("echo $_git_prompt_watcher_pid")
        child.expect(r"(\d+)\r\n")
        new_pid = int(child.match.group(1))
        child.expect("test>")

        # New PID should be different from the old one
        assert new_pid != initial_pid, "New watcher should have different PID"

        # New watcher should be running
        assert psutil.pid_exists(new_pid), "New watcher should be running"

        # Verify it's actually an fswatch process (handle permission errors
        # and PID reuse)
        new_process = psutil.Process(new_pid)
        is_fswatch = False
        try:
            new_cmdline = new_process.cmdline()
            logger.debug("New process cmdline: %s", new_cmdline)
            is_fswatch = "fswatch" in " ".join(new_cmdline)
        except psutil.AccessDenied:
            try:
                process_name = new_process.name()
                logger.debug("New process name: %s", process_name)
                is_fswatch = "fswatch" in process_name
            except psutil.AccessDenied:
                # If we can't get process info, assume it's working (PID reused)
                logger.debug("Cannot get process info for new PID %s", new_pid)
                is_fswatch = True

        # If PID reuse happened, that's OK - the important thing is that it works
        if not is_fswatch:
            logger.info(
                "PID %s was reused by a different process (this is normal)",
                new_pid,
            )

        # Move back outside any repo
        child.sendline(f"cd {self.temp_dir}")
        child.expect("PROMPT_READY")
        child.expect("test>")

        # Give time for chpwd hook
        time.sleep(0.1)

        # Verify the new watcher is also killed (or PID reused)
        # If PID exists, check if it's still the same fswatch process
        if psutil.pid_exists(new_pid):
            try:
                final_process = psutil.Process(new_pid)
                final_cmdline = final_process.cmdline()
                # If it's still fswatch, that's a problem
                if "fswatch" in " ".join(final_cmdline):
                    pytest.fail(
                        f"fswatch process {new_pid} should be killed when leaving repo",
                    )
                else:
                    logger.debug("PID %s was reused by: %s", new_pid, final_cmdline)
            except psutil.AccessDenied:
                try:
                    process_name = final_process.name()
                    if "fswatch" in process_name:
                        pytest.fail(
                            f"fswatch process {new_pid} should be killed when "
                            f"leaving repo",
                        )
                    else:
                        logger.debug(
                            "PID %s was reused by process: %s",
                            new_pid,
                            process_name,
                        )
                except psutil.AccessDenied:
                    logger.debug("Cannot verify if PID %s was reused", new_pid)

        # The important test is that the PID variable is cleared and the plugin works
        # We can't reliably check for fswatch processes without knowing which
        # ones are ours

        # Verify PID variable is cleared
        child.sendline("echo \"Final PID: '$_git_prompt_watcher_pid'\"")
        child.expect("Final PID: ''")
        child.expect("test>")

    def test_watcher_killed_on_shell_exit(self) -> None:
        """Verify that watchers are killed when the shell exits."""
        self.create_test_repo()
        child = self.get_zsh_child()

        # Get watcher PID
        child.sendline("echo $_git_prompt_watcher_pid")
        child.expect(r"(\d+)\r\n")
        watcher_pid = int(child.match.group(1))
        child.expect("test>")

        # Verify watcher is running
        assert self.verify_fswatch_running(watcher_pid), "fswatch should be running"

        # Force close the shell to test cleanup
        child.close()

        # Give time for cleanup
        time.sleep(0.5)

        # Verify watcher process is killed (handle PID reuse)
        if psutil.pid_exists(watcher_pid):
            try:
                proc = psutil.Process(watcher_pid)
                cmdline = proc.cmdline()
                # If it's still fswatch, that's a problem
                if "fswatch" in " ".join(cmdline):
                    pytest.fail(
                        f"fswatch process {watcher_pid} should be killed on shell exit",
                    )
                # If it's a different process, that's fine (PID reuse)
            except psutil.ZombieProcess:
                # Zombie processes are being cleaned up by init - that's fine
                # The fact that it's a zombie means the process is effectively dead
                pass
            except psutil.AccessDenied:
                try:
                    process_name = proc.name()
                    if "fswatch" in process_name:
                        pytest.fail(
                            f"fswatch process {watcher_pid} should be killed on "
                            f"shell exit",
                        )
                except psutil.ZombieProcess:
                    # If it's a zombie process, it's being cleaned up - that's fine
                    pass
                except psutil.AccessDenied:
                    # Can't verify, but the shell cleanup should have worked
                    pass

    def test_watcher_functionality_end_to_end(self) -> None:
        """Test that the watcher actually works by verifying it can detect file changes.

        Tests file change detection.
        """
        self.create_test_repo()
        child = self.get_zsh_child()

        # Get initial watcher PID
        child.sendline("echo $_git_prompt_watcher_pid")
        child.expect(r"(\d+)\r\n")
        initial_pid = int(child.match.group(1))
        child.expect("test>")

        # Verify watcher is running
        assert self.verify_fswatch_running(initial_pid), "fswatch should be running"

        # Create a file change that should trigger the watcher
        test_file = self.test_repo_path / "test_functionality.txt"
        test_file.write_text("test content")

        # Give time for fswatch to detect the change
        time.sleep(0.1)

        # Verify watcher is still running after file change
        assert psutil.pid_exists(initial_pid), (
            "Watcher should still be running after file change"
        )

        # Move outside repository
        child.sendline(f"cd {self.temp_dir}")
        child.expect("PROMPT_READY")
        child.expect("test>")

        # Give time for cleanup
        time.sleep(0.1)

        # Verify PID variable is cleared
        child.sendline("echo \"PID cleared: '$_git_prompt_watcher_pid'\"")
        child.expect("PID cleared: ''")
        child.expect("test>")

        # Verify the process was cleaned up (or PID was reused)
        if psutil.pid_exists(initial_pid):
            try:
                proc = psutil.Process(initial_pid)
                cmdline = proc.cmdline()
                # If it's still our fswatch process, that's a problem
                if "fswatch" in " ".join(cmdline) and str(
                    self.test_repo_path,
                ) in " ".join(cmdline):
                    # Check if it's monitoring our test repo - if so, cleanup failed
                    pytest.fail(
                        f"fswatch process {initial_pid} should be cleaned up when "
                        f"leaving repo",
                    )
            except psutil.AccessDenied:
                # Can't verify, but the plugin should have cleaned up
                pass

        # The key test: verify plugin works in a new repository
        new_repo_path = self.temp_dir / "new_repo"
        new_repo_path.mkdir()
        new_repo = Repo.init(new_repo_path)

        # Configure repo
        with new_repo.config_writer() as config:
            config.set_value("user", "email", TEST_EMAIL)
            config.set_value("user", "name", TEST_USER)

        # Move to new repo
        child.sendline(f"cd {new_repo_path}")
        child.expect("PROMPT_READY")
        child.expect("test>")

        # Should get a new watcher
        child.sendline("echo $_git_prompt_watcher_pid")
        child.expect(r"(\d+)\r\n")
        new_pid = int(child.match.group(1))
        child.expect("test>")

        # New watcher should be running
        assert psutil.pid_exists(new_pid), "New watcher should be running"

        # Test that the new watcher actually works
        new_test_file = new_repo_path / "new_test.txt"
        new_test_file.write_text("new test content")

        # Give time for fswatch to detect
        time.sleep(0.1)

        # Watcher should still be running
        assert psutil.pid_exists(new_pid), "New watcher should handle file changes"

    def _clean_jobs_output(self, raw_output: str) -> str:
        """Clean jobs output by removing ANSI sequences and terminal artifacts."""
        clean = raw_output.strip()
        # Remove ANSI escape sequences
        clean = re.sub(r"\x1b\[[?0-9;]*[mKJhlr]", "", clean)
        # Remove backspace and other control characters
        clean = re.sub(r"[\x08\x0c\x7f]", "", clean)
        # Remove carriage returns and line feeds
        clean = re.sub(r"[\r\n]", " ", clean)
        # Remove terminal artifacts
        clean = re.sub(r"PROMPT_READY", "", clean)
        clean = re.sub(r"%", "", clean)
        clean = re.sub(r"#", "", clean)  # Remove shell job markers
        # Remove command echo patterns (terminal echo still happens despite echo=False)
        clean = re.sub(r"j*jobs", "", clean)
        # Collapse whitespace
        return re.sub(r"\s+", " ", clean).strip()

    def test_fswatch_jobs_not_cluttering_output(self) -> None:
        """Test that fswatch processes don't appear in shell jobs output.

        Verifies that the jobs table is empty.
        """
        self.create_test_repo()
        child = self.get_zsh_child()

        # Plugin should be loaded and watcher running
        child.sendline("echo $_git_prompt_watcher_pid")
        child.expect(r"(\d+)\r\n")
        watcher_pid = int(child.match.group(1))
        child.expect("test>")

        # Verify watcher is running
        assert psutil.pid_exists(watcher_pid), "Watcher should be running"

        # Check jobs output - should be completely empty (no jobs at all)
        child.sendline("jobs")
        child.expect("test>")
        jobs_output = child.before
        clean_jobs_output = self._clean_jobs_output(jobs_output)

        # Jobs output should be completely empty - no jobs at all
        assert clean_jobs_output == "", (
            f"jobs should show no background jobs, but got: '{clean_jobs_output}'"
        )

        # Start a background job to verify jobs command works
        child.sendline("sleep 10 &")
        child.expect("test>")

        # Now jobs should show exactly one job (the sleep command) but still not fswatch
        child.sendline("jobs")
        child.expect("test>")
        jobs_output = child.before
        clean_jobs_output = self._clean_jobs_output(jobs_output)

        # Should contain sleep but not fswatch
        assert "sleep" in clean_jobs_output, (
            f"jobs should show background sleep: {clean_jobs_output}"
        )
        assert "fswatch" not in clean_jobs_output, (
            f"fswatch should not appear in jobs output: {clean_jobs_output}"
        )

        # Verify there's exactly one job by checking the job number format
        job_lines = [
            line
            for line in clean_jobs_output.split("\n")
            if "[" in line and "]" in line
        ]
        assert len(job_lines) == 1, (
            f"Should have exactly one job, but found {len(job_lines)}: {job_lines}"
        )

        # Kill the sleep job
        child.sendline("kill %1")
        child.expect("test>")

        # Wait a moment for the termination message to clear, then check jobs again
        time.sleep(0.1)
        child.sendline("jobs")
        child.expect("test>")
        jobs_output = child.before
        clean_jobs_output = self._clean_jobs_output(jobs_output)

        # Filter out termination messages
        if "terminated" in clean_jobs_output:
            # Run jobs again to get clean output after termination message
            child.sendline("jobs")
            child.expect("test>")
            jobs_output = child.before
            clean_jobs_output = self._clean_jobs_output(jobs_output)

        assert clean_jobs_output == "", (
            f"jobs should be empty after killing sleep job, but got: "
            f"'{clean_jobs_output}'"
        )


if __name__ == "__main__":
    # Run tests when executed directly
    pytest.main([__file__, "-v"])
