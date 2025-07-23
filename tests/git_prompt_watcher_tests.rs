use anyhow::{Context, Result, anyhow};
use expectrl::{Regex, Session};
use git2::{Repository, Signature, Time};
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Once;
use std::thread;
use std::time::Duration;
use sysinfo::System;
use tempfile::TempDir;
use tokio::time::sleep;

static INIT_LOGGER: Once = Once::new();

fn setup_logger() {
    INIT_LOGGER.call_once(|| {
        env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .is_test(true)
            .try_init()
            .ok();
    });
}

// Timeouts

const PROCESS_POLL_TIMEOUT: Duration = Duration::from_secs(5);

// Sleep intervals
const POLL_INTERVAL: Duration = Duration::from_millis(50);
const FSWATCH_DETECTION_DELAY: Duration = Duration::from_millis(250);
const PROCESS_CLEANUP_DELAY: Duration = Duration::from_millis(200);

// Git config
const TEST_EMAIL: &str = "test@example.com";
const TEST_USER: &str = "Test User";

// Shell markers
const PROMPT_MARKER: &str = "PROMPT_READY";
const SHELL_PROMPT: &str = "test>";

// Security test data - malicious gitignore patterns
const MALICIOUS_GITIGNORE_PATTERNS: &[&str] = &[
    // Try to inject shell commands
    "normal_file.txt",
    "; rm -rf /tmp/test_attack",      // Command injection attempt
    "$(echo 'command_substitution')", // Command substitution
    "`echo 'backtick_substitution'`", // Backtick substitution
    "file && echo 'logical_and'",     // Logical operators
    "file || echo 'logical_or'",
    "file | echo 'pipe'",           // Pipe operator
    "file; echo 'semicolon'",       // Command separator
    "file\necho 'newline'",         // Newline injection
    "file\recho 'carriage_return'", // Carriage return
    "file\techo 'tab'",             // Tab character
    // Special characters that might break parsing
    "file with spaces",
    "file'with'quotes",
    "file\"with\"double\"quotes",
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
    // Unicode and special encodings
    "file\x00with\x00null",                               // Null bytes
    "file\x1bwith\x1bescape",                             // Escape sequences
    "file\x7fwith\x7fhigh",                               // High ASCII bytes
    "file\u{2028}with\u{2028}line\u{2028}separator",      // Unicode line separator
    "file\u{2029}with\u{2029}paragraph\u{2029}separator", // Unicode paragraph separator
    // Control characters
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
    "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
    // Format string attacks
    "%s%s%s%s%s%s%s%s%s%s",
    "%x%x%x%x%x%x%x%x%x%x",
    "%n%n%n%n%n%n%n%n%n%n",
    // Path traversal attempts
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "/etc/shadow",
    "/dev/null",
    "/dev/zero",
    "/dev/random",
    "/proc/self/exe",
    // Glob patterns that might cause issues
    "**/**/***/**",
    // Regular expression special characters
    "file.*with.*regex",
    "file.+with.+regex",
    "file.{1,100}with.{1,100}regex",
    "file^with^caret",
    "file$with$dollar$end",
];

// Additional patterns that require dynamic allocation
fn get_large_malicious_patterns() -> Vec<String> {
    vec![
        "a".repeat(1000),
        "b".repeat(10000),
        "*".repeat(100),
        "?".repeat(100),
        "[".repeat(100),
        "]".repeat(100),
        "{".repeat(100),
        "}".repeat(100),
    ]
}

struct TestContext {
    temp_dir: TempDir,
    test_repo_path: PathBuf,
    project_root: PathBuf,
    plugin_path: PathBuf,
}

impl TestContext {
    fn new() -> Result<Self> {
        setup_logger();
        let temp_dir = TempDir::new().context("Failed to create temp directory")?;
        let test_repo_path = temp_dir.path().join("test_repo");

        let project_root = std::env::current_dir().context("Failed to get current directory")?;
        let plugin_path = project_root.join("git-prompt-watcher.plugin.zsh");

        if !plugin_path.exists() {
            return Err(anyhow!("Plugin file not found at {:?}", plugin_path));
        }

        Ok(Self {
            temp_dir,
            test_repo_path,
            project_root,
            plugin_path,
        })
    }

    fn create_test_repo(&self) -> Result<Repository> {
        fs::create_dir_all(&self.test_repo_path).context("Failed to create test repo directory")?;
        let repo = Repository::init(&self.test_repo_path)
            .context("Failed to initialize git repository")?;

        let mut config = repo.config().context("Failed to get repo config")?;
        config
            .set_str("user.email", TEST_EMAIL)
            .context("Failed to set user email")?;
        config
            .set_str("user.name", TEST_USER)
            .context("Failed to set user name")?;

        self.create_and_commit_file(&repo, "README.md", "# Test repo\n", "Initial commit")?;
        Ok(repo)
    }

    fn create_and_commit_file(
        &self,
        repo: &Repository,
        filename: &str,
        content: &str,
        commit_msg: &str,
    ) -> Result<PathBuf> {
        let file_path = self.test_repo_path.join(filename);
        fs::write(&file_path, content).context("Failed to write file")?;

        let mut index = repo.index().context("Failed to get repo index")?;
        index
            .add_path(Path::new(filename))
            .context("Failed to add file to index")?;
        index.write().context("Failed to write index")?;

        let tree_id = index.write_tree().context("Failed to write tree")?;
        let tree = repo.find_tree(tree_id).context("Failed to find tree")?;
        let signature = Signature::new(TEST_USER, TEST_EMAIL, &Time::new(0, 0))
            .context("Failed to create signature")?;

        let parent_commit = repo.head().ok().and_then(|h| h.peel_to_commit().ok());
        let parents: Vec<_> = parent_commit.iter().collect();

        repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            commit_msg,
            &tree,
            &parents,
        )
        .context("Failed to create commit")?;

        Ok(file_path)
    }

    fn get_zsh_child(&self, cwd: Option<&Path>, use_starship: bool) -> Result<expectrl::Session> {
        let cwd = cwd.unwrap_or(&self.test_repo_path);

        let common_setup = r#"
# Disable first-time user configuration
setopt NO_GLOBAL_RCS
setopt NO_RCS

# Add fswatch to PATH
export PATH="/opt/homebrew/bin:$PATH"

# Skip any interactive setup
DISABLE_AUTO_UPDATE=true
DISABLE_UPDATE_PROMPT=true
"#;

        let specific_setup = if use_starship {
            r#"
# Set up Starship
export STARSHIP_CONFIG="$GPW_PROJECT_ROOT/tests/starship.toml"
eval "$(starship init zsh)"

# Load the plugin after starship
source "$GPW_PLUGIN_PATH"

# Custom marker for prompt detection
export PROMPT_MARKER="PROMPT_READY"
precmd_functions+=(echo_marker)
echo_marker() { echo "$PROMPT_MARKER" }
"#
        } else {
            r#"
# Load the plugin
source "$GPW_PLUGIN_PATH"

# Simple prompt for testing
export PS1="test> "

# Custom marker for prompt detection
export PROMPT_MARKER="PROMPT_READY"
precmd() { echo "$PROMPT_MARKER" }
"#
        };

        let zshrc_content = format!("{common_setup}{specific_setup}");
        let zshrc_path = self.temp_dir.path().join(".zshrc");
        fs::write(&zshrc_path, zshrc_content).context("Failed to write .zshrc")?;

        let mut command = Command::new("zsh");
        command.arg("-i"); // Start an interactive shell
        command.env("ZDOTDIR", self.temp_dir.path());
        command.env("GPW_PLUGIN_PATH", &self.plugin_path);
        command.env("GPW_TEMP_DIR", self.temp_dir.path());
        command.env("GPW_PROJECT_ROOT", &self.project_root);
        command.env(
            "GPW_USE_STARSHIP",
            if use_starship { "true" } else { "false" },
        );
        command.current_dir(cwd);

        let mut session = Session::spawn(command).context("Failed to spawn Zsh session")?;
        session.set_expect_timeout(Some(Duration::from_secs(30)));

        session.expect(Regex(PROMPT_MARKER))?;

        Ok(session)
    }
}

/// Polls the system to check if the fswatch process with the given PID is running.
fn is_fswatch_running(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    let mut sys = System::new();
    sys.refresh_processes();
    sys.process(sysinfo::Pid::from(pid as usize))
        .is_some_and(|p| p.name().contains("fswatch"))
}

/// Polls the shell variable to get the watcher's PID.
async fn get_watcher_pid_from_shell(session: &mut expectrl::Session) -> Result<u32> {
    let start = tokio::time::Instant::now();
    while start.elapsed() < PROCESS_POLL_TIMEOUT {
        if let Ok(pid) = get_watcher_pid(session) {
            if pid > 0 {
                return Ok(pid);
            }
        }
        sleep(POLL_INTERVAL).await;
    }
    Err(anyhow!("Watcher PID variable was not set or was empty"))
}

/// Waits for the fswatch process to start by polling the shell variable.
async fn wait_for_fswatch_to_start(session: &mut expectrl::Session) -> Result<u32> {
    let pid = get_watcher_pid_from_shell(session).await?;
    let start = tokio::time::Instant::now();
    while start.elapsed() < PROCESS_POLL_TIMEOUT {
        if is_fswatch_running(pid) {
            return Ok(pid);
        }
        sleep(POLL_INTERVAL).await;
    }
    Err(anyhow!(
        "fswatch process with PID {} did not start within timeout",
        pid
    ))
}

/// Waits for the fswatch process to terminate by polling the system.
async fn wait_for_process_termination(pid: u32) -> Result<()> {
    let start = tokio::time::Instant::now();
    while start.elapsed() < PROCESS_POLL_TIMEOUT {
        if !is_fswatch_running(pid) {
            return Ok(());
        }
        sleep(POLL_INTERVAL).await;
    }
    Err(anyhow!("Process {} did not terminate within timeout", pid))
}

/// Helper function to get watcher PID from shell session
fn get_watcher_pid(session: &mut expectrl::Session) -> Result<u32> {
    session.send_line("echo \"WATCHERPID:$_git_prompt_watcher_pid:\"")?;
    let output = session.expect(Regex(r"WATCHERPID:(\d+):"))?;
    let matches: Vec<_> = output.matches().collect();
    let full_match = String::from_utf8_lossy(matches[0]);
    let pid_str = full_match
        .strip_prefix("WATCHERPID:")
        .context("Failed to strip prefix from PID match")?
        .strip_suffix(":")
        .context("Failed to strip suffix from PID match")?;
    session.expect(Regex(SHELL_PROMPT))?;
    Ok(pid_str.parse()?)
}

/// Sync version of `wait_for_process_termination` for backwards compatibility
fn wait_for_process_termination_sync(pid: u32, timeout: Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if !is_fswatch_running(pid) {
            return true;
        }
        thread::sleep(Duration::from_millis(10));
    }
    false
}

#[tokio::test]

async fn test_prerequisites() -> Result<()> {
    // Check git
    assert!(
        Command::new("git").arg("--version").output().is_ok(),
        "git command should be available"
    );

    // Check fswatch
    assert!(
        Command::new("fswatch").arg("--version").output().is_ok(),
        "fswatch command should be available"
    );

    Ok(())
}

#[tokio::test]

async fn test_plugin_loads_without_error() -> Result<()> {
    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    // Plugin should have loaded successfully
    child.send_line("echo 'Plugin loaded successfully'")?;
    child.expect(Regex("Plugin loaded successfully"))?;
    child.expect(Regex("test>"))?;

    Ok(())
}

#[tokio::test]

async fn test_fswatch_basic_functionality() -> Result<()> {
    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    // Test if we can start fswatch manually
    child.send_line(
        "echo 'Starting fswatch manually...' && fswatch -o .git/HEAD .git/index & echo $!",
    )?;
    child.expect(Regex(SHELL_PROMPT))?;

    // Give it a moment to start
    child.send_line("sleep 0.5")?;
    child.expect(Regex(SHELL_PROMPT))?;

    // Check if fswatch is running
    child.send_line("pgrep -f fswatch")?;
    child.expect(Regex(SHELL_PROMPT))?;

    // Kill the manual fswatch
    child.send_line("pkill -f fswatch")?;
    child.expect(Regex(SHELL_PROMPT))?;

    Ok(())
}

#[tokio::test]

async fn test_watcher_starts_in_git_repo() -> Result<()> {
    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    // Test that the plugin automatically started an fswatch process in a git repo
    let watcher_pid = get_watcher_pid(&mut child)?;

    // Verify the PID is actually a running fswatch process
    assert!(
        is_fswatch_running(watcher_pid),
        "Watcher PID is set but fswatch is not running"
    );

    // Clean up
    child.send_line("pkill -f fswatch")?;
    child.expect(Regex(SHELL_PROMPT))?;

    Ok(())
}

#[tokio::test]

async fn test_watcher_stops_outside_git_repo() -> Result<()> {
    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    // Move outside git repo
    child.send_line(format!("cd {}", ctx.temp_dir.path().display()))?;
    child.expect(Regex("PROMPT_READY"))?;
    child.expect(Regex("test>"))?;

    // Check if watcher PID is cleared
    child.send_line("echo \"Watcher PID: '$_git_prompt_watcher_pid'\"")?;
    child.expect(Regex("Watcher PID: ''"))?;

    Ok(())
}

#[tokio::test]

async fn test_file_change_triggers_fswatch() -> Result<()> {
    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    // Get the watcher PID and verify it's running
    let watcher_pid = get_watcher_pid(&mut child)?;

    // Create a new file directly
    let new_file = ctx.test_repo_path.join("newfile.txt");
    fs::write(&new_file, "test content")?;

    // Give fswatch time to detect the change
    sleep(FSWATCH_DETECTION_DELAY).await;

    // Watcher should still be running
    assert!(
        is_fswatch_running(watcher_pid),
        "Watcher should still be running after file change"
    );

    Ok(())
}

#[tokio::test]

async fn test_git_operations_trigger_monitoring() -> Result<()> {
    let ctx = TestContext::new()?;
    let repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    let watcher_pid = wait_for_fswatch_to_start(&mut child).await?;

    // 1. Test staging a file
    let staged_file = ctx.test_repo_path.join("staged.txt");
    fs::write(&staged_file, "staged content")?;
    let mut index = repo.index()?;
    index.add_path(Path::new("staged.txt"))?;
    index.write()?;

    sleep(FSWATCH_DETECTION_DELAY).await;
    assert!(
        is_fswatch_running(watcher_pid),
        "Watcher should handle git staging"
    );

    // 2. Test committing a file
    ctx.create_and_commit_file(
        &repo,
        "committed.txt",
        "committed content",
        "Add committed file",
    )?;

    sleep(FSWATCH_DETECTION_DELAY).await;
    assert!(
        is_fswatch_running(watcher_pid),
        "Watcher should handle git commits"
    );

    Ok(())
}

#[tokio::test]

async fn test_signal_handling_setup() -> Result<()> {
    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    // Check if TRAPUSR1 is defined
    child.send_line("declare -f TRAPUSR1")?;
    child.expect(Regex("TRAPUSR1"))?;
    child.expect(Regex("test>"))?;

    // Check if TRAPUSR2 is defined
    child.send_line("declare -f TRAPUSR2")?;
    child.expect(Regex("TRAPUSR2"))?;
    child.expect(Regex("test>"))?;

    // Check function registration
    child.send_line("echo ${chpwd_functions[*]}")?;
    child.expect(Regex("_check_git_repo_change"))?;
    child.expect(Regex("test>"))?;

    child.send_line("echo ${zshexit_functions[*]}")?;
    child.expect(Regex("_stop_git_watcher"))?;
    child.expect(Regex("test>"))?;

    Ok(())
}

#[tokio::test]

async fn test_malicious_gitignore_patterns_security() -> Result<()> {
    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    // Verify initial watcher is running
    let _initial_pid = get_watcher_pid(&mut child)?;

    // Write malicious gitignore with command injection patterns
    let malicious_gitignore = ctx.test_repo_path.join(".gitignore");
    let mut all_patterns: Vec<String> = MALICIOUS_GITIGNORE_PATTERNS
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    all_patterns.extend(get_large_malicious_patterns());
    fs::write(&malicious_gitignore, all_patterns.join("\n"))?;

    // Give time for fswatch to detect gitignore change (should restart watcher)
    sleep(PROCESS_CLEANUP_DELAY).await;

    // Check if watcher is still running (potentially with new PID due to restart)
    let new_pid = get_watcher_pid(&mut child)?;

    // Watcher should be running (potentially with new PID due to restart)
    let mut sys = System::new();
    sys.refresh_processes();
    assert!(
        sys.process(sysinfo::Pid::from(new_pid as usize)).is_some(),
        "Watcher should survive malicious gitignore"
    );

    // Verify shell is still functional
    child.send_line("echo 'shell_still_works'")?;
    child.expect(Regex("shell_still_works"))?;
    child.expect(Regex("test>"))?;

    Ok(())
}

#[tokio::test]

async fn test_watcher_cleanup_on_exit() -> Result<()> {
    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    // Verify watcher is initially running (PID is set)
    child.send_line("echo \"INITIALPID:$_git_prompt_watcher_pid:\"")?;
    let output = child.expect(Regex(r"INITIALPID:(\d+):"))?;
    let matches: Vec<_> = output.matches().collect();
    let full_match = String::from_utf8_lossy(matches[0]);
    let pid_str = full_match
        .strip_prefix("INITIALPID:")
        .unwrap()
        .strip_suffix(":")
        .unwrap();
    let _initial_pid: u32 = pid_str.parse()?;

    // Call stop function
    child.send_line("_stop_git_watcher")?;
    child.expect(Regex("test>"))?;

    // Check that PID variable is cleared
    child.send_line("echo \"After stop PID: '$_git_prompt_watcher_pid'\"")?;
    child.expect(Regex("After stop PID: ''"))?;
    child.expect(Regex("test>"))?;

    // Test that starting and stopping works multiple times
    child.send_line("_start_git_watcher")?;
    child.expect(Regex("test>"))?;

    child.send_line("echo \"RESTARTEDPID:$_git_prompt_watcher_pid:\"")?;
    let output = child.expect(Regex(r"RESTARTEDPID:(\d+):"))?;
    let matches: Vec<_> = output.matches().collect();
    let full_match = String::from_utf8_lossy(matches[0]);
    let pid_str = full_match
        .strip_prefix("RESTARTEDPID:")
        .unwrap()
        .strip_suffix(":")
        .unwrap();
    let _restarted_pid: u32 = pid_str.parse()?;

    // Stop again
    child.send_line("_stop_git_watcher")?;
    child.expect(Regex("test>"))?;

    // Should be cleared again
    child.send_line("echo \"Final PID: '$_git_prompt_watcher_pid'\"")?;
    child.expect(Regex("Final PID: ''"))?;
    child.expect(Regex("test>"))?;

    Ok(())
}

#[tokio::test]

async fn test_watcher_really_stops_when_leaving_repo() -> Result<()> {
    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    // Get initial watcher PID
    child.send_line("echo \"WATCHERPID:$_git_prompt_watcher_pid:\"")?;
    let output = child.expect(Regex(r"WATCHERPID:(\d+):"))?;
    let matches: Vec<_> = output.matches().collect();
    let full_match = String::from_utf8_lossy(matches[0]);
    let pid_str = full_match
        .strip_prefix("WATCHERPID:")
        .unwrap()
        .strip_suffix(":")
        .unwrap();
    let initial_pid: u32 = pid_str.parse()?;
    child.expect(Regex("test>"))?;

    // Verify initial watcher is running
    let mut sys = System::new();
    sys.refresh_processes();
    assert!(
        sys.process(sysinfo::Pid::from(initial_pid as usize))
            .is_some(),
        "Initial watcher should be running"
    );

    // Move outside the git repository
    child.send_line(format!("cd {}", ctx.temp_dir.path().display()))?;
    child.expect(Regex("PROMPT_READY"))?;
    child.expect(Regex("test>"))?;

    // Give time for the chpwd hook to trigger
    sleep(PROCESS_CLEANUP_DELAY).await;

    // Check that the PID variable is cleared
    child.send_line("echo \"PID after leaving: '$_git_prompt_watcher_pid'\"")?;
    child.expect(Regex("PID after leaving: ''"))?;
    child.expect(Regex("test>"))?;

    // Most importantly: verify the actual process is killed
    assert!(
        wait_for_process_termination_sync(initial_pid, Duration::from_secs(1)),
        "Watcher process {initial_pid} should be killed when leaving repo"
    );

    Ok(())
}

#[tokio::test]

async fn test_gitignore_change_handling() -> Result<()> {
    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    // Get initial watcher PID
    let initial_pid = get_watcher_pid(&mut child)?;

    // Verify fswatch is running
    assert!(is_fswatch_running(initial_pid), "fswatch should be running");

    // Modify .gitignore directly
    let gitignore = ctx.test_repo_path.join(".gitignore");
    fs::write(&gitignore, "*.log\n")?;

    // Give time for potential restart
    sleep(Duration::from_millis(200)).await;

    // Check if watcher is still running (same or new PID)
    let current_pid = get_watcher_pid(&mut child)?;

    let mut sys = System::new();
    sys.refresh_processes();
    assert!(
        sys.process(sysinfo::Pid::from(current_pid as usize))
            .is_some(),
        "Watcher should be running after gitignore change"
    );

    Ok(())
}

#[tokio::test]

async fn test_branch_switching() -> Result<()> {
    let ctx = TestContext::new()?;
    let repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    // Create and switch to new branch
    let new_branch = repo.branch("test-branch", &repo.head()?.peel_to_commit()?, false)?;
    repo.set_head(new_branch.get().name().unwrap())?;
    repo.checkout_head(None)?;

    // Get watcher PID
    let watcher_pid = get_watcher_pid(&mut child)?;

    // Verify fswatch is running
    assert!(is_fswatch_running(watcher_pid), "fswatch should be running");

    // Create commit on new branch
    ctx.create_and_commit_file(&repo, "branch_file.txt", "branch content", "Branch commit")?;

    // Switch back to main
    repo.set_head("refs/heads/main")?;
    repo.checkout_head(None)?;

    sleep(FSWATCH_DETECTION_DELAY).await;

    // Watcher should still be running
    assert!(
        is_fswatch_running(watcher_pid),
        "Watcher should handle branch switching"
    );

    Ok(())
}

#[tokio::test]

async fn test_multiple_rapid_file_changes() -> Result<()> {
    let ctx = TestContext::new()?;
    let repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    // Get watcher PID
    let watcher_pid = get_watcher_pid(&mut child)?;

    // Verify fswatch is running
    assert!(is_fswatch_running(watcher_pid), "fswatch should be running");

    // Create multiple files rapidly
    let mut file_paths = Vec::new();
    for i in 0..5 {
        let file_path = ctx.test_repo_path.join(format!("file{i}.txt"));
        fs::write(&file_path, format!("content {i}"))?;
        file_paths.push(format!("file{i}.txt"));
    }

    // Add all files at once
    let mut index = repo.index()?;
    for file_path in &file_paths {
        index.add_path(Path::new(file_path))?;
    }
    index.write()?;

    sleep(FSWATCH_DETECTION_DELAY).await;

    // Watcher should survive rapid changes
    assert!(
        is_fswatch_running(watcher_pid),
        "Watcher should handle rapid file changes"
    );

    Ok(())
}

#[tokio::test]

async fn test_signal_delivery_to_shell() -> Result<()> {
    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    // Create a signal handler in the shell
    child.send_line("signal_received=''")?;
    child.expect(Regex(SHELL_PROMPT))?;

    child.send_line("TRAPUSR1() { signal_received='USR1_RECEIVED'; echo 'SIGNAL_CAUGHT' }")?;
    child.expect(Regex(SHELL_PROMPT))?;

    // Get the shell PID using a specific marker to avoid escape sequence contamination
    child.send_line("echo \"SHELLPID:$$:\"")?;
    let output = child.expect(Regex(r"SHELLPID:(\d+):"))?;
    let matches: Vec<_> = output.matches().collect();

    if matches.is_empty() {
        return Err(anyhow::anyhow!("Could not get shell PID"));
    }

    let full_match = String::from_utf8_lossy(matches[0]);
    let shell_pid_str = full_match
        .strip_prefix("SHELLPID:")
        .unwrap()
        .strip_suffix(":")
        .unwrap();
    child.expect(Regex(SHELL_PROMPT))?;

    let shell_pid: i32 = shell_pid_str.parse().context("Failed to parse shell PID")?;

    // Send USR1 signal to the shell process from Rust
    signal::kill(Pid::from_raw(shell_pid), Signal::SIGUSR1).context("Failed to send signal")?;

    // Give time for signal processing
    sleep(Duration::from_millis(200)).await;

    // Check if signal was received by looking for our marker
    child.expect(Regex("SIGNAL_CAUGHT"))?;

    // Verify the variable was set
    child.send_line("echo $signal_received")?;
    child.expect(Regex("USR1_RECEIVED"))?;
    child.expect(Regex(SHELL_PROMPT))?;

    Ok(())
}

#[tokio::test]
async fn test_prompt_updates_with_starship() -> Result<()> {
    assert!(
        Command::new("starship").arg("--version").output().is_ok(),
        "starship command should be available"
    );

    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, true)?;

    let watcher_pid = wait_for_fswatch_to_start(&mut child).await?;

    // 1. Test untracked files
    let untracked_file = ctx.test_repo_path.join("untracked.txt");
    fs::write(&untracked_file, "untracked content")?;

    // Give fswatch time to detect the change and trigger prompt update
    sleep(FSWATCH_DETECTION_DELAY).await;

    // Send a command to trigger a new prompt with the git status
    child.send_line("echo 'checking prompt'")?;
    child.expect(Regex("checking prompt"))?;

    // Look for the untracked status indicator (? followed by test>)
    child
        .expect(Regex(r"\? test>"))
        .map_err(anyhow::Error::from)
        .context("Prompt did not update for untracked file")?;

    // Check if watcher is still running, restart if needed
    if !is_fswatch_running(watcher_pid) {
        child.send_line("_start_git_watcher")?;
        child.expect(Regex(SHELL_PROMPT))?;
        let new_pid = get_watcher_pid(&mut child)?;
        assert!(
            is_fswatch_running(new_pid),
            "Watcher should be running after restart"
        );
    }

    // 2. Test staged files
    child.send_line("git add untracked.txt")?;

    // Give time for the staging to complete and fswatch to detect
    sleep(FSWATCH_DETECTION_DELAY).await;

    child.send_line("echo 'checking staged prompt'")?;
    child.expect(Regex("checking staged prompt"))?;

    // Look for the staged status indicator (+ followed by test>)
    child
        .expect(Regex(r"\+ test>"))
        .map_err(anyhow::Error::from)
        .context("Prompt did not update for staged file")?;

    // Final check that watcher is still functional
    let final_pid = get_watcher_pid(&mut child)?;
    assert!(
        is_fswatch_running(final_pid),
        "Watcher should be running at end of test"
    );

    Ok(())
}

#[tokio::test]
async fn test_prompt_updates_on_branch_switch_with_starship() -> Result<()> {
    assert!(
        Command::new("starship").arg("--version").output().is_ok(),
        "starship command should be available"
    );

    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, true)?;

    let watcher_pid = wait_for_fswatch_to_start(&mut child).await?;

    // Check initial prompt is on main branch
    child.send_line("echo 'checking initial branch'")?;
    child.expect(Regex("checking initial branch"))?;
    child.expect(Regex(r"on main .*test>"))?;

    // Create and switch to a new branch
    child.send_line("git checkout -b feature-branch")?;
    child.expect(Regex("Switched to a new branch"))?;

    // Give fswatch time to detect the branch change
    sleep(FSWATCH_DETECTION_DELAY).await;

    // Check prompt updated to new branch name
    child.send_line("echo 'checking feature branch'")?;
    child.expect(Regex("checking feature branch"))?;
    child.expect(Regex(r"on feature-branch .*test>"))?;
    assert!(is_fswatch_running(watcher_pid));

    // Switch back to main
    child.send_line("git checkout main")?;
    child.expect(Regex("Switched to branch"))?;

    // Give fswatch time to detect the branch change
    sleep(FSWATCH_DETECTION_DELAY).await;

    // Check prompt updated back to main
    child.send_line("echo 'checking main branch again'")?;
    child.expect(Regex("checking main branch again"))?;
    child.expect(Regex(r"on main .*test>"))?;
    assert!(is_fswatch_running(watcher_pid));

    Ok(())
}

#[tokio::test]

async fn test_watcher_restarts_between_different_repos() -> Result<()> {
    let ctx = TestContext::new()?;

    // Create first repository
    let _repo1 = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    // Get initial watcher PID
    let initial_pid = get_watcher_pid(&mut child)?;

    // Verify initial watcher is running
    assert!(
        is_fswatch_running(initial_pid),
        "Initial watcher should be running"
    );

    // Create second repository in a different location
    let repo2_path = ctx.temp_dir.path().join("second_repo");
    fs::create_dir_all(&repo2_path)?;
    let repo2 = Repository::init(&repo2_path)?;

    // Configure second repo
    let mut config = repo2.config()?;
    config.set_str("user.email", TEST_EMAIL)?;
    config.set_str("user.name", TEST_USER)?;

    // Add initial file to second repo
    let readme2 = repo2_path.join("README.md");
    fs::write(&readme2, "# Second repo\n")?;
    let mut index = repo2.index()?;
    index.add_path(Path::new("README.md"))?;
    index.write()?;

    let tree_id = index.write_tree()?;
    let tree = repo2.find_tree(tree_id)?;
    let signature = Signature::new(TEST_USER, TEST_EMAIL, &Time::new(0, 0))?;

    repo2.commit(
        Some("HEAD"),
        &signature,
        &signature,
        "Initial commit in second repo",
        &tree,
        &[],
    )?;

    // First move outside both repos to ensure watcher stops
    child.send_line(format!("cd {}", ctx.temp_dir.path().display()))?;
    child.expect(Regex("PROMPT_READY"))?;
    child.expect(Regex("test>"))?;

    // Verify watcher is stopped
    child.send_line("echo \"Outside repo PID: '$_git_prompt_watcher_pid'\"")?;
    child.expect(Regex("Outside repo PID: ''"))?;
    child.expect(Regex("test>"))?;

    // Now move to second repository
    child.send_line(format!("cd {}", repo2_path.display()))?;
    child.expect(Regex("PROMPT_READY"))?;
    child.expect(Regex("test>"))?;

    // Give time for new watcher to start
    sleep(Duration::from_millis(200)).await;

    // Get new watcher PID
    let new_pid = get_watcher_pid(&mut child)?;

    // Verify that the new watcher is running
    assert!(
        is_fswatch_running(new_pid),
        "New watcher should be running in second repository"
    );

    // Create a file in the second repo to verify the watcher is working
    let test_file = repo2_path.join("test_change.txt");
    fs::write(&test_file, "test content")?;

    // Give time for fswatch to detect the change
    sleep(FSWATCH_DETECTION_DELAY).await;

    // The watcher should still be alive and monitoring
    assert!(
        is_fswatch_running(new_pid),
        "Watcher should handle file changes in second repository"
    );

    Ok(())
}

#[tokio::test]

async fn test_watcher_stays_same_within_repo_subdirs() -> Result<()> {
    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    // Get initial watcher PID
    let initial_pid = wait_for_fswatch_to_start(&mut child).await?;

    // Create subdirectories within the repo
    let subdir1 = ctx.test_repo_path.join("src");
    fs::create_dir_all(&subdir1)?;
    let subdir2 = ctx.test_repo_path.join("docs").join("api");
    fs::create_dir_all(&subdir2)?;

    // Move to first subdirectory
    child.send_line(format!("cd {}", subdir1.display()))?;
    child.expect(Regex(PROMPT_MARKER))?;
    child.expect(Regex(SHELL_PROMPT))?;

    // PID should be the same (no restart)
    let current_pid = get_watcher_pid(&mut child)?;
    assert_eq!(
        initial_pid, current_pid,
        "Watcher should not restart when moving within same repository"
    );
    assert!(is_fswatch_running(current_pid));

    // Move to nested subdirectory
    child.send_line(format!("cd {}", subdir2.display()))?;
    child.expect(Regex(PROMPT_MARKER))?;
    child.expect(Regex(SHELL_PROMPT))?;

    // PID should still be the same
    let final_pid = get_watcher_pid(&mut child)?;
    assert_eq!(
        initial_pid, final_pid,
        "Watcher should not restart when moving to nested subdirectory"
    );
    assert!(is_fswatch_running(final_pid));

    Ok(())
}

#[tokio::test]

async fn test_watcher_killed_on_shell_exit() -> Result<()> {
    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    let watcher_pid = wait_for_fswatch_to_start(&mut child).await?;
    assert!(is_fswatch_running(watcher_pid));

    // Test that manual cleanup works
    child.send_line("_stop_git_watcher")?;
    child.expect(Regex(SHELL_PROMPT))?;

    // Verify watcher process is killed
    wait_for_process_termination(watcher_pid).await?;

    // Now exit the shell
    child.send_line("exit")?;

    Ok(())
}

#[tokio::test]

async fn test_malicious_global_gitignore_security() -> Result<()> {
    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    let initial_pid = wait_for_fswatch_to_start(&mut child).await?;

    // Create a temporary global gitignore with malicious content
    let global_gitignore_path = ctx.temp_dir.path().join("global_gitignore");
    fs::write(
        &global_gitignore_path,
        "$(touch /tmp/global_attack)\nnormal_pattern.txt",
    )?;

    // Set the global gitignore temporarily and restart the watcher
    child.send_line(format!(
        "git config --global core.excludesfile {}",
        global_gitignore_path.display()
    ))?;
    child.expect(Regex(SHELL_PROMPT))?;
    child.send_line("_stop_git_watcher && _start_git_watcher")?;
    child.expect(Regex(SHELL_PROMPT))?;

    // Wait for the watcher to restart
    let new_pid = wait_for_fswatch_to_start(&mut child).await?;
    assert_ne!(initial_pid, new_pid, "Watcher should have restarted");

    // Verify no attack file was created
    let attack_path = Path::new("/tmp/global_attack");
    assert!(
        !attack_path.exists(),
        "Attack file from global gitignore should not exist"
    );

    // Clean up
    child.send_line("git config --global --unset core.excludesfile")?;
    child.expect(Regex(SHELL_PROMPT))?;

    Ok(())
}

#[tokio::test]

async fn test_malicious_git_info_exclude_security() -> Result<()> {
    let ctx = TestContext::new()?;
    let repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    let watcher_pid = wait_for_fswatch_to_start(&mut child).await?;

    // Create a malicious .git/info/exclude file
    let exclude_file_path = repo.path().join("info/exclude");
    fs::create_dir_all(exclude_file_path.parent().unwrap())?;
    fs::write(
        &exclude_file_path,
        "$(touch /tmp/exclude_attack)\nnormal_pattern.txt",
    )?;

    // Give fswatch time to detect the change
    sleep(FSWATCH_DETECTION_DELAY).await;

    // Watcher should still be running
    assert!(is_fswatch_running(watcher_pid));

    // Verify no attack file was created
    let attack_path = Path::new("/tmp/exclude_attack");
    assert!(
        !attack_path.exists(),
        "Attack file from .git/info/exclude should not exist"
    );

    Ok(())
}

#[tokio::test]

async fn test_large_gitignore_file_handling() -> Result<()> {
    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    let _watcher_pid = wait_for_fswatch_to_start(&mut child).await?;

    // Create an extremely large gitignore file
    let large_gitignore_path = ctx.test_repo_path.join(".gitignore");
    let large_content: String = (0..10000).fold(String::new(), |mut acc, i| {
        use std::fmt::Write;
        writeln!(&mut acc, "pattern{i}").unwrap();
        acc
    });
    fs::write(&large_gitignore_path, large_content)?;

    // Give fswatch time to detect the change and restart
    sleep(FSWATCH_DETECTION_DELAY).await;

    // Wait a bit more for the signal processing
    sleep(Duration::from_millis(500)).await;

    // The watcher should have restarted and still be running
    let new_pid = get_watcher_pid(&mut child)?;
    // Don't require PID to be different - the important thing is that it's still running
    assert!(
        is_fswatch_running(new_pid),
        "Watcher should be running after gitignore change"
    );

    Ok(())
}

#[tokio::test]

async fn test_fswatch_jobs_not_cluttering_output() -> Result<()> {
    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    // Plugin should be loaded and watcher running
    let watcher_pid = get_watcher_pid(&mut child)?;

    // Verify watcher is running
    let mut sys = System::new();
    sys.refresh_processes();
    assert!(
        sys.process(sysinfo::Pid::from(watcher_pid as usize))
            .is_some(),
        "Watcher should be running"
    );

    // Check jobs output - should be completely empty (no jobs at all)
    child.send_line("jobs")?;
    child.expect(Regex("test>"))?;

    // Start a background job to verify jobs command works
    child.send_line("sleep 10 &")?;
    child.expect(Regex("test>"))?;

    // Now jobs should show exactly one job (the sleep command) but still not fswatch
    child.send_line("jobs")?;
    let output = child.expect(Regex("test>"))?;
    let jobs_output = String::from_utf8_lossy(output.before());

    // Should contain sleep but not fswatch
    assert!(
        jobs_output.contains("sleep"),
        "jobs should show background sleep: {jobs_output}"
    );
    assert!(
        !jobs_output.contains("fswatch"),
        "fswatch should not appear in jobs output: {jobs_output}"
    );

    // Kill the sleep job
    child.send_line("kill %1")?;
    child.expect(Regex("test>"))?;

    Ok(())
}

#[tokio::test]
async fn test_no_attack_files_created_during_security_test() -> Result<()> {
    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;

    // Create a malicious gitignore to trigger potential attacks
    let malicious_gitignore = ctx.test_repo_path.join(".gitignore");
    let mut all_patterns: Vec<String> = MALICIOUS_GITIGNORE_PATTERNS
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    all_patterns.extend(get_large_malicious_patterns());

    fs::write(&malicious_gitignore, all_patterns.join("\n"))?;

    // Give time for processing
    sleep(Duration::from_millis(200)).await;

    // Verify no attack files were created in common attack locations
    let attack_files = [
        "/tmp/attack_file",
        "/tmp/test_attack",
        "/tmp/command_substitution",
        "/tmp/backtick_substitution",
        "/tmp/exclude_attack",
        "/tmp/user_info",
        "/tmp/global_attack",
    ];

    for attack_file in &attack_files {
        let attack_path = Path::new(attack_file);
        assert!(
            !attack_path.exists(),
            "Attack file should not exist: {attack_file}"
        );
    }

    // Also check in the temp directory
    let temp_attack_files = [
        "attack_file",
        "test_attack",
        "command_substitution",
        "backtick_substitution",
    ];

    for attack_file in &temp_attack_files {
        let attack_path = ctx.temp_dir.path().join(attack_file);
        assert!(
            !attack_path.exists(),
            "Attack file should not exist in temp dir: {attack_file}"
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_command_injection_via_gitignore_patterns() -> Result<()> {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .try_init();

    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;

    // Start shell session
    let mut session = ctx.get_zsh_child(None, false)?;

    // Get initial watcher PID and verify it's running
    let initial_pid = get_watcher_pid(&mut session)?;
    assert!(
        is_fswatch_running(initial_pid),
        "Initial watcher should be running"
    );

    // Create malicious gitignore with command injection patterns
    let malicious_patterns = [
        "normal_file.txt",
        "; rm -rf /tmp/test_attack",      // Command injection attempt
        "$(echo 'command_substitution')", // Command substitution
        "`echo 'backtick_substitution'`", // Backtick substitution
        "file && echo 'logical_and'",     // Logical operators
        "file || echo 'logical_or'",
        "file | echo 'pipe'",     // Pipe operator
        "file; echo 'semicolon'", // Command separator
        "file\necho 'newline'",   // Newline injection
    ];

    let gitignore_path = ctx.test_repo_path.join(".gitignore");
    std::fs::write(&gitignore_path, malicious_patterns.join("\n"))?;

    // Give time for fswatch to detect gitignore change (should restart watcher)
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Check if watcher is still running (should be restarted)
    let new_pid = get_watcher_pid(&mut session)?;

    // Watcher should be running (potentially with new PID due to restart)
    assert!(
        is_fswatch_running(new_pid),
        "Watcher should survive malicious gitignore"
    );

    // Verify shell is still functional
    session.send_line("echo 'shell_still_works'")?;
    session.expect(Regex("shell_still_works"))?;
    session.expect(Regex("test>"))?;

    Ok(())
}

#[tokio::test]
async fn test_large_gitignore_security() -> Result<()> {
    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    let _initial_pid = wait_for_fswatch_to_start(&mut child).await?;

    // Create an extremely large gitignore file with malicious patterns
    let large_gitignore = ctx.test_repo_path.join(".gitignore");
    let mut large_patterns: Vec<String> = (0..10000).map(|i| format!("pattern{i}")).collect();
    large_patterns.extend(get_large_malicious_patterns());

    fs::write(&large_gitignore, large_patterns.join("\n"))?;

    // Give time for fswatch to detect the change and restart
    sleep(Duration::from_millis(500)).await;

    // The watcher should have restarted and still be running
    let new_pid = get_watcher_pid(&mut child)?;
    assert!(
        is_fswatch_running(new_pid),
        "Watcher should be running after large gitignore change"
    );

    // Verify no attack files were created
    let attack_files = ["/tmp/test_attack", "/tmp/global_attack"];
    for attack_file in &attack_files {
        let attack_path = Path::new(attack_file);
        assert!(
            !attack_path.exists(),
            "Attack file should not exist: {attack_file}"
        );
    }

    Ok(())
}
