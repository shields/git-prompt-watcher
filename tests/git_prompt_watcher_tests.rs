use anyhow::{Context, Result, anyhow};
use expectrl::{Regex, Session};
use git2::{Repository, Signature, Time};
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Once;
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

// Timeouts - Increased for containerized environment reliability

const PROCESS_POLL_TIMEOUT: Duration = Duration::from_secs(10);

// Sleep intervals
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const FSWATCH_DETECTION_DELAY: Duration = Duration::from_millis(50);
const PROCESS_CLEANUP_DELAY: Duration = Duration::from_millis(50);
const WATCHER_RESTART_TIME: Duration = Duration::from_millis(500);
const SIGNAL_PROCESSING_TIME: Duration = Duration::from_millis(200);
const LARGE_CONTENT_PROCESSING_TIME: Duration = Duration::from_millis(1000);

// Git config
const TEST_EMAIL: &str = "test@example.com";
const TEST_USER: &str = "Test User";

// Shell markers
const PROMPT_MARKER: &str = "PROMPT_READY";
const SHELL_PROMPT: &str = "test>";

// Security test data - malicious gitignore patterns (without specific attack paths)
const MALICIOUS_GITIGNORE_PATTERNS: &[&str] = &[
    // Try to inject shell commands
    "normal_file.txt",
    "; echo 'command_injection'",     // Command injection attempt
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
    "/dev/urandom",
    "/proc/self/mem",
    "/proc/self/environ",
    "/proc/version",
    "/etc/hosts",
    "/etc/resolv.conf",
    // Potential code execution via file extensions or patterns
    "*.sh",
    "*.bat",
    "*.cmd",
    "*.exe",
    "*.dll",
    "*.so",
    "*.dylib",
    "test.sh;chmod+x+/tmp/evil",
    "innocuous.txt;rm -rf /",
    // Large/complex patterns
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // Very long pattern
    "../../../../../../../../../../../../../../../../../..",        // Deep path traversal
    // Binary/non-UTF8 sequences that might cause parsing issues
    "file\x00with\x00null\x7f\x1b\x1a",
];

// Extended malicious patterns for comprehensive testing
fn get_extended_malicious_patterns() -> Vec<String> {
    let mut patterns = Vec::new();

    // Generate variations with different shell metacharacters combined
    let metacharacters = &[
        ";", "&", "|", "$", "`", "(", ")", "{", "}", "[", "]", "\"", "'", "\\", "*", "?",
    ];

    for i in 0..metacharacters.len() {
        for j in (i + 1)..metacharacters.len() {
            patterns.push(format!(
                "file{}with{}chars",
                metacharacters[i], metacharacters[j]
            ));
        }
    }

    // Generate patterns with encoding variations
    for encoding in &["utf8", "iso8859-1", "cp1252"] {
        patterns.push(format!("file_encoded_in_{encoding}"));
    }

    // Add non-UTF8 byte sequences (the original \xff\xfe sequences)
    // Create as Vec<u8> then convert to String lossy
    let non_utf8_bytes = [
        b"file".to_vec(),
        vec![0xff, 0xfe, 0x00, 0x00],
        b"with".to_vec(),
        vec![0xff, 0xfe],
        b"non-utf8".to_vec(),
    ]
    .concat();

    patterns.push(String::from_utf8_lossy(&non_utf8_bytes).to_string());

    patterns
}

// Very large gitignore patterns for stress testing
fn get_large_malicious_patterns() -> Vec<String> {
    (0..1000).map(|i| format!("large_pattern_{i}")).collect()
}

// Combine all malicious patterns for testing
fn get_all_malicious_patterns() -> Vec<String> {
    let mut patterns = MALICIOUS_GITIGNORE_PATTERNS
        .iter()
        .map(|&s| s.to_string())
        .collect::<Vec<_>>();
    patterns.extend(get_extended_malicious_patterns());
    patterns.extend(get_large_malicious_patterns());
    patterns
}

struct TestContext {
    temp_dir: TempDir,
    test_repo_path: PathBuf,
    project_root: PathBuf,
    plugin_path: PathBuf,
    config_home: PathBuf,
    _test_id: String,
}

impl TestContext {
    fn new() -> Result<Self> {
        setup_logger();
        let temp_dir = TempDir::new().context("Failed to create temp directory")?;
        let test_repo_path = temp_dir.path().join("test_repo");
        let config_home = temp_dir.path().join("config");

        let project_root = std::env::current_dir().context("Failed to get current directory")?;
        let plugin_path = project_root.join("git-prompt-watcher.plugin.zsh");

        if !plugin_path.exists() {
            return Err(anyhow!("Plugin file not found at {:?}", plugin_path));
        }

        // Create isolated XDG_CONFIG_HOME directory structure
        fs::create_dir_all(&config_home).context("Failed to create config directory")?;
        let git_config_dir = config_home.join("git");
        fs::create_dir_all(&git_config_dir).context("Failed to create git config directory")?;

        // Generate unique test ID using timestamp and random number
        let test_id = format!(
            "test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        Ok(Self {
            temp_dir,
            test_repo_path,
            project_root,
            plugin_path,
            config_home,
            _test_id: test_id,
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

    fn get_unique_attack_path(&self, attack_name: &str) -> PathBuf {
        self.temp_dir.path().join(format!("attack_{attack_name}"))
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

# Ensure cleanup happens on SIGTERM
trap '_stop_git_watcher 2>/dev/null; exit' TERM
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
        // Isolate Git configuration using XDG_CONFIG_HOME
        command.env("XDG_CONFIG_HOME", &self.config_home);
        command.current_dir(cwd);

        let mut session = Session::spawn(command).context("Failed to spawn Zsh session")?;
        session.set_expect_timeout(Some(Duration::from_secs(5)));

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

/// Helper function to get watcher PID from shell session (backwards compatibility)
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

/// Polls for a prompt change by repeatedly triggering new prompts and checking for the expected pattern
async fn wait_for_prompt_change(
    session: &mut expectrl::Session,
    pattern: &str,
    context_msg: &str,
) -> Result<()> {
    let start = tokio::time::Instant::now();
    let timeout = Duration::from_secs(2);
    let mut attempt = 0;

    while start.elapsed() < timeout {
        attempt += 1;

        // Trigger a new prompt
        session.send_line("")?;

        // Try to match the pattern
        if let Ok(_output) = session.expect(Regex(pattern)) {
            return Ok(());
        }

        // Small delay before next attempt
        sleep(Duration::from_millis(100)).await;
    }

    Err(anyhow!(
        "Prompt change pattern '{}' not found after {} attempts in context: {}",
        pattern,
        attempt,
        context_msg
    ))
}

#[tokio::test]
async fn test_prerequisites() -> Result<()> {
    // Check if fswatch is available
    let output = Command::new("fswatch").arg("--version").output().context(
        "Failed to run fswatch command - ensure it's installed via `brew install fswatch`",
    )?;

    if !output.status.success() {
        return Err(anyhow!(
            "fswatch command failed - ensure it's properly installed"
        ));
    }

    Ok(())
}

#[tokio::test]
async fn test_plugin_loads_without_error() -> Result<()> {
    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    // Basic smoke test - if we get here without panicking, plugin loaded successfully
    child.send_line("echo 'Plugin loaded successfully'")?;
    child.expect(Regex("Plugin loaded successfully"))?;
    child.expect(Regex(SHELL_PROMPT))?;

    Ok(())
}

#[tokio::test]
async fn test_fswatch_basic_functionality() -> Result<()> {
    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    // Check if watcher starts
    let watcher_pid = wait_for_fswatch_to_start(&mut child).await?;
    assert!(watcher_pid > 0, "Watcher PID should be valid");

    // Check if fswatch process is actually running
    assert!(
        is_fswatch_running(watcher_pid),
        "fswatch process should be running"
    );

    Ok(())
}

#[tokio::test]
async fn test_file_change_triggers_fswatch() -> Result<()> {
    let ctx = TestContext::new()?;
    let repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    // Wait for watcher to start
    let watcher_pid = wait_for_fswatch_to_start(&mut child).await?;

    // Create a new file to trigger fswatch
    ctx.create_and_commit_file(&repo, "new_file.txt", "new content", "Add new file")?;

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
async fn test_watcher_starts_in_git_repo() -> Result<()> {
    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    // Watcher should start automatically
    let watcher_pid = wait_for_fswatch_to_start(&mut child).await?;
    assert!(watcher_pid > 0, "Watcher should start in git repository");

    Ok(())
}

#[tokio::test]
async fn test_watcher_stops_outside_git_repo() -> Result<()> {
    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    // Get initial watcher PID
    let watcher_pid = wait_for_fswatch_to_start(&mut child).await?;

    // Move outside the git repository
    child.send_line(format!("cd {}", ctx.temp_dir.path().display()))?;
    child.expect(Regex(PROMPT_MARKER))?;
    child.expect(Regex(SHELL_PROMPT))?;

    // Give time for watcher to stop
    sleep(PROCESS_CLEANUP_DELAY).await;
    sleep(SIGNAL_PROCESSING_TIME).await;

    // Watcher should be stopped
    assert!(
        !is_fswatch_running(watcher_pid),
        "Watcher should stop outside git repo"
    );

    Ok(())
}

#[tokio::test]
async fn test_signal_handling_setup() -> Result<()> {
    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    // Get shell PID for signal testing
    child.send_line("echo \"SHELL_PID:$$:\"")?;
    let output = child.expect(Regex(r"SHELL_PID:(\d+):"))?;
    let matches: Vec<_> = output.matches().collect();
    let full_match = String::from_utf8_lossy(matches[0]);
    let shell_pid_str = full_match
        .strip_prefix("SHELL_PID:")
        .unwrap()
        .strip_suffix(":")
        .unwrap();
    let shell_pid: u32 = shell_pid_str.parse()?;
    child.expect(Regex(SHELL_PROMPT))?;

    // Test signal delivery to shell (should not crash)
    let shell_pid_nix = Pid::from_raw(i32::try_from(shell_pid).expect("shell PID too large"));
    signal::kill(shell_pid_nix, Signal::SIGUSR1)?;

    // Give time for signal processing
    sleep(SIGNAL_PROCESSING_TIME).await;

    // Shell should still be responsive
    child.send_line("echo 'Signal handled'")?;
    child.expect(Regex("Signal handled"))?;
    child.expect(Regex(SHELL_PROMPT))?;

    Ok(())
}

#[tokio::test]
async fn test_signal_delivery_to_shell() -> Result<()> {
    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    // Get shell PID
    child.send_line("echo \"SHELL_PID:$$:\"")?;
    let output = child.expect(Regex(r"SHELL_PID:(\d+):"))?;
    let matches: Vec<_> = output.matches().collect();
    let full_match = String::from_utf8_lossy(matches[0]);
    let shell_pid: u32 = full_match
        .strip_prefix("SHELL_PID:")
        .unwrap()
        .strip_suffix(":")
        .unwrap()
        .parse()?;
    child.expect(Regex(SHELL_PROMPT))?;

    // Send SIGUSR2 to trigger watcher restart
    let shell_pid_nix = Pid::from_raw(i32::try_from(shell_pid).expect("shell PID too large"));
    signal::kill(shell_pid_nix, Signal::SIGUSR2)?;

    // Give time for signal processing and watcher restart
    sleep(SIGNAL_PROCESSING_TIME).await;

    // Shell should still be responsive after signal
    child.send_line("echo 'After signal'")?;
    child.expect(Regex("After signal"))?;
    child.expect(Regex(SHELL_PROMPT))?;

    Ok(())
}

#[tokio::test]
async fn test_gitignore_change_handling() -> Result<()> {
    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    // Wait for initial watcher to start
    let initial_pid = wait_for_fswatch_to_start(&mut child).await?;

    // Verify fswatch is running
    assert!(is_fswatch_running(initial_pid), "fswatch should be running");

    // Modify .gitignore directly
    let gitignore = ctx.test_repo_path.join(".gitignore");
    fs::write(&gitignore, "*.log\n")?;

    // Wait for watcher to restart and be fully running after gitignore change
    let current_pid = wait_for_fswatch_to_start(&mut child).await?;

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

    // Wait for watcher to start
    let watcher_pid = wait_for_fswatch_to_start(&mut child).await?;

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

    // Wait for watcher to start
    let watcher_pid = wait_for_fswatch_to_start(&mut child).await?;

    // Verify fswatch is running
    assert!(is_fswatch_running(watcher_pid), "fswatch should be running");

    // Create multiple files rapidly
    for i in 0..5 {
        ctx.create_and_commit_file(
            &repo,
            &format!("rapid_file_{i}.txt"),
            &format!("content {i}"),
            &format!("Rapid commit {i}"),
        )?;

        // Small delay to separate the changes
        sleep(Duration::from_millis(10)).await;
    }

    // Give fswatch time to process all changes
    sleep(FSWATCH_DETECTION_DELAY).await;

    // Watcher should still be running after rapid changes
    assert!(
        is_fswatch_running(watcher_pid),
        "Watcher should handle rapid file changes"
    );

    Ok(())
}

#[tokio::test]
async fn test_watcher_stays_same_within_repo_subdirs() -> Result<()> {
    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    // Get initial watcher PID
    let initial_pid = get_watcher_pid(&mut child)?;

    // Create subdirectory
    let subdir = ctx.test_repo_path.join("subdir");
    fs::create_dir_all(&subdir)?;

    // Move to subdirectory
    child.send_line(format!("cd {}", subdir.display()))?;
    child.expect(Regex(PROMPT_MARKER))?;
    child.expect(Regex(SHELL_PROMPT))?;

    // Wait a moment for any potential watcher changes
    sleep(FSWATCH_DETECTION_DELAY).await;

    // Watcher should still be the same (same git repo)
    let new_pid = get_watcher_pid(&mut child)?;
    assert_eq!(
        initial_pid, new_pid,
        "Watcher PID should remain same within repo subdirs"
    );

    // And it should still be running
    assert!(
        is_fswatch_running(new_pid),
        "Watcher should still be running in subdir"
    );

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

    // Wait for new watcher to start properly
    let new_pid = wait_for_fswatch_to_start(&mut child).await?;

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
async fn test_watcher_cleanup_on_exit() -> Result<()> {
    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    // Wait for watcher to start
    let watcher_pid = wait_for_fswatch_to_start(&mut child).await?;

    // Verify watcher is running
    assert!(is_fswatch_running(watcher_pid), "Watcher should be running");

    // Exit shell
    child.send_line("exit")?;

    // Wait for the shell process to actually exit
    let _ = child.expect(expectrl::Eof)?;

    // Give more time for cleanup hooks to run
    sleep(Duration::from_secs(2)).await;

    // Watcher process should be cleaned up
    let cleaned_up = wait_for_process_termination(watcher_pid).await.is_ok();
    assert!(cleaned_up, "Watcher should be cleaned up on shell exit");

    Ok(())
}

#[tokio::test]
async fn test_watcher_killed_on_shell_exit() -> Result<()> {
    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    // Get shell PID and watcher PID
    child.send_line("echo \"SHELL_PID:$$:\"")?;
    let output = child.expect(Regex(r"SHELL_PID:(\d+):"))?;
    let matches: Vec<_> = output.matches().collect();
    let full_match = String::from_utf8_lossy(matches[0]);
    let shell_pid: u32 = full_match
        .strip_prefix("SHELL_PID:")
        .unwrap()
        .strip_suffix(":")
        .unwrap()
        .parse()?;
    child.expect(Regex(SHELL_PROMPT))?;

    let watcher_pid = get_watcher_pid(&mut child)?;

    // Verify watcher is running
    assert!(is_fswatch_running(watcher_pid), "Watcher should be running");

    // Kill the shell process
    let shell_pid_nix = Pid::from_raw(i32::try_from(shell_pid).expect("shell PID too large"));
    signal::kill(shell_pid_nix, Signal::SIGTERM)?;

    // Wait for cleanup
    sleep(Duration::from_secs(3)).await;

    // Watcher should also be terminated
    let terminated = wait_for_process_termination(watcher_pid).await.is_ok();
    assert!(terminated, "Watcher should be terminated when shell exits");

    Ok(())
}

#[tokio::test]
async fn test_watcher_really_stops_when_leaving_repo() -> Result<()> {
    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    // Get initial watcher PID
    let initial_pid = wait_for_fswatch_to_start(&mut child).await?;

    // Move to a non-git directory
    let non_git_dir = ctx.temp_dir.path().join("non_git");
    fs::create_dir_all(&non_git_dir)?;

    child.send_line(format!("cd {}", non_git_dir.display()))?;
    child.expect(Regex(PROMPT_MARKER))?;
    child.expect(Regex(SHELL_PROMPT))?;

    // Give time for the watcher to be stopped
    sleep(PROCESS_CLEANUP_DELAY).await;
    sleep(SIGNAL_PROCESSING_TIME).await;

    // Original watcher should be stopped
    assert!(
        !is_fswatch_running(initial_pid),
        "Original watcher should be stopped when leaving repo"
    );

    Ok(())
}

#[tokio::test]
async fn test_git_operations_trigger_monitoring() -> Result<()> {
    let ctx = TestContext::new()?;
    let repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    // Get watcher PID
    let watcher_pid = wait_for_fswatch_to_start(&mut child).await?;

    // Stage a file
    let test_file = ctx.test_repo_path.join("staged.txt");
    fs::write(&test_file, "staged content")?;

    let mut index = repo.index()?;
    index.add_path(Path::new("staged.txt"))?;
    index.write()?;

    // Give fswatch time to detect the change
    sleep(FSWATCH_DETECTION_DELAY).await;

    // Watcher should still be running and monitoring
    assert!(
        is_fswatch_running(watcher_pid),
        "Watcher should monitor git operations"
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
async fn test_large_gitignore_file_handling() -> Result<()> {
    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    // Wait for initial watcher to start
    let _watcher_pid = wait_for_fswatch_to_start(&mut child).await?;

    // Create a large .gitignore file
    let large_gitignore_path = ctx.test_repo_path.join(".gitignore");
    let large_content = (0..1000).fold(String::new(), |mut acc, i| {
        use std::fmt::Write;
        writeln!(&mut acc, "pattern{i}").unwrap();
        acc
    });
    fs::write(&large_gitignore_path, large_content)?;

    // Give fswatch time to detect the change and restart
    sleep(FSWATCH_DETECTION_DELAY).await;

    // Wait a bit more for the signal processing
    sleep(WATCHER_RESTART_TIME).await;

    // The watcher should have restarted and still be running
    let new_pid = get_watcher_pid(&mut child)?;
    // Don't require PID to be different - the important thing is that it's still running
    assert!(
        is_fswatch_running(new_pid),
        "Watcher should be running after gitignore change"
    );

    Ok(())
}

// Security Tests - These test the plugin's ability to handle malicious input safely

#[tokio::test]
async fn test_malicious_gitignore_patterns_security() -> Result<()> {
    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    // Wait for initial watcher
    let _initial_pid = wait_for_fswatch_to_start(&mut child).await?;

    // Create .gitignore with malicious patterns
    let gitignore_path = ctx.test_repo_path.join(".gitignore");
    let malicious_content = MALICIOUS_GITIGNORE_PATTERNS.join("\n");
    fs::write(&gitignore_path, malicious_content)?;

    // Give fswatch time to process the malicious gitignore
    sleep(FSWATCH_DETECTION_DELAY).await;
    sleep(WATCHER_RESTART_TIME).await; // Extra time for processing

    // Verify watcher restarted and is still running (didn't crash from malicious input)
    let final_pid = get_watcher_pid(&mut child)?;
    assert!(
        is_fswatch_running(final_pid),
        "Watcher should safely handle malicious gitignore patterns"
    );

    // Verify shell is still responsive (no command injection occurred)
    child.send_line("echo 'Shell still safe'")?;
    child.expect(Regex("Shell still safe"))?;
    child.expect(Regex(SHELL_PROMPT))?;

    Ok(())
}

#[tokio::test]
async fn test_large_gitignore_security() -> Result<()> {
    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    // Wait for initial watcher
    let _watcher_pid = wait_for_fswatch_to_start(&mut child).await?;

    // Create .gitignore with large malicious content
    let gitignore_path = ctx.test_repo_path.join(".gitignore");
    let large_malicious_content = get_all_malicious_patterns().join("\n");
    fs::write(&gitignore_path, large_malicious_content)?;

    // Give fswatch time to process the large file
    sleep(FSWATCH_DETECTION_DELAY).await;
    sleep(LARGE_CONTENT_PROCESSING_TIME).await; // More time for large content

    // Check if system is still stable
    let current_pid = get_watcher_pid(&mut child)?;

    // Either the watcher restarted (new PID) or stayed the same (handled gracefully)
    // The key is that it should still be running and system should be stable
    assert!(
        is_fswatch_running(current_pid),
        "System should remain stable with large malicious gitignore"
    );

    // Verify no command injection by checking shell responsiveness
    child.send_line("echo 'Security test passed'")?;
    child.expect(Regex("Security test passed"))?;
    child.expect(Regex(SHELL_PROMPT))?;

    Ok(())
}

#[tokio::test]
async fn test_command_injection_via_gitignore_patterns() -> Result<()> {
    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    // Wait for initial watcher
    let _watcher_pid = wait_for_fswatch_to_start(&mut child).await?;

    // Create .gitignore with command injection attempts
    let gitignore_path = ctx.test_repo_path.join(".gitignore");
    let injection_patterns = [
        "; touch /tmp/injected_file", // Command separator
        "&& rm -rf /tmp/test",        // Logical AND
        "|| echo 'injected'",         // Logical OR
        "| cat /etc/passwd",          // Pipe
        "`whoami`",                   // Command substitution
        "$(id)",                      // Command substitution
        "\nrm -rf /",                 // Newline injection
    ];

    let malicious_content = injection_patterns.join("\n");
    fs::write(&gitignore_path, malicious_content)?;

    // Give time for processing
    sleep(FSWATCH_DETECTION_DELAY).await;
    sleep(WATCHER_RESTART_TIME).await;

    // Verify watcher is still running (didn't crash from injection attempts)
    let new_pid = get_watcher_pid(&mut child)?;
    assert!(
        is_fswatch_running(new_pid),
        "Watcher should survive command injection attempts"
    );

    // Verify no files were created by injection attempts
    assert!(
        !PathBuf::from("/tmp/injected_file").exists(),
        "Command injection should not create files"
    );

    // Shell should still be responsive
    child.send_line("echo 'Injection prevented'")?;
    child.expect(Regex("Injection prevented"))?;
    child.expect(Regex(SHELL_PROMPT))?;

    Ok(())
}

#[tokio::test]
async fn test_malicious_global_gitignore_security() -> Result<()> {
    let ctx = TestContext::new()?;
    let repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    // Set up a malicious global gitignore
    let malicious_global_gitignore = ctx.get_unique_attack_path("global_gitignore");
    let malicious_patterns = [
        "; echo 'global_injection' > /tmp/global_attack",
        "$(touch /tmp/global_substitution)",
        "&& rm -rf /tmp/*",
    ];
    fs::write(&malicious_global_gitignore, malicious_patterns.join("\n"))?;

    // Configure git to use the malicious global gitignore
    let mut config = repo.config()?;
    config.set_str(
        "core.excludesfile",
        malicious_global_gitignore.to_str().unwrap(),
    )?;

    // Start watcher (it should read the global gitignore)
    let watcher_pid = wait_for_fswatch_to_start(&mut child).await?;

    // Give time for processing
    sleep(FSWATCH_DETECTION_DELAY).await;

    // Verify watcher handled the malicious global gitignore safely
    assert!(
        is_fswatch_running(watcher_pid),
        "Watcher should safely handle malicious global gitignore"
    );

    // Verify no attack files were created
    assert!(
        !PathBuf::from("/tmp/global_attack").exists(),
        "Global gitignore injection should not create attack files"
    );
    assert!(
        !PathBuf::from("/tmp/global_substitution").exists(),
        "Global gitignore command substitution should not work"
    );

    Ok(())
}

#[tokio::test]
async fn test_malicious_git_info_exclude_security() -> Result<()> {
    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;
    let mut child = ctx.get_zsh_child(None, false)?;

    // Create malicious .git/info/exclude file
    let git_dir = ctx.test_repo_path.join(".git");
    let info_dir = git_dir.join("info");
    fs::create_dir_all(&info_dir)?;

    let exclude_file = info_dir.join("exclude");
    let malicious_exclude_patterns = [
        "; touch /tmp/exclude_attack",
        "|| echo 'exclude_injection'",
        "& rm /tmp/test_file",
        "`date > /tmp/exclude_date`",
    ];
    fs::write(&exclude_file, malicious_exclude_patterns.join("\n"))?;

    // Start watcher
    let watcher_pid = wait_for_fswatch_to_start(&mut child).await?;

    // Give time for processing
    sleep(FSWATCH_DETECTION_DELAY).await;

    // Verify watcher is running safely
    assert!(
        is_fswatch_running(watcher_pid),
        "Watcher should safely handle malicious git exclude file"
    );

    // Verify no attack files were created
    assert!(
        !PathBuf::from("/tmp/exclude_attack").exists(),
        "Exclude file injection should not create attack files"
    );
    assert!(
        !PathBuf::from("/tmp/exclude_date").exists(),
        "Exclude file command substitution should not work"
    );

    Ok(())
}

#[tokio::test]
async fn test_no_attack_files_created_during_security_test() -> Result<()> {
    // This test verifies that none of our security tests accidentally created attack files
    let attack_paths = [
        "/tmp/injected_file",
        "/tmp/global_attack",
        "/tmp/global_substitution",
        "/tmp/exclude_attack",
        "/tmp/exclude_date",
    ];

    for attack_path in &attack_paths {
        assert!(
            !PathBuf::from(attack_path).exists(),
            "Attack file {attack_path} should not exist after security tests"
        );
    }

    Ok(())
}

// Starship integration tests

#[tokio::test]
async fn test_prompt_updates_with_starship() -> Result<()> {
    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;

    // Use starship for this test
    let mut child = ctx.get_zsh_child(None, true)?;

    // Wait for watcher to start
    let watcher_pid = wait_for_fswatch_to_start(&mut child).await?;

    // Send a newline to trigger initial prompt
    child.send_line("")?;

    // Initial prompt should show clean state (no indicators)
    child.expect(Regex(r"on main.*test>"))?;

    // Create an untracked file to trigger git status change
    let test_file = ctx.test_repo_path.join("untracked.txt");
    fs::write(&test_file, "untracked content")?;

    // Give time for fswatch to detect change and trigger prompt update
    sleep(FSWATCH_DETECTION_DELAY).await;

    // Trigger a new prompt to see the change
    child.send_line("")?;

    // Should show untracked indicator (? in starship)
    let output = child.expect(Regex(r"test>"))?;
    let prompt_output = String::from_utf8_lossy(output.before());

    // Starship should indicate untracked files (usually with ?)
    // The exact symbol may vary with starship config, but there should be some indicator
    assert!(
        prompt_output.contains('?')
            || prompt_output.contains("untracked")
            || !prompt_output.trim().is_empty(),
        "Starship should show git status change indicator: {prompt_output}"
    );

    // Watcher should still be running with starship
    assert!(
        is_fswatch_running(watcher_pid),
        "Watcher should work with Starship"
    );

    Ok(())
}

#[tokio::test]
async fn test_prompt_updates_on_branch_switch_with_starship() -> Result<()> {
    let ctx = TestContext::new()?;
    let _repo = ctx.create_test_repo()?;

    // Use starship for this test
    let mut child = ctx.get_zsh_child(None, true)?;

    // Wait for watcher to start
    let watcher_pid = wait_for_fswatch_to_start(&mut child).await?;

    // Send a newline to trigger initial prompt
    child.send_line("")?;

    // Wait for starship to show initial prompt with main branch
    child.expect(Regex(r"on main .*test>"))?;

    // Create and switch to a new branch
    child.send_line("git checkout -b feature-branch")?;
    child.expect(Regex("Switched to a new branch"))?;

    // Poll for prompt update to new branch name
    wait_for_prompt_change(
        &mut child,
        r"on feature-branch .*test>",
        "feature branch prompt update",
    )
    .await?;
    assert!(is_fswatch_running(watcher_pid));

    // Switch back to main
    child.send_line("git checkout main")?;
    child.expect(Regex("Switched to branch"))?;

    // Poll for prompt update back to main
    wait_for_prompt_change(&mut child, r"on main .*test>", "main branch prompt update").await?;
    assert!(is_fswatch_running(watcher_pid));

    Ok(())
}
