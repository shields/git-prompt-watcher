# Git status monitoring for prompt updates
#
# Copyright 2025 Michael Shields
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

_git_prompt_watcher_pid=""
_git_prompt_current_git_dir=""

_start_git_watcher() {
    # Stop any existing watcher first. A plain `kill` (SIGTERM) here would leak
    # the old process on every restart because fswatch ignores SIGTERM;
    # _stop_git_watcher sends SIGKILL, which reliably reaps it.
    _stop_git_watcher

    # Only start watcher if we're in a git repository
    if git rev-parse --git-dir >/dev/null 2>&1; then
        local git_dir=$(git rev-parse --git-dir 2>/dev/null)
        if [[ -n "$git_dir" ]]; then
            # Create temporary filter file for fswatch exclude patterns
            local filter_file=$(mktemp -t gpw-filter.XXXXXX) || return 1

            # Add basic exclude patterns to filter file
            {
                echo '.git/objects/.*'
                echo '.git/logs/.*'
                git ls-files --others --ignored --exclude-standard --directory 2>/dev/null | sed 's|/$|/.*|'
            } > "$filter_file"

            # Find gitignore files to watch for changes
            local gitignore_files=()
            local repo_root=$(git rev-parse --show-toplevel 2>/dev/null)

            if [[ -n "$repo_root" ]]; then
                while IFS= read -r -d '' gitignore_file; do
                    [[ -f "$gitignore_file" ]] && gitignore_files+=("$gitignore_file")
                done < <(find "$repo_root" -name ".gitignore" -print0 2>/dev/null)
            fi

            # Add global gitignore if it exists. --path makes git expand a
            # leading ~ so the -f test below does not silently fail on a path
            # like ~/.gitignore_global.
            local global_gitignore=$(git config --global --path core.excludesfile 2>/dev/null)
            [[ -n "$global_gitignore" && -f "$global_gitignore" ]] && gitignore_files+=("$global_gitignore")

            # Watch git files, working directory, and gitignore files.
            # Create the named pipe inside a private mktemp directory rather than
            # via `mktemp -u`, whose predictable name allows a symlink/TOCTOU
            # attack in the shared temp dir.
            local pipe_dir=$(mktemp -d -t gpw-pipe.XXXXXX) || { rm -f "$filter_file"; return 1; }
            local pipe_file="$pipe_dir/pipe"
            mkfifo "$pipe_file" || { rm -rf "$pipe_dir"; rm -f "$filter_file"; return 1; }

            # Start fswatch in background and get its PID.
            # Emit changed paths (not the -o batch count) so the reader can tell
            # gitignore changes from ordinary changes, and a marker after each
            # batch so the reader can collapse a multi-file change into a single
            # signal instead of one signal per file.
            # Some targets (e.g. .git/index before the first commit) may not
            # exist yet; fswatch tolerates missing paths and keeps running, so
            # they are passed unconditionally and start firing once created.
            fswatch \
                    --batch-marker \
                    --filter-from="$filter_file" \
                    --latency=0.1 \
                    -- \
                    "$git_dir/index" \
                    "$git_dir/HEAD" \
                    "$git_dir/refs" \
                    "$git_dir/info/exclude" \
                    "${gitignore_files[@]}" \
                    "${repo_root:-$PWD}" \
                    2>/dev/null > "$pipe_file" &!
            local fswatch_pid=$!

            # Start the reader process. fswatch prints the changed paths of a
            # batch followed by a "NoOp" marker line; we accumulate whether any
            # path was a gitignore file and send exactly one signal per batch.
            #
            # The FIFO is opened read-write (3<>) so the open never blocks: a
            # read-only open would hang forever if fswatch failed to start (e.g.
            # an unsupported flag). Because the reader then also holds a write
            # end, EOF never arrives, so the loop instead runs while the fswatch
            # process is alive and uses a timed read to poll for its exit.
            local shell_pid=$$
            {
                # Reliable temp cleanup even if this subshell is signalled.
                trap 'rm -rf "$pipe_dir"; rm -f "$filter_file"' EXIT INT TERM HUP

                local restart_needed=false
                while kill -0 "$fswatch_pid" 2>/dev/null; do
                    # Stop if the shell we serve is gone or was replaced (e.g.
                    # via exec), so we neither orphan fswatch nor signal an
                    # unrelated process that reused the PID.
                    if [[ "$(ps -p "$shell_pid" -o comm= 2>/dev/null)" != *zsh* ]]; then
                        kill -9 "$fswatch_pid" 2>/dev/null
                        break
                    fi

                    IFS= read -r -t 1 line <&3 || continue

                    if [[ "$line" == "NoOp" ]]; then
                        if [[ "$restart_needed" == "true" ]]; then
                            # A gitignore changed: restart with new ignore patterns
                            kill -USR2 "$shell_pid" 2>/dev/null
                        else
                            # Normal prompt redraw
                            kill -USR1 "$shell_pid" 2>/dev/null
                        fi
                        restart_needed=false
                        continue
                    fi

                    for gitignore_file in "${gitignore_files[@]}" "$git_dir/info/exclude"; do
                        if [[ "$line" == *"$gitignore_file"* ]]; then
                            restart_needed=true
                            break
                        fi
                    done
                done 3<> "$pipe_file"
            } &!

            # Store the fswatch PID, not the reader PID
            _git_prompt_watcher_pid=$fswatch_pid
        fi
    fi
}

_stop_git_watcher() {
    if [[ -n "$_git_prompt_watcher_pid" ]]; then
        # fswatch ignores SIGTERM, so send SIGKILL directly (this also avoids a
        # blocking sleep that would otherwise lag every cd/restart). Confirm the
        # process is still a direct child of this shell first: the watcher may
        # have already exited and had its PID recycled, and we must not kill an
        # unrelated process. Checking the parent PID (rather than the command
        # name) keeps this working even if fswatch is a wrapper or alias. Once
        # fswatch is gone the reader process notices and removes its temp files.
        local watcher_ppid="$(ps -p "$_git_prompt_watcher_pid" -o ppid= 2>/dev/null)"
        if [[ "${watcher_ppid//[[:space:]]/}" == "$$" ]]; then
            kill -9 "$_git_prompt_watcher_pid" 2>/dev/null
        fi
    fi
    _git_prompt_watcher_pid=""
}

_check_git_repo_change() {
    local current_git_dir=""
    current_git_dir=$(git rev-parse --absolute-git-dir 2>/dev/null)

    # Only restart watcher if git directory changed
    if [[ "$current_git_dir" != "$_git_prompt_current_git_dir" ]]; then
        _git_prompt_current_git_dir="$current_git_dir"
        if [[ -n "$current_git_dir" ]]; then
            _start_git_watcher
        else
            _stop_git_watcher
        fi
    fi
}

# Safely reset prompt, avoiding interference with active zle operations
_safe_reset_prompt() {
    if zle; then
        # Check if we're in the middle of completion, search, or other sensitive operations
        case "${WIDGET:-}" in
            expand-or-complete|complete-word|menu-*|*search*|*history*|\
            fzf-tab-complete|fzf-tab-*|_fzf-tab-*|*fzf*)
                # Don't interrupt these operations
                ;;
            *)
                # Safe to reset prompt
                zle reset-prompt
                ;;
        esac
    fi
}

# Handle SIGUSR1 to redraw prompt
TRAPUSR1() {
    _safe_reset_prompt
}

# Handle SIGUSR2 to restart watcher (when gitignore changes)
TRAPUSR2() {
    _start_git_watcher
    _safe_reset_prompt
}

# Check for git repo changes when changing directories
chpwd_functions+=(_check_git_repo_change)

# Initialize on shell startup
_check_git_repo_change

# Clean up watcher on shell exit and signals
zshexit_functions+=(_stop_git_watcher)

# Also handle common termination signals
TRAPTERM() {
    _stop_git_watcher
}

TRAPINT() {
    _stop_git_watcher
}

TRAPHUP() {
    _stop_git_watcher
}
