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
    # Kill existing watcher
    [[ -n "$_git_prompt_watcher_pid" ]] && kill "$_git_prompt_watcher_pid" 2>/dev/null
    _git_prompt_watcher_pid=""

    # Only start watcher if we're in a git repository
    if git rev-parse --git-dir >/dev/null 2>&1; then
        local git_dir=$(git rev-parse --git-dir 2>/dev/null)
        if [[ -n "$git_dir" ]]; then
            # Create temporary filter file for fswatch exclude patterns
            local filter_file=$(mktemp)

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

            # Add global gitignore if it exists
            local global_gitignore=$(git config --global core.excludesfile 2>/dev/null)
            [[ -n "$global_gitignore" && -f "$global_gitignore" ]] && gitignore_files+=("$global_gitignore")

            # Watch git files, working directory, and gitignore files
            # Create a named pipe for communication
            local pipe_file=$(mktemp -u)
            mkfifo "$pipe_file" 2>/dev/null

            # Start fswatch in background and get its PID
            fswatch -o \
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

            # Start the reader process
            {
                while read line <&3; do
                    # Check if a gitignore file changed - if so, restart watcher
                    local restart_needed=false
                    for gitignore_file in "${gitignore_files[@]}" "$git_dir/info/exclude"; do
                        if [[ "$line" == *"$gitignore_file"* ]]; then
                            restart_needed=true
                            break
                        fi
                    done

                    if [[ "$restart_needed" == "true" ]]; then
                        # Restart the watcher with new ignore patterns
                        kill -USR2 $$ 2>/dev/null
                    else
                        # Normal prompt redraw
                        kill -USR1 $$ 2>/dev/null
                    fi
                done 3< "$pipe_file"

                # Clean up pipe and filter file when done
                rm -f "$pipe_file" "$filter_file"
            } &!

            # Store the fswatch PID, not the reader PID
            _git_prompt_watcher_pid=$fswatch_pid
        fi
    fi
}

_stop_git_watcher() {
    if [[ -n "$_git_prompt_watcher_pid" ]]; then
        # Try SIGTERM first, then SIGKILL if necessary
        kill "$_git_prompt_watcher_pid" 2>/dev/null
        sleep 0.1
        kill -9 "$_git_prompt_watcher_pid" 2>/dev/null
        # Note: pipe cleanup is handled by the reader process
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
