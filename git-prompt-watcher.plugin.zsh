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
_git_prompt_reader_pid=""
_git_prompt_pipe_dir=""
_git_prompt_filter_file=""
_git_prompt_current_git_dir=""

# Print the parent PID of pid, or nothing if it cannot be determined. Reads from
# /proc on Linux (no fork, and works without procps) and falls back to ps
# elsewhere (e.g. macOS, which has no /proc).
_gpw_ppid_of() {
    local pid=$1 ppid=""
    if [[ -r /proc/$pid/stat ]]; then
        # /proc/<pid>/stat is "pid (comm) state ppid ..."; comm may contain
        # spaces or ')', so split after the last ')' to find ppid.
        local stat_line
        if IFS= read -r stat_line < /proc/$pid/stat 2>/dev/null; then
            stat_line="${stat_line##*\) }"
            ppid="${${(s: :)stat_line}[2]}"
        fi
    elif (( $+commands[ps] )); then
        ppid="$(ps -p "$pid" -o ppid= 2>/dev/null)"
    fi
    print -r -- "${ppid//[[:space:]]/}"
}

# Send a signal (default KILL) to pid, but only if it is still a direct child of
# this shell. The PID may have already exited and been recycled, and we must not
# signal an unrelated process. If the parent PID cannot be determined, signal
# anyway, as the recycle window is tiny.
_gpw_kill_if_child() {
    local pid=$1 sig=${2:-KILL}
    [[ -n "$pid" ]] || return 0
    local ppid="$(_gpw_ppid_of "$pid")"
    [[ -z "$ppid" || "$ppid" == "$$" ]] && kill -"$sig" "$pid" 2>/dev/null
}

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

            # Find gitignore files to watch for changes. fswatch is not
            # recursive on Linux/inotify and the working-tree watch below only
            # reports the repo root's top level, so nested .gitignore files must
            # be listed explicitly here to be watched at all.
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
            # --batch-marker makes fswatch print a "NoOp" line after each batch
            # of events, letting the reader collapse a multi-file change into a
            # single prompt redraw instead of emitting one signal per file.
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
                    </dev/null 2>/dev/null > "$pipe_file" &!
            local fswatch_pid=$!

            # Start the reader process. fswatch prints the changed paths of a
            # batch followed by a "NoOp" marker line; the reader sends exactly
            # one prompt-redraw signal (SIGUSR1) per batch.
            #
            # The FIFO is opened read-write (3<>) so the open never blocks: a
            # read-only open would hang forever if fswatch failed to start (e.g.
            # an unsupported flag). Because the reader then also holds a write
            # end, EOF never arrives, so the loop instead runs while the fswatch
            # process is alive and uses a timed read to poll for its exit.
            local shell_pid=$$
            {
                # Clean up temp files when the reader ends, and exit promptly
                # when signalled so _stop_git_watcher can reap it with SIGTERM.
                trap 'rm -rf "$pipe_dir"; rm -f "$filter_file"' EXIT
                trap 'exit' INT TERM HUP

                while kill -0 "$fswatch_pid" 2>/dev/null; do
                    # Stop if the shell we serve has exited (portable liveness
                    # check; needs no external tools).
                    if ! kill -0 "$shell_pid" 2>/dev/null; then
                        kill -9 "$fswatch_pid" 2>/dev/null
                        break
                    fi
                    # Also stop if that PID was exec'd into a non-zsh process, so
                    # we never signal an unrelated program. Read the command name
                    # from /proc on Linux (no fork, and works without procps) and
                    # fall back to ps elsewhere (e.g. macOS, which has no /proc).
                    # If neither can tell us, skip this refinement rather than
                    # guess and kill a live watcher.
                    local shell_comm=""
                    if [[ -r /proc/$shell_pid/comm ]]; then
                        IFS= read -r shell_comm < /proc/$shell_pid/comm 2>/dev/null
                    elif (( $+commands[ps] )); then
                        shell_comm="$(ps -p "$shell_pid" -o comm= 2>/dev/null)"
                    fi
                    if [[ -n "$shell_comm" && "$shell_comm" != *zsh* ]]; then
                        kill -9 "$fswatch_pid" 2>/dev/null
                        break
                    fi

                    IFS= read -r -t 1 line <&3 || continue

                    # One redraw per batch: act only on the end-of-batch marker
                    # and ignore the individual path lines that precede it.
                    [[ "$line" == "NoOp" ]] && kill -USR1 "$shell_pid" 2>/dev/null
                done 3<> "$pipe_file"
            } &!
            local reader_pid=$!

            # Track both processes so _stop_git_watcher can reap the reader too;
            # _git_prompt_watcher_pid is the fswatch PID the tests inspect. Also
            # record the temp paths so _stop_git_watcher can remove them even if
            # the reader is killed before its cleanup trap is installed.
            _git_prompt_watcher_pid=$fswatch_pid
            _git_prompt_reader_pid=$reader_pid
            _git_prompt_pipe_dir=$pipe_dir
            _git_prompt_filter_file=$filter_file
        fi
    fi
}

_stop_git_watcher() {
    # Reap the reader first with SIGTERM so it runs its cleanup trap (removing
    # the pipe and filter temp files) and stops holding the terminal open; then
    # SIGKILL fswatch, which ignores SIGTERM. Killing the reader explicitly
    # (rather than letting it notice fswatch's exit by polling) avoids a delay
    # of up to one poll interval, which otherwise leaves the watcher holding the
    # tty after the shell exits. Sending SIGKILL directly also avoids a blocking
    # sleep that would lag every cd/restart.
    _gpw_kill_if_child "$_git_prompt_reader_pid" TERM
    _gpw_kill_if_child "$_git_prompt_watcher_pid" KILL
    # Remove the temp files here rather than relying solely on the reader's EXIT
    # trap: the reader may be signalled before that trap is installed (a restart
    # that stops it immediately after starting it), which would orphan them.
    [[ -n "$_git_prompt_pipe_dir" ]] && rm -rf "$_git_prompt_pipe_dir" 2>/dev/null
    [[ -n "$_git_prompt_filter_file" ]] && rm -f "$_git_prompt_filter_file" 2>/dev/null
    _git_prompt_reader_pid=""
    _git_prompt_watcher_pid=""
    _git_prompt_pipe_dir=""
    _git_prompt_filter_file=""
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

# Handle SIGUSR2 to restart the watcher on demand (e.g. an external trigger)
TRAPUSR2() {
    _start_git_watcher
    _safe_reset_prompt
}

# Stop the watcher on shell exit, then wait for the killed fswatch to be reaped.
# zsh reaps a disowned child only while it keeps running (its SIGCHLD handler
# runs between commands); after this hook the shell stops, so without waiting
# here the process would linger as a zombie. We cannot wait() a disowned PID, so
# poll until it is gone: kill -0 still succeeds for a zombie, so also stop once
# the PID is no longer our child (gone, or recycled to an unrelated process) to
# avoid spinning the full timeout on a recycled PID. On cd/restart the shell
# keeps running and reaps it, so this wait is only needed at exit, which keeps
# _stop_git_watcher fast on the interactive path.
_git_prompt_watcher_exit() {
    local pid=$_git_prompt_watcher_pid
    _stop_git_watcher
    local i
    for i in {1..50}; do
        kill -0 "$pid" 2>/dev/null || break
        [[ "$(_gpw_ppid_of "$pid")" == "$$" ]] || break
        sleep 0.02
    done
}

# Check for git repo changes when changing directories
chpwd_functions+=(_check_git_repo_change)

# Initialize on shell startup
_check_git_repo_change

# Clean up watcher on shell exit and signals
zshexit_functions+=(_git_prompt_watcher_exit)

# Clean up on signals that terminate the shell, since zshexit_functions does not
# run when the shell is killed by a signal. SIGINT (Ctrl-C) is deliberately not
# handled: it interrupts the foreground command, not the shell, so stopping the
# watcher on it would leave it dead until the next directory change.
TRAPTERM() {
    _stop_git_watcher
}

TRAPHUP() {
    _stop_git_watcher
}
