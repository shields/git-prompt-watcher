# Invoked by startup.py in a clean zsh, once per sample. The timer covers only
# sourcing the plugin, so shell startup and exit are excluded.
# Copyright 2026 Michael Shields. Licensed under the Apache License, Version 2.0.
emulate -R zsh
zmodload zsh/datetime
setopt NO_MONITOR

plugin=$1
mode=$2
directory=$3
expect_watcher=$4
trace_file=$5

builtin cd -- "$directory" || exit 1

if [[ $mode == profile ]]; then
    _bench_timed() {
        local label=$1
        shift
        local -F 9 bench_started=$EPOCHREALTIME
        "$@"
        local bench_rc=$?
        local -F 9 bench_elapsed=$(( EPOCHREALTIME - bench_started ))
        printf '%s\t%.9f\n' "$label" "$bench_elapsed" >> "$trace_file"
        return $bench_rc
    }
    # The plugin's functions first run while it is being sourced, so only the
    # external commands they fork can be wrapped. fswatch is left alone: a
    # wrapper started with &! would make the plugin record the wrapper's PID
    # instead of fswatch's, breaking watcher tracking and cleanup.
    git() {
        local operation=$1
        [[ $1 == -C ]] && operation=$3
        _bench_timed "git-$operation" command git "$@"
    }
    mktemp() { _bench_timed mktemp command mktemp "$@"; }
    mkfifo() { _bench_timed mkfifo command mkfifo "$@"; }
    sed() { _bench_timed sed command sed "$@"; }
fi

typeset -F 9 started=$EPOCHREALTIME
source "$plugin" || exit 1
typeset -F 9 elapsed=$(( EPOCHREALTIME - started ))

# Check outside the timer: a failed start must not look fast.
if (( expect_watcher )); then
    if [[ -z $_git_prompt_watcher_pid ]] || ! kill -0 "$_git_prompt_watcher_pid" 2>/dev/null; then
        print -u2 -- 'benchmark: watcher failed to start'
        exit 1
    fi
elif [[ -n $_git_prompt_watcher_pid ]]; then
    print -u2 -- 'benchmark: watcher started outside a repository'
    exit 1
fi

printf '%.9f\n' "$elapsed"

# Normal shell exit runs the plugin's cleanup hook; it is outside the timer.
