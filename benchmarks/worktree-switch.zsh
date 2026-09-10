# Invoked by worktree-switch.py in a clean zsh; timings exclude shell startup.
# Copyright 2026 Michael Shields. Licensed under the Apache License, Version 2.0.
emulate -R zsh
zmodload zsh/datetime
setopt NO_MONITOR

plugin=$1
mode=$2
first=$3
second=$4
iterations=$5
warmup=$6
trace_file=$7
integer sample_index=0
integer recorded_index=0

builtin cd -- "$first" || exit 1

if [[ $mode == without-find ]]; then
    # Diagnostic ablation only: this intentionally omits nested ignore watches.
    find() { return 0; }
fi

if [[ $mode != off ]]; then
    source "$plugin" || exit 1
fi

if [[ $mode == profile ]]; then
    _bench_timed() {
        local label=$1
        shift
        local -F 9 bench_started=$EPOCHREALTIME
        "$@"
        local bench_rc=$?
        local -F 9 bench_elapsed=$(( EPOCHREALTIME - bench_started ))
        # Reader subprocesses inherit these functions and termination traps;
        # their cleanup must not be counted as foreground shutdown work.
        if (( sample_index > 0 )) && { [[ $label != (start|stop) ]] || (( ZSH_SUBSHELL == 0 )); }; then
            printf '%d\t%s\t%.9f\n' "$sample_index" "$label" "$bench_elapsed" >> "$trace_file"
        fi
        return $bench_rc
    }
    functions[_bench_original_start]=$functions[_start_git_watcher]
    functions[_bench_original_stop]=$functions[_stop_git_watcher]
    _start_git_watcher() { _bench_timed start _bench_original_start "$@"; }
    _stop_git_watcher() { _bench_timed stop _bench_original_stop "$@"; }
    find() { _bench_timed find command find "$@"; }
    git() {
        local operation=$1
        [[ $1 == -C ]] && operation=$3
        _bench_timed "git-$operation" command git "$@"
    }
fi

if [[ $mode == same-worktree ]]; then
    second=$first
fi

# Each round measures both directions separately. Warmups also exercise real
# watcher shutdown/restart, so the first recorded cd does not get a free stop.
for (( round = 1; round <= warmup + iterations; round++ )); do
    for destination in "$second" "$first"; do
        if (( round > warmup )); then
            sample_index=$(( ++recorded_index ))
        fi
        previous_pid=${_git_prompt_watcher_pid:-}
        typeset -F 9 started=$EPOCHREALTIME
        builtin cd -- "$destination" || exit 1
        typeset -F 9 elapsed=$(( EPOCHREALTIME - started ))
        if [[ $mode != off ]]; then
            # Check outside the timer: a failed start must not look fast.
            if [[ -z $_git_prompt_watcher_pid ]] || ! kill -0 "$_git_prompt_watcher_pid" 2>/dev/null; then
                print -u2 -- 'benchmark: watcher failed to start'
                exit 1
            fi
            if [[ $mode == same-worktree ]]; then
                [[ $_git_prompt_watcher_pid == "$previous_pid" ]] || exit 1
            else
                [[ $_git_prompt_watcher_pid != "$previous_pid" ]] || exit 1
            fi
        fi
        if (( sample_index > 0 )); then
            printf '%d\t%.9f\n' "$sample_index" "$elapsed"
        fi
        sample_index=0
    done
done

# Normal shell exit runs the plugin's cleanup hook; it is outside the timer.
