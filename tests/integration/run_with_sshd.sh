#!/usr/bin/env bash
# Spins up an ephemeral, unprivileged sshd instance with a throwaway host key and
# a throwaway client key trusted via authorized_keys, runs the given test binary
# against it with connection details in the environment, then tears everything down.
set -euo pipefail

log() { echo "[run_with_sshd $(date -u +%H:%M:%S)] $*" >&2; }

TEST_BIN="${1:?usage: run_with_sshd.sh <test-binary>}"

SSHD_BIN="$(command -v sshd || echo /usr/sbin/sshd)"
if [[ ! -x "$SSHD_BIN" ]]; then
    echo "sshd not found; install openssh-server to run integration tests" >&2
    exit 1
fi

log "starting; entropy_avail=$(cat /proc/sys/kernel/random/entropy_avail 2>/dev/null || echo '?')"

WORKDIR="$(mktemp -d)"
cleanup() {
    if [[ -n "${SSHD_PID:-}" ]]; then
        kill "$SSHD_PID" 2>/dev/null || true
        wait "$SSHD_PID" 2>/dev/null || true
    fi
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

log "generating host/client keys"
ssh-keygen -q -t ed25519 -N '' -f "$WORKDIR/hostkey"
ssh-keygen -q -t ed25519 -N '' -f "$WORKDIR/clientkey"
cp "$WORKDIR/clientkey.pub" "$WORKDIR/authorized_keys"
log "keys ready; entropy_avail=$(cat /proc/sys/kernel/random/entropy_avail 2>/dev/null || echo '?')"

# Retry with a fresh random port a few times in case of a rare bind collision
# with a lingering socket from a previous run.
PORT=0
for attempt in 1 2 3 4 5; do
    CANDIDATE_PORT=$(( (RANDOM % 20000) + 20000 ))

    cat > "$WORKDIR/sshd_config" <<EOF
Port $CANDIDATE_PORT
ListenAddress 127.0.0.1
HostKey $WORKDIR/hostkey
AuthorizedKeysFile $WORKDIR/authorized_keys
PidFile $WORKDIR/sshd.pid
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
UsePAM no
StrictModes no
LogLevel ERROR
Subsystem sftp internal-sftp
EOF

    "$SSHD_BIN" -f "$WORKDIR/sshd_config" -D -e > "$WORKDIR/sshd.log" 2>&1 &
    SSHD_PID=$!
    log "sshd started (pid=$SSHD_PID), waiting for port $CANDIDATE_PORT"

    ready=0
    for _ in $(seq 1 50); do
        if ! kill -0 "$SSHD_PID" 2>/dev/null; then
            break
        fi
        if (exec 3<>"/dev/tcp/127.0.0.1/$CANDIDATE_PORT") 2>/dev/null; then
            exec 3<&- 3>&-
            ready=1
            break
        fi
        sleep 0.1
    done

    if [[ "$ready" -eq 1 ]]; then
        PORT="$CANDIDATE_PORT"
        break
    fi

    kill "$SSHD_PID" 2>/dev/null || true
    wait "$SSHD_PID" 2>/dev/null || true
    unset SSHD_PID
    echo "sshd failed to bind port $CANDIDATE_PORT (attempt $attempt), retrying..." >&2
done

if [[ "$PORT" -eq 0 ]]; then
    echo "sshd never came up after several attempts" >&2
    echo "--- last sshd log ---" >&2
    cat "$WORKDIR/sshd.log" >&2 2>/dev/null || true
    exit 1
fi

touch "$WORKDIR/known_hosts"

export SSHPP_TEST_HOST=127.0.0.1
export SSHPP_TEST_PORT="$PORT"
export SSHPP_TEST_USER="$(whoami)"
export SSHPP_TEST_KEY="$WORKDIR/clientkey"
export SSHPP_TEST_KNOWN_HOSTS="$WORKDIR/known_hosts"

log "sshd up on port $PORT; launching test binary; entropy_avail=$(cat /proc/sys/kernel/random/entropy_avail 2>/dev/null || echo '?')"

# Line-buffer stdout/stderr so that if ctest ever has to kill this on a TIMEOUT, whatever
# ran before the hang is still visible in the captured output instead of sitting lost in a
# libc stdio block buffer (observed: CI timeouts here previously showed zero output at all).
#
# stdbuf works by LD_PRELOAD-ing libstdbuf.so into the child, which breaks ASan/UBSan
# builds ("ASan runtime does not come first in initial library list") since the sanitizer
# runtime must be first in the preload order. Skip stdbuf for sanitizer-instrumented
# binaries; they flush enough on their own (and abort loudly) that buffering is a
# non-issue there.
#
# Deliberately NOT `exec`d: exec would replace this shell process with the test
# binary, discarding the `trap cleanup EXIT` above before it ever runs - sshd (still
# running in the background) would then be orphaned holding ctest's captured
# stdout/stderr pipe open forever, so ctest would hang reading for EOF until its own
# TIMEOUT killed the whole process tree (observed: a full-length "Timeout" ctest
# failure immediately after the test binary itself had already printed "All tests
# passed" and exited). Backgrounded and `wait`ed (rather than a plain foreground
# command) purely so the polling loop below can watch it via `kill -0`; the EXIT
# trap still fires and kills sshd once this script exits, and the exit code is
# still correctly propagated via `wait`'s own status.
if ldd "$TEST_BIN" 2>/dev/null | grep -qE 'libasan|libubsan|libtsan|libmsan'; then
    "$TEST_BIN" &
else
    stdbuf -oL -eL "$TEST_BIN" &
fi
TESTBIN_PID=$!

# Diagnostic: if the test binary is still running well past when it normally
# would be done, dump thread wchans/syscalls and a process snapshot to stderr
# before ctest's own 300s TIMEOUT kills everything, so a future recurrence of
# the still-unexplained intermittent hang here (observed repeatedly in CI,
# essentially never reproducible locally even under heavy artificial CPU
# stress) leaves actual evidence instead of nothing. Implemented as a plain
# polling loop in THIS process (not a separate backgrounded watchdog) so
# there's no separate process that could hold ctest's captured stdout/stderr
# pipe open after this script exits - the exact class of bug fixed above for
# sshd. `wait` returns immediately once the test binary exits either way.
DUMPED=0
for _ in $(seq 1 48); do  # 48 * 5s = 240s
    if ! kill -0 "$TESTBIN_PID" 2>/dev/null; then
        break
    fi
    sleep 5
    if [[ "$DUMPED" -eq 0 ]] && [[ $((SECONDS)) -ge 240 ]]; then
        DUMPED=1
        log "test binary still running after ~240s; dumping diagnostics"
        echo "entropy_avail=$(cat /proc/sys/kernel/random/entropy_avail 2>/dev/null || echo '?')" >&2
        ps auxww >&2 2>/dev/null || true
        for tid in /proc/"$TESTBIN_PID"/task/*; do
            [[ -d "$tid" ]] || continue
            echo "thread $(basename "$tid"): comm=$(cat "$tid/comm" 2>/dev/null) wchan=$(cat "$tid/wchan" 2>/dev/null) syscall=$(cat "$tid/syscall" 2>/dev/null)" >&2
        done
    fi
done

wait "$TESTBIN_PID"
exit $?
