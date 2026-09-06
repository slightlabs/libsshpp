#!/usr/bin/env bash
# Spins up an ephemeral, unprivileged sshd instance with a throwaway host key and
# a throwaway client key trusted via authorized_keys, runs the given test binary
# against it with connection details in the environment, then tears everything down.
set -euo pipefail

TEST_BIN="${1:?usage: run_with_sshd.sh <test-binary>}"

SSHD_BIN="$(command -v sshd || echo /usr/sbin/sshd)"
if [[ ! -x "$SSHD_BIN" ]]; then
    echo "sshd not found; install openssh-server to run integration tests" >&2
    exit 1
fi

WORKDIR="$(mktemp -d)"
cleanup() {
    if [[ -n "${SSHD_PID:-}" ]]; then
        kill "$SSHD_PID" 2>/dev/null || true
        wait "$SSHD_PID" 2>/dev/null || true
    fi
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

ssh-keygen -q -t ed25519 -N '' -f "$WORKDIR/hostkey"
ssh-keygen -q -t ed25519 -N '' -f "$WORKDIR/clientkey"
cp "$WORKDIR/clientkey.pub" "$WORKDIR/authorized_keys"

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
# passed" and exited). Running it as a plain foreground command lets the EXIT trap
# fire and kill sshd once the test binary exits, which also correctly propagates its
# exit code since nothing after it modifies `$?`.
if ldd "$TEST_BIN" 2>/dev/null | grep -qE 'libasan|libubsan|libtsan|libmsan'; then
    "$TEST_BIN"
else
    stdbuf -oL -eL "$TEST_BIN"
fi
