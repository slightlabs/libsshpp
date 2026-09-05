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

    "$SSHD_BIN" -f "$WORKDIR/sshd_config" -D -e &
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
    exit 1
fi

touch "$WORKDIR/known_hosts"

export SSHPP_TEST_HOST=127.0.0.1
export SSHPP_TEST_PORT="$PORT"
export SSHPP_TEST_USER="$(whoami)"
export SSHPP_TEST_KEY="$WORKDIR/clientkey"
export SSHPP_TEST_KNOWN_HOSTS="$WORKDIR/known_hosts"

"$TEST_BIN"
