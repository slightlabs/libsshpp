# Contributing

Contributions are welcome. Before opening a PR:

1. Read the [Design](design/README.md) documents relevant to the area you're touching — they
   are the normative reference for the public API, build system, and packaging. Design changes
   go through a PR against `docs/design/` first.
2. Check [10. Testing and CI §10.10](design/10-testing-and-ci.md#1010-definition-of-done-for-a-feature-pr)
   for the definition of done for a feature PR.

## Building from source

```bash
sudo apt install libssh-dev catch2 openssh-server   # or your distro's equivalents
cmake -S . -B build -DLIBSSHPP_BUILD_TESTS=ON -DLIBSSHPP_SYSTEM_TESTS=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

`LIBSSHPP_SYSTEM_TESTS=ON` builds an integration test that spins up a throwaway, unprivileged
`sshd` (ephemeral host/client keys, temp `known_hosts`, high port) and exercises connect →
verify host key → authenticate → exec end-to-end; see
[tests/integration/run_with_sshd.sh](https://github.com/slightlabs/libsshpp/blob/main/tests/integration/run_with_sshd.sh).

## Build options

| Option | Default | Effect |
|---|---|---|
| `LIBSSHPP_HEADER_ONLY` | `OFF` | Build as an `INTERFACE` library, per [09 §9.3](design/09-build-and-packaging.md#93-header-only-mode) |
| `LIBSSHPP_WITH_SFTP` | `ON` | SFTP module |
| `LIBSSHPP_WITH_SCP` | `ON` | SCP module |
| `LIBSSHPP_WITH_SERVER` | `ON` | Server module: message-style *and* event-driven callback style, `TestServer` |
| `LIBSSHPP_WITH_FORWARDING` | `ON` | Port forwarding: `open_direct`, `LocalForward`, `RemoteForward`, `X11Forwarder`, `SocksProxy` |
| `LIBSSHPP_WITH_CONSOLE` | `OFF` | tty helpers: `Shell::try_interact()`, `auth::console_*_prompt()`, `KeyboardInteractive::console_handler()`, `Chain::interactive_default()` |
| `LIBSSHPP_BUILD_TESTS` | top-level only | Catch2 test suite |
| `LIBSSHPP_SANITIZERS` | `""` | e.g. `address;undefined` |

Full list in [09 §9.2](design/09-build-and-packaging.md#92-top-level-cmakeliststxt-structure).
Note: `LIBSSHPP_WITH_CONSOLE` defaults to `OFF` since a library embedded in a server has no
business putting a terminal in raw mode or installing a `SIGWINCH` handler; opt in for
CLI-style clients.

## Security

Report vulnerabilities privately per
[SECURITY.md](https://github.com/slightlabs/libsshpp/blob/main/SECURITY.md) rather than opening
a public issue.
