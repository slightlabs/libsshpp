# libsshpp

A modern **C++17** wrapper around [libssh](https://www.libssh.org/), packaged with **CMake** and
**Conan 2**.

> **Status: M0 through M3 implemented, plus most of the remaining design (with a few
> documented scope trims).** `Library`, error handling, `Session`, `SessionOptions`,
> authenticators, `Key`/PKI, `KnownHosts`, `HostKeyVerifier` policies, `Channel`, `Exec`,
> `Shell` (incl. `try_interact()` and console prompt helpers under `LIBSSHPP_WITH_CONSOLE`),
> the SFTP module (`sftp::Sftp`/`File`/`Directory`, transfer helpers with path-traversal
> hardening, pipelined `File::ReadAhead`/`WriteBehind`), SCP (`scp::Reader`/`Writer` +
> `try_upload`/`try_download`), TCP/UNIX-socket port forwarding (`open_direct`,
> `LocalForward`, `RemoteForward`, `X11Forwarder`, `SocksProxy`, `Connector`/
> `BidirectionalPump`), and both server styles - message-pull (`server::Bind`/`Session`/
> `Message`) and event-driven callbacks (`SessionHandler`/`ChannelHandler`,
> `SimpleAuthHandler`, `CommandHandler`, `SftpSubsystemHandler`, `server::TestServer`) -
> are implemented and tested against a real `sshd` (and, for the server module, against
> `libsshpp`'s own client) — see [tests/](tests/), [examples/01_exec.cpp](examples/01_exec.cpp).
>
> Relative to the full design, the following are **not implemented**: the forwarding
> module still serves one connection at a time per forwarder with a poll-based pump
> (`BidirectionalPump` included) rather than driving everything through `ssh_connector`
> via `Event`; the callback-style server has no keyboard-interactive auth or
> tcpip-forward/direct-tcpip channel handling (the libssh version this targets has no
> callback slots for them - use the message style for those) and no `Options::faults`
> fault-injection in `TestServer`; there is no pcap module. The design documents in
> [`docs/design/`](docs/design/README.md) remain the normative reference — code that
> contradicts them is a bug in one or the other.

---

## What it gives you

* **RAII everywhere.** Sessions, channels, SFTP handles and keys are move-only types with
  correct destruction ordering. A `Channel` can never outlive the `ssh_session` it belongs to.
* **One error model.** libssh return codes, `ssh_get_error()` text, and SFTP `SSH_FX_*` status
  codes all land in `std::error_code`-compatible categories.
* **Exceptions *and* error codes.** Every fallible operation has a throwing form and a
  `try_`-prefixed form returning `Result<T>`. Pick one; no API is exception-only.
* **Type-safe options.** No `ssh_options_set(s, SSH_OPTIONS_PORT, &port)` `void*` guessing.
* **Full feature coverage.** Session/auth, channels/exec/PTY, SFTP, SCP, port forwarding, X11,
  known-hosts, PKI, and the **server** side.
* **Safe by default.** Host-key verification is a required explicit step, shell quoting is
  provided, SFTP tree transfers reject path traversal, and forwarders bind to loopback.

## Ten-line example

```cpp
#include <sshpp/sshpp.hpp>

int main() {
    sshpp::Library lib;

    sshpp::SessionOptions opts;
    opts.host = "example.com";
    opts.user = "deploy";
    opts.timeout = std::chrono::seconds{10};

    sshpp::Session ssh{opts};
    ssh.connect();
    ssh.verify_host_key(sshpp::StrictHostKeyPolicy{});
    ssh.authenticate(sshpp::auth::PublicKeyAuto{});

    auto r = sshpp::Exec{ssh}.run("uptime");
    std::cout << r.stdout_text;
    return r.exit_code;
}
```

Same thing without exceptions:

```cpp
if (auto r = ssh.try_connect(); !r) { std::cerr << r.error().to_string(); return 1; }
```

## Documentation

| Document | Contents |
|---|---|
| [API reference (Doxygen)](https://slightlabs.github.io/libsshpp/) | Generated from `include/sshpp/` on every tagged release |
| [Design index](docs/design/README.md) | Start here |
| [01 Goals and scope](docs/design/01-goals-and-scope.md) | Requirements, non-goals, platforms, licensing |
| [02 Architecture](docs/design/02-architecture.md) | Layering, lifetime model, threading, layout, ADRs |
| [03 Error handling](docs/design/03-error-handling.md) | `errc`, `ErrorInfo`, `Result<T>`, exception hierarchy |
| [04 Core API](docs/design/04-api-core.md) | `Library`, `Session`, options, auth, keys, known hosts |
| [05 Channels](docs/design/05-api-channels.md) | `Channel`, `Exec`, `Shell`, PTY, `Event` |
| [06 SFTP and SCP](docs/design/06-api-sftp-scp.md) | File/dir APIs, transfers, attributes |
| [07 Forwarding](docs/design/07-api-forwarding.md) | `-L`, `-R`, `-D`, X11, byte pumps |
| [08 Server](docs/design/08-api-server.md) | `Bind`, handlers, message loop, `TestServer` |
| [09 Build and packaging](docs/design/09-build-and-packaging.md) | CMake, Conan, install/export, header-only |
| [10 Testing and CI](docs/design/10-testing-and-ci.md) | Test pyramid, fuzzing, sanitizers, CI matrix |
| [11 Versioning and roadmap](docs/design/11-versioning-and-roadmap.md) | SemVer/ABI policy, milestones |

## Planned consumption

### Conan 2

```ini
# conanfile.txt
[requires]
libsshpp/1.0.0

[generators]
CMakeDeps
CMakeToolchain
```

```bash
conan install . --output-folder=build --build=missing
cmake --preset conan-release
cmake --build --preset conan-release
```

### CMake

```cmake
find_package(libsshpp CONFIG REQUIRED)
target_link_libraries(app PRIVATE libsshpp::libsshpp)
```

### Build options

| Option | Default | Effect |
|---|---|---|
| `LIBSSHPP_HEADER_ONLY` | `OFF` | Build as an `INTERFACE` library, per [09 §9.3](docs/design/09-build-and-packaging.md#93-header-only-mode) |
| `LIBSSHPP_WITH_SFTP` | `ON` | SFTP module |
| `LIBSSHPP_WITH_SCP` | `ON` | SCP module |
| `LIBSSHPP_WITH_SERVER` | `ON` | Server module: message-style *and* event-driven callback style, `TestServer` |
| `LIBSSHPP_WITH_FORWARDING` | `ON` | Port forwarding: `open_direct`, `LocalForward`, `RemoteForward`, `X11Forwarder`, `SocksProxy` |
| `LIBSSHPP_WITH_CONSOLE` | `OFF` | tty helpers: `Shell::try_interact()`, `auth::console_*_prompt()`, `KeyboardInteractive::console_handler()`, `Chain::interactive_default()` |
| `LIBSSHPP_BUILD_TESTS` | top-level only | Catch2 test suite |
| `LIBSSHPP_SANITIZERS` | `""` | e.g. `address;undefined` |

Full list in [09 §9.2](docs/design/09-build-and-packaging.md#92-top-level-cmakeliststxt-structure).
Note: `LIBSSHPP_WITH_CONSOLE` defaults to `OFF` since a library embedded in a server has
no business putting a terminal in raw mode or installing a `SIGWINCH` handler; opt in for
CLI-style clients.

## Building from source (current state)

```bash
sudo apt install libssh-dev catch2 openssh-server   # or your distro's equivalents
cmake -S . -B build -DLIBSSHPP_BUILD_TESTS=ON -DLIBSSHPP_SYSTEM_TESTS=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

`LIBSSHPP_SYSTEM_TESTS=ON` builds an integration test that spins up a throwaway, unprivileged
`sshd` (ephemeral host/client keys, temp `known_hosts`, high port) and exercises connect →
verify host key → authenticate → exec end-to-end; see
[tests/integration/run_with_sshd.sh](tests/integration/run_with_sshd.sh).

## Requirements

* C++17 compiler — GCC 9+, Clang 12+, AppleClang 14+, MSVC 19.29+
* CMake 3.23+
* libssh 0.10.4 – 0.11.x (not vendored; bring your own via Conan, vcpkg, or a system package)

## Licensing

`libsshpp` is **LGPL-2.1-or-later**, matching libssh (see [LICENSE](LICENSE) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)).

Linking `libsshpp` **statically** (or using header-only mode) into a proprietary application
propagates the LGPL's relinking obligations. The Conan recipe therefore defaults to
`libssh/*:shared=True`. If you need different terms, obtain them from the libssh project — a
wrapper cannot grant what it does not own. See
[01 §1.7](docs/design/01-goals-and-scope.md#17-licensing).

## Security

Host-key verification is a mandatory, explicit step: `Session::connect()` does not verify, and
using a channel before `verify_host_key()` fails. Use `StrictHostKeyPolicy` or
`PinnedHostKeyPolicy` in production; `AcceptAnyHostKeyPolicy` requires an
`i_understand_this_is_insecure()` tag to construct.

When building remote commands from untrusted input, use the `argv` overload of `Exec::run` (or
`sshpp::shell_quote`) — the `std::string_view` overload passes the command to the remote shell
verbatim.

Report vulnerabilities privately per [SECURITY.md](SECURITY.md).

## Contributing

See [10 §10.10](docs/design/10-testing-and-ci.md#1010-definition-of-done-for-a-feature-pr) for
the definition of done. Design changes go through a PR against `docs/design/` first.
