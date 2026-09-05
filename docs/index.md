# libsshpp

A modern **C++17** wrapper around [libssh](https://www.libssh.org/), packaged with **CMake** and
**Conan 2**.

!!! info "Status"
    M0 through M3 implemented, plus most of the remaining design (with a few documented scope
    trims). `Library`, error handling, `Session`, `SessionOptions`, authenticators, `Key`/PKI,
    `KnownHosts`, `HostKeyVerifier` policies, `Channel`, `Exec`, `Shell` (incl. `try_interact()`
    and console prompt helpers under `LIBSSHPP_WITH_CONSOLE`), the SFTP module
    (`sftp::Sftp`/`File`/`Directory`, transfer helpers with path-traversal hardening, pipelined
    `File::ReadAhead`/`WriteBehind`), SCP (`scp::Reader`/`Writer` + `try_upload`/`try_download`),
    TCP/UNIX-socket port forwarding (`open_direct`, `LocalForward`, `RemoteForward`,
    `X11Forwarder`, `SocksProxy`, `Connector`/`BidirectionalPump`), and both server styles -
    message-pull (`server::Bind`/`Session`/`Message`) and event-driven callbacks
    (`SessionHandler`/`ChannelHandler`, `SimpleAuthHandler`, `CommandHandler`,
    `SftpSubsystemHandler`, `server::TestServer`) - are implemented and tested against a real
    `sshd` (and, for the server module, against `libsshpp`'s own client).

    Relative to the full design, the following are **not implemented**: the forwarding module
    still serves one connection at a time per forwarder with a poll-based pump
    (`BidirectionalPump` included) rather than driving everything through `ssh_connector` via
    `Event`; the callback-style server has no keyboard-interactive auth or
    tcpip-forward/direct-tcpip channel handling (the libssh version this targets has no callback
    slots for them - use the message style for those) and no `Options::faults` fault-injection in
    `TestServer`; there is no pcap module. The [Design](design/README.md) documents remain the
    normative reference — code that contradicts them is a bug in one or the other.

## What it gives you

- **RAII everywhere.** Sessions, channels, SFTP handles and keys are move-only types with
  correct destruction ordering. A `Channel` can never outlive the `ssh_session` it belongs to.
- **One error model.** libssh return codes, `ssh_get_error()` text, and SFTP `SSH_FX_*` status
  codes all land in `std::error_code`-compatible categories.
- **Exceptions *and* error codes.** Every fallible operation has a throwing form and a
  `try_`-prefixed form returning `Result<T>`. Pick one; no API is exception-only.
- **Type-safe options.** No `ssh_options_set(s, SSH_OPTIONS_PORT, &port)` `void*` guessing.
- **Full feature coverage.** Session/auth, channels/exec/PTY, SFTP, SCP, port forwarding, X11,
  known-hosts, PKI, and the **server** side.
- **Safe by default.** Host-key verification is a required explicit step, shell quoting is
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

## Where to go next

- New to libsshpp? Start with the [Design overview](design/README.md), which links every
  design document in reading order.
- Looking for a class or function? See the generated [API Reference](api-reference.md).
- Building or packaging the library? See
  [09. Build and packaging](design/09-build-and-packaging.md).
- Want to contribute? See [Contributing](contributing.md).

## Requirements

- C++17 compiler — GCC 9+, Clang 12+, AppleClang 14+, MSVC 19.29+
- CMake 3.23+
- libssh 0.10.4 – 0.11.x (not vendored; bring your own via Conan, vcpkg, or a system package)

## Licensing

`libsshpp` is **LGPL-2.1-or-later**, matching libssh (see
[LICENSE](https://github.com/slightlabs/libsshpp/blob/main/LICENSE) and
[THIRD_PARTY_NOTICES.md](https://github.com/slightlabs/libsshpp/blob/main/THIRD_PARTY_NOTICES.md)).

Linking `libsshpp` **statically** (or using header-only mode) into a proprietary application
propagates the LGPL's relinking obligations. The Conan recipe therefore defaults to
`libssh/*:shared=True`. If you need different terms, obtain them from the libssh project — a
wrapper cannot grant what it does not own. See
[01 §1.7](design/01-goals-and-scope.md#17-licensing).

## Security

Host-key verification is a mandatory, explicit step: `Session::connect()` does not verify, and
using a channel before `verify_host_key()` fails. Use `StrictHostKeyPolicy` or
`PinnedHostKeyPolicy` in production; `AcceptAnyHostKeyPolicy` requires an
`i_understand_this_is_insecure()` tag to construct.

When building remote commands from untrusted input, use the `argv` overload of `Exec::run` (or
`sshpp::shell_quote`) — the `std::string_view` overload passes the command to the remote shell
verbatim.

Report vulnerabilities privately per
[SECURITY.md](https://github.com/slightlabs/libsshpp/blob/main/SECURITY.md).
