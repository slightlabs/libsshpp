# Changelog

All notable changes to this project are documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this
project follows the SemVer/ABI policy in
[11 — Versioning and roadmap](docs/design/11-versioning-and-roadmap.md).

## [Unreleased]

No tagged release yet. Implementation status against the milestones in
[11 §11.5](docs/design/11-versioning-and-roadmap.md#115-milestones):

### Added

* **M0/M1 — Foundation and client core**: `Library`, error handling
  (`errc`/`sftp_errc`/`ErrorInfo`/`Result<T>`/exception hierarchy),
  `SessionOptions`, `Session`, `Key`/PKI, `KnownHosts`, `HostKeyVerifier`
  policies (Strict/TOFU/AcceptAny/Pinned/Callback), all authenticators,
  `Channel`, `Event`, `Exec` (with `shell_quote`).
* **M2 — SFTP**: `sftp::Sftp`/`File`/`Directory`/`DirectoryIterator`,
  `sftp/algorithms.hpp` transfer helpers with path-traversal hardening,
  pipelined `File::ReadAhead`/`File::WriteBehind`.
* **SCP**: `scp::Reader`/`Writer`, `try_upload`/`try_download`.
* **Forwarding**: `open_direct`, `LocalForward`, `RemoteForward` (one
  connection at a time per forwarder, poll-based pump, POSIX sockets only),
  plus UNIX-socket forward targets, `Connector` (thin `ssh_connector_*` wrap),
  `BidirectionalPump`, `X11Forwarder`, and `SocksProxy` (SOCKS4/5 dynamic
  forwarding).
* **M3 — Server**: `server::Bind`, `server::Session`, `server::Message`
  (message-pull style, docs/design/08 §8.5), plus the event-driven callback
  style (§8.6: `SessionHandler`/`ChannelHandler` via `detail::HandlerBridge`),
  `SimpleAuthHandler`, `CommandHandler`, `SftpSubsystemHandler` (chroot-style,
  hardened path resolution), and `server::TestServer` for hermetic tests.
* **Shell/console**: `<sshpp/shell.hpp>` (`Shell::try_start`/`try_write`/
  `try_read`/`try_resize`/`try_send_signal`, plus `try_interact()` under
  `LIBSSHPP_WITH_CONSOLE`), console auth prompts (`auth::console_password_prompt`,
  `auth::console_passphrase_prompt`, `KeyboardInteractive::console_handler`,
  `Chain::interactive_default`), all gated by `LIBSSHPP_WITH_CONSOLE` (default `OFF`).
* CMake build (compiled + install rules), header-only mode (`LIBSSHPP_HEADER_ONLY=ON`,
  via `.ipp` indirection per docs/design/09 §9.3), Conan-ready structure, Catch2
  unit tests, and integration tests that spin up a real ephemeral `sshd` (or, for
  the server module, use `libsshpp`'s own client and server together) — all run
  in both compiled and header-only configurations.
* `LICENSE` (LGPL-2.1-or-later), `THIRD_PARTY_NOTICES.md`, `SECURITY.md`.

### Known gaps relative to the design

See the README's status note for the full list. In short: no pcap module; the
forwarding module's pumps are poll-based rather than driving everything
through `ssh_connector` via `Event`; the callback-style server has no
keyboard-interactive auth, tcpip-forward/direct-tcpip channel handling, or
`TestServer` fault injection (the target libssh version has no callback
support for the first two).
