# 01 — Goals and Scope

## 1.1 Motivation

libssh is a mature, well-audited C library, but its C API pushes a lot of work onto the caller:

* Manual `ssh_new` / `ssh_free`, `ssh_channel_new` / `ssh_channel_free` pairs with strict
  destruction ordering (a channel must not outlive its session).
* `ssh_options_set` is a variadic-ish `void*` interface with per-option pointer/int semantics
  that the compiler cannot check.
* Errors are reported as sentinel `int`s (`SSH_OK`, `SSH_ERROR`, `SSH_AGAIN`,
  `SSH_AUTH_DENIED`, …) with the human-readable reason stashed on the session
  (`ssh_get_error`), so the failure detail is easy to lose.
* SFTP has a *second*, independent error channel (`sftp_get_error` → `SSH_FX_*`).
* Buffers are raw `void*` + `uint32_t`, with `ssh_string`/`ssh_buffer` needing explicit frees.

`libsshpp` removes that boilerplate without hiding libssh: every wrapper exposes the raw
handle, so users can always drop down to the C API.

## 1.2 Goals

| G# | Goal |
|----|------|
| G1 | **Zero leaks by construction.** All libssh handles are owned by move-only RAII types with correct destruction ordering enforced at compile time or by shared ownership. |
| G2 | **Type-safe options.** `SessionOptions` is a checked struct/builder; no `void*` casts in user code. |
| G3 | **One coherent error model.** libssh, SFTP `SSH_FX_*`, and getaddrinfo/OS errors all funnel into `std::error_code`-compatible categories, plus the session's textual reason. |
| G4 | **Both exception and error-code styles.** Throwing API is primary; a `try_*` sibling returning `Result<T>` exists for every fallible call. No API is exception-only. |
| G5 | **Idiomatic C++ surfaces.** Ranges/iterators for directories, `std::istream`/`std::ostream` for channels, `std::string_view`/`std::span`-like views for buffers, `std::filesystem::path` for paths. |
| G6 | **Full feature parity** with libssh for the areas listed in §1.4 — the wrapper must never be the reason a user has to abandon it. |
| G7 | **Easy consumption.** `conan install` + `find_package(libsshpp)` + `target_link_libraries(app PRIVATE libsshpp::libsshpp)` and nothing else. Also usable via `FetchContent`/CPM and as header-only. |
| G8 | **No hidden global state.** Global libssh init/threading setup is explicit and idempotent (`sshpp::Library`). |
| G9 | **Testable.** The server module lets the test-suite run a real SSH server in-process, so >80 % of integration tests need no external daemon. |

## 1.3 Non-goals

* **Not** a protocol re-implementation. `libsshpp` never parses SSH packets itself.
* **Not** an async/coroutine framework in v1. See [11 — Roadmap](11-versioning-and-roadmap.md).
* **Not** a CLI tool. Examples are provided, but `ssh`/`scp` clones are not shipped.
* **No** SSHv1, no telnet/rsh fallbacks.
* **No** bundled crypto backend selection logic — that is libssh's build-time concern; we only
  *report* what the linked libssh supports.
* **No** ABI stability across minor versions in the `0.x` series (see §11.2).

## 1.4 Feature scope for v1.0

| Area | Included | libssh surface wrapped |
|------|----------|------------------------|
| Global init / logging / threading | ✅ | `ssh_init`, `ssh_finalize`, `ssh_set_log_level`, `ssh_set_log_callback`, `ssh_threads_set_callbacks` |
| Session lifecycle | ✅ | `ssh_new`, `ssh_free`, `ssh_connect`, `ssh_disconnect`, `ssh_is_connected`, `ssh_blocking_flush`, `ssh_get_fd` |
| Options | ✅ | all `SSH_OPTIONS_*`, `ssh_options_parse_config`, `ssh_options_get*` |
| Host-key verification | ✅ | `ssh_session_is_known_server`, `ssh_session_update_known_hosts`, `ssh_get_server_publickey`, `ssh_get_publickey_hash`, `ssh_known_hosts_parse_line` |
| Authentication | ✅ | `none`, `list`, `password`, `publickey`, `publickey_auto`, `try_publickey`, `kbdint` (full prompt loop), `agent`, `gssapi` |
| Keys / PKI | ✅ | `ssh_pki_import_*`, `ssh_pki_export_*`, `ssh_pki_generate`, `ssh_key_type`, `ssh_key_cmp`, fingerprints |
| Channels | ✅ | open session, `request_exec`, `request_shell`, `request_pty[_size]`, `request_subsystem`, `request_env`, `request_send_signal`, `change_pty_size`, read/write/stderr, EOF, exit status/signal |
| Event loop primitives | ✅ | `ssh_event_*`, `ssh_channel_select`, `ssh_channel_poll_timeout` |
| SFTP | ✅ | session, file I/O (incl. 64-bit seek), directories, stat/lstat/fstat/setstat, chmod/chown/utimes, symlink/readlink, rename/unlink/mkdir/rmdir, canonicalize, statvfs, limits, extensions, async read (`sftp_aio_*` where available) |
| SCP | ✅ | `ssh_scp_*` read/write/recursive, request loop, permissions & 64-bit sizes |
| Port forwarding | ✅ | direct-tcpip (local), `tcpip-forward` (remote) incl. `ssh_channel_accept_forward`/`cancel_forward`, `open_forward_unix`, X11 request + `ssh_channel_accept_x11` |
| Server side | ✅ | `ssh_bind_*`, `ssh_handle_key_exchange`, `ssh_set_auth_methods`, message API (`ssh_message_*`) **and** callback API (`ssh_set_server_callbacks`, `ssh_set_channel_callbacks`) |
| Proxy / jump hosts | ✅ (via `ProxyCommand` + `ProxyJump` option and `Session::attach_fd`) | `SSH_OPTIONS_PROXYCOMMAND`, `SSH_OPTIONS_FD` |
| PCAP capture | ⚠️ optional module | `ssh_pcap_file_*` |

## 1.5 Requirements

### Functional

* **FR-1** — A user can connect, verify the host key against `known_hosts`, authenticate with
  any libssh-supported method, run a remote command, and read its stdout/stderr and exit
  status in ≤ 15 lines of code.
* **FR-2** — Every wrapper type exposes `native_handle()` returning the raw libssh handle, and
  a static `from_native(handle, ownership)` adopting or borrowing it.
* **FR-3** — Any failure surfaces: numeric libssh code, category, textual reason from
  `ssh_get_error`, and (for SFTP) the `SSH_FX_*` sub-code.
* **FR-4** — Timeouts are expressible with `std::chrono::duration` on every blocking call that
  libssh supports a timeout for.
* **FR-5** — Cancellation: a blocking session can be interrupted from another thread via
  `Session::request_cancel()` (implemented with a self-pipe/`ssh_set_blocking` + `Event`).

### Non-functional

* **NFR-1** — No dynamic allocation in the hot read/write path beyond what libssh itself does;
  `read_some()` writes into a caller-supplied buffer.
* **NFR-2** — Wrapper overhead per call: at most one virtual dispatch (only for user-supplied
  policy objects) and no exception thrown on success paths.
* **NFR-3** — Compiles clean at `-Wall -Wextra -Wpedantic -Wconversion` / `/W4` with
  warnings-as-errors in CI.
* **NFR-4** — Headers do **not** include `<libssh/libssh.h>`; the C API is confined to the
  implementation via opaque handle typedefs (see [02 §2.4](02-architecture.md#24-hiding-the-c-api)).
* **NFR-5** — Clean under ASan/UBSan/TSan and Valgrind for the whole test suite.

## 1.6 Supported platforms and toolchains

| Platform | Toolchain | Tier |
|----------|-----------|------|
| Linux (glibc ≥ 2.28, musl) | GCC 9+, Clang 12+ | 1 — CI-tested |
| macOS 12+ (x86_64, arm64) | AppleClang 14+ | 1 — CI-tested |
| Windows 10+ | MSVC 19.29+ (VS 2019 16.11), clang-cl | 1 — CI-tested |
| FreeBSD 13+ | Clang 14+ | 2 — best-effort |
| MinGW-w64 | GCC 12+ | 2 — best-effort |

libssh versions: **0.10.4 minimum**, **0.11.x supported**. Features added after 0.10.4
(`sftp_aio_*`, `ssh_channel_get_exit_state`, `SSH_OPTIONS_CONTROL_MASTER`) are compiled in
conditionally and reported through `sshpp::features()` — see
[09 §9.4](09-build-and-packaging.md#94-feature-detection-and-generated-headers).

## 1.7 Licensing

libssh is **LGPL-2.1-or-later**. Because `libsshpp` is a derived work that links libssh, the
library itself ships under **LGPL-2.1-or-later** so downstream users retain the same relinking
rights they already have with libssh.

Practical consequences that must be documented in the top-level `README.md`:

* Linking `libsshpp` **statically** into a proprietary application propagates LGPL relinking
  obligations. The default Conan option is therefore `shared=False` for `libsshpp` but the
  recipe warns and exposes `libssh/*:shared=True` guidance.
* Header-only mode is equivalent to static linking for licensing purposes.
* Inline functions/templates in public headers are covered by the LGPL §5 "header file"
  exemption, but we keep templates thin regardless.

`SPDX-License-Identifier: LGPL-2.1-or-later` goes at the top of every source file, and a
`LICENSE` + `THIRD_PARTY_NOTICES.md` are installed with the package.
