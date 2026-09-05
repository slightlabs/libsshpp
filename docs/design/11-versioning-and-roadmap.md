# 11 — Versioning, Compatibility and Roadmap

## 11.1 Semantic versioning

`libsshpp` follows [SemVer 2.0](https://semver.org/) for its **API**.

| Change | Bump |
|---|---|
| New type, new function, new defaulted parameter appended | Minor |
| New `errc` enumerator appended before `unknown` | Minor (callers must have a `default`) |
| New virtual function on a user-implementable interface (`SessionHandler`, `HostKeyVerifier`) | Minor **only if** it has a default implementation; otherwise major |
| Behaviour change that can break a correct caller | Major |
| Removing a deprecated symbol | Major |
| Bug fix with no API change | Patch |
| Raising the minimum libssh version | Minor (documented), unless it removes a feature → major |
| Raising the minimum C++ standard | Major |

Pre-1.0 (`0.x`), minor bumps may break API; this is stated in the README.

## 11.2 ABI policy

* ABI is stable within a major version. `SOVERSION` = major.
* Enforced mechanically by `abidiff` in CI against the previous release's shared library
  ([10 §10.7](10-testing-and-ci.md#107-static-analysis-and-hygiene)).
* Techniques used to keep ABI breakage avoidable:
  * `inline namespace v1 { }` inside `sshpp`, so a future `v2` can coexist in one binary.
  * Every polymorphic public class has a virtual destructor and is documented as
    "derive-only, do not add members downstream".
  * Types likely to grow (`SessionOptions`, `BindOptions`, `TransferOptions`) are passed by
    `const&` and never returned by value across the ABI boundary in a way that fixes their size
    in inline code — accessors are out-of-line.
  * Handle classes (`Session`, `Channel`, `Sftp`) hold exactly one `shared_ptr`/pointer member;
    new state goes into the pimpl'd core, not the public class.
  * No `std::function`/`std::string` members in classes that cross the DLL boundary by value
    with inline construction; such members live in the impl.
* Header-only and static builds are exempt (they are recompiled anyway); the policy exists for
  distro and shared-library consumers.

## 11.3 Deprecation process

1. Mark with `SSHPP_DEPRECATED("use X instead")` (expands to `[[deprecated]]`) in release *N*.
2. Document in `CHANGELOG.md` under "Deprecated" with the removal target.
3. Keep working for at least two minor releases **and** at least six months.
4. Remove in the next major release.

`SSHPP_DISABLE_DEPRECATION_WARNINGS` lets consumers silence the noise while they migrate.

## 11.4 libssh compatibility policy

* Minimum supported libssh is stated in `README.md`, checked at configure time, and asserted at
  runtime by `Library::features()`.
* New libssh features are adopted behind a `SSHPP_HAS_*` macro with a working fallback, never a
  hard requirement, until the minimum version catches up.
* The minimum is raised at most once per minor release, and only to a version present in the
  current Debian stable / Ubuntu LTS / RHEL, or available on ConanCenter for at least six
  months.
* Security advisories in libssh are tracked; a libssh CVE that requires a wrapper-side
  workaround produces an immediate patch release.

## 11.5 Milestones

### M0 — Skeleton (foundation)

* Repository, CMake project, Conan recipe, CI skeleton, `Library`, `error.hpp`, `result.hpp`,
  `types.hpp`, enum mapping infrastructure + tests.
* **Exit criterion:** `conan create .` succeeds on all tier-1 platforms; `test_package` links.

### M1 — Client core

* `SessionOptions`, `Session`, `KnownHosts`, `HostKeyVerifier` policies, `Key`, all
  authenticators, `Channel`, `Exec`.
* `server::TestServer` (minimum viable: password + pubkey auth, exec) — needed to test M1.
* **Exit criterion:** `examples/01_exec.cpp` works against `TestServer` and a real sshd; the
  auth and host-key coverage matrices from [10 §10.3](10-testing-and-ci.md) are green.

### M2 — SFTP

* `sftp::Sftp`, `File`, `Directory`, `Attributes`, iteration, `algorithms.hpp` transfers with
  progress/resume/atomic, `ReadAhead`/`WriteBehind`.
* **Exit criterion:** a 1 GiB transfer over a 100 ms-RTT emulated link reaches ≥ 80 % of raw
  channel throughput; path-traversal fuzz target clean.

### M3 — Server, SCP, forwarding

* Full `server::` module (message + callback styles, ready-made handlers).
* `scp::Reader`/`Writer` + helpers.
* `LocalForward`, `RemoteForward`, `open_direct`, `SocksProxy`, `X11Forwarder`, `Connector`.
* **Exit criterion:** `examples/10_minimal_server.cpp` accepts a connection from OpenSSH's
  `ssh(1)`; forwarding tests green under TSan.

### M4 — Polish and 1.0

* `Shell::interact`, `ChannelIOStream`, pcap module, benchmarks.
* Doxygen site + tutorials, README, migration notes from raw libssh.
* ABI baseline captured; header-only and minimal-option builds green.
* **Exit criterion:** all of [10 §10.10](10-testing-and-ci.md#1010-definition-of-done-for-a-feature-pr)
  satisfied repo-wide; coverage gate met; no known high/medium CodeQL findings.

## 11.6 Post-1.0

### 1.1 — Async, phase 1 (event-loop friendly)

Formalize the non-blocking contract that `Event` + `errc::would_block` already imply:

* `AsyncSession` wrapping the same `SessionCore` in non-blocking mode.
* Explicit readiness API: `wants_read()`, `wants_write()`, `on_readable()`, `on_writable()`.
* Reference integrations (separate optional packages, no core dependency):
  `libsshpp-asio`, `libsshpp-libuv`, `libsshpp-qt`.

### 1.2 — Coroutines (C++20 build only)

* `task<T>` / `Awaitable` returning versions of every `try_*` operation, guarded by
  `SSHPP_HAS_COROUTINES`, built only when the consumer compiles as C++20.
* Sender/receiver (P2300) adapters once the standard settles — explicitly *not* before.

### 1.3 and beyond — candidates

| Idea | Notes |
|---|---|
| Agent protocol client (`ssh-agent` socket, key listing, signing) | libssh exposes little; would be our own implementation |
| Certificate support (`@cert-authority`, principals, validity) | Needs libssh cert APIs to mature |
| FIDO/U2F (`sk-ssh-ed25519`) auth flows | Depends on libssh + libfido2 |
| Connection multiplexing (`ControlMaster`) | libssh 0.11 has `SSH_OPTIONS_CONTROL_MASTER`; needs a session-pool abstraction |
| Session pool / connection reuse for tooling | Layer 4, no protocol work |
| `ProxyJump` chains without `ProxyCommand` | Build a `Session` over a `direct-tcpip` channel of another `Session` via `SSH_OPTIONS_FD` + a socketpair pump |
| C API for FFI consumers | Only if there is demand |

`ProxyJump` chaining is the highest-value item on this list and is already unblocked by the
v1 design (`SessionOptions::fd` + `Connector`); it is post-1.0 only because it needs its own
test matrix.

## 11.7 Explicit non-plans

* No TLS/HTTPS transport, no SSH-over-WebSocket.
* No bundling or vendoring of libssh, OpenSSL, or zlib.
* No `std::filesystem`-style global functions operating on an implicit session.
* No Python/Rust bindings in this repository.
* No support for compilers older than the tier-1 list in
  [01 §1.6](01-goals-and-scope.md#16-supported-platforms-and-toolchains).
