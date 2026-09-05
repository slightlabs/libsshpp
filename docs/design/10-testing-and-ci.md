# 10 — Testing, Quality and CI

## 10.1 Test pyramid

| Tier | Directory | Needs network? | Runtime budget | What it covers |
|------|-----------|----------------|----------------|----------------|
| Unit | `tests/unit/` | No | < 5 s total | Pure logic: enum mappings, `Result<T>`, `ErrorInfo`, `SessionOptions` validation/parsing, `RemotePath`, `shell_quote`, path-traversal guards, `SecureString` zeroing, SOCKS request parsing, `Fingerprint` formatting |
| Integration | `tests/integration/` | Loopback only | < 60 s total | Full client↔server flows against `server::TestServer` |
| System | `tests/system/` | Docker | opt-in | Real OpenSSH server: interop, `~/.ssh/config`, agent, PAM keyboard-interactive, SCP |
| Fuzz | `tests/fuzz/` | No | CI-scheduled | Parsers we own |
| Benchmark | `bench/` | Loopback | manual | Throughput and wrapper overhead |

Framework: **Catch2 v3** (from Conan). Chosen over GTest for header-simplicity, `SECTION`-based
fixtures, and built-in generators for the option matrices.

## 10.2 Unit tests without a network

The interesting property: most bugs in an SSH wrapper are not protocol bugs, they are
*translation* bugs. Those are testable with zero I/O.

* **Enum mapping** — for every `enum class` in the public API there is a table test asserting a
  round-trip to the libssh constant and back, plus a `static_assert` block. Adding an enumerator
  without updating the map fails to compile (the translation function uses a `switch` with no
  `default`, and `-Werror=switch` is on).
* **`SessionOptions` application** — an `ssh_options_set` recorder (a link-time seam used only
  in unit builds) captures the `(option, value)` pairs so the ordering contract in
  [04 §4.2](04-api-core.md#42-sshppsession_optionshpp) is asserted directly.
* **Path traversal** — a parameterised test feeds `..`, `../..`, `a/../../b`, `/abs`,
  `C:\win`, `foo\0bar`, UTF-8 overlong sequences, and very long components into the SFTP tree
  helper's name validator and the server's `SftpSubsystemHandler` resolver. All must be
  rejected.
* **`shell_quote`** — property test: for a corpus of random byte strings, `sh -c "echo
  $(shell_quote(s))"` must reproduce `s` exactly (run against the local shell when available,
  otherwise against a reference implementation).
* **`SecureString`** — allocate, fill with a marker, deallocate, then scan the freed region
  (with a custom allocator that retains the page) for the marker. Run under ASan-off build to
  avoid quarantine interference.

## 10.3 Integration tests against `server::TestServer`

Every client feature is tested against the in-process server:

```cpp
TEST_CASE("exec returns stdout and exit code", "[exec]") {
    sshpp::server::TestServer::Options o;
    o.exec = [](std::string_view cmd, std::istream&, std::ostream& out, std::ostream& err) {
        if (cmd == "ok")   { out << "hello"; return 0; }
        if (cmd == "fail") { err << "boom";  return 3; }
        return 127;
    };
    sshpp::server::TestServer server{o};

    sshpp::Session s{server.client_options()};
    s.connect();
    s.verify_host_key(sshpp::PinnedHostKeyPolicy{{server.host_key_fingerprint()}});
    s.authenticate(sshpp::auth::Password{sshpp::SecureString{"testpass"}});

    auto r = sshpp::Exec{s}.run("ok");
    CHECK(r.exit_code == 0);
    CHECK(r.stdout_text == "hello");
}
```

Coverage matrix (each row is a Catch2 test file):

| Area | Cases |
|---|---|
| Connect | success, refused, DNS failure, timeout, cancel mid-connect, reconnect |
| Host key | `not_found`, `ok`, `changed` (via `faults.wrong_host_key_after_first_connect`), TOFU write-back, pinning, callback policy returning each `Decision` |
| Auth | password ok/denied, pubkey ok/denied, `publickey_auto`, agent (with a fake agent socket), keyboard-interactive multi-prompt, partial→chain completion, max-attempts disconnect |
| Channel | exec, shell, subsystem, env, pty + resize, signals, stderr interleaving, EOF ordering, exit-status without draining, large writes, zero-length writes |
| SFTP | every method, 64-bit offsets, sparse seeks, permission errors mapped to `sftp_errc`, directory iteration incl. empty and huge directories, recursive walk with a symlink loop, resume, atomic upload crash simulation |
| SCP | read/write, recursive, deny path, malicious filename from the server |
| Forwarding | local, remote, direct-unix, SOCKS5 (with a loopback echo target), EOF/half-close semantics, `stop()` while connections are live, connection cap |
| Errors | every `errc` enumerator is produced by at least one test (enforced by a coverage assertion at the end of the run) |
| Lifetime | `Channel` outliving `Session`, moved-from use, double `close()`, destructor during an active transfer |

The "every `errc` is produced" check is a genuine forcing function: it prevents dead error
codes and undocumented failure modes.

## 10.4 Fault injection

`TestServer::Options::faults` (see [08 §8.8](08-api-server.md#88-servertestserver--layer-4))
provides deterministic hostile behaviour. Additional injection points:

* A `detail::testing::SocketFilter` hook (compiled only when `LIBSSHPP_BUILD_TESTS=ON`) that can
  drop, delay, or truncate bytes on the loopback connection — used for `connection_lost`
  mid-SFTP-transfer and partial-write paths.
* An allocation-failure injector for `out_of_memory` paths.

## 10.5 System tests (opt-in)

`LIBSSHPP_SYSTEM_TESTS=ON` enables tests that need a real OpenSSH server. The fixture starts
`linuxserver/openssh-server` (or uses `SSHPP_TEST_HOST`/`SSHPP_TEST_PORT` if set) via
`tests/system/docker-compose.yml`, seeded with:

* a test user with password and pubkey auth,
* `AuthenticationMethods publickey,keyboard-interactive` on a second user (multi-factor),
* an sftp-only chrooted user,
* `PermitOpen`/`AllowTcpForwarding` variants for forwarding tests,
* a legacy-algorithms server (one container running with `Ciphers +aes128-cbc` etc.) to test
  negotiation failures and explicit algorithm selection.

These are skipped (not failed) when Docker is unavailable, and run nightly rather than per-PR.

## 10.6 Fuzzing

libFuzzer targets under `tests/fuzz/`, built with `LIBSSHPP_BUILD_FUZZERS=ON`:

| Target | Input |
|---|---|
| `fuzz_known_hosts_line` | A `known_hosts` line |
| `fuzz_authorized_keys_line` | An `authorized_keys` line |
| `fuzz_public_key_import` | base64/PEM key material |
| `fuzz_remote_path` | `RemotePath` normalization + traversal validator |
| `fuzz_socks_request` | SOCKS4/5 request bytes |
| `fuzz_sftp_server_path` | Path resolution in `SftpSubsystemHandler` |
| `fuzz_display_parse` | `$DISPLAY` strings |
| `fuzz_target_parse` | `SessionOptions::parse_target` |

Seed corpora are committed; OSS-Fuzz integration is a post-1.0 goal. These target **our**
parsers only — fuzzing libssh's protocol code is upstream's job.

## 10.7 Static analysis and hygiene

| Tool | Where | Gate |
|---|---|---|
| `clang-format` (config in-tree) | pre-commit + CI | Fails CI on diff |
| `clang-tidy` | CI, `-warnings-as-errors` on the enabled check set | Blocking |
| `cppcheck` | CI | Advisory |
| `include-what-you-use` | Weekly | Advisory |
| CodeQL (`cpp`, security-extended) | Per PR + weekly | Blocking on high severity |
| `-Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wnon-virtual-dtor -Wold-style-cast -Wcast-align -Wunused -Woverloaded-virtual -Wnull-dereference -Wdouble-promotion -Wformat=2` / `/W4 /permissive-` | Every build | `LIBSSHPP_WARNINGS_AS_ERRORS=ON` in CI |
| ABI check (`abi-compliance-checker` / `abidiff`) | Release PRs | Blocking on a break without a major bump |
| `cmake-lint` / `cmake-format` | CI | Blocking |

clang-tidy check set includes `bugprone-*`, `cert-*`, `cppcoreguidelines-*` (minus the
noisy pointer-arithmetic ones inside `detail/`), `modernize-*`, `performance-*`,
`readability-*`, and `misc-*`.

## 10.8 Sanitizers and dynamic analysis

* **ASan+UBSan** — full unit + integration suite, every PR, Linux and macOS.
* **TSan** — the `Locking::internal` tests, the forwarding pumps, and `TestServer` concurrency,
  every PR on Linux.
* **MSan** — Linux only, requires an MSan-instrumented libssh + OpenSSL; run weekly in a
  dedicated container, non-blocking.
* **Valgrind memcheck** — weekly, full suite, blocking on definite leaks.
* **Coverage** — `gcovr`/`llvm-cov`, uploaded per PR. Gate: line coverage ≥ 85 % overall and
  ≥ 95 % for `include/sshpp/detail/` translation code; a PR may not lower the number.

## 10.9 CI matrix (GitHub Actions)

| Job | OS | Compiler | Config | Notes |
|-----|----|----------|--------|-------|
| `linux-gcc` | ubuntu-22.04, ubuntu-24.04 | GCC 9, 12, 14 | Debug + Release | Baseline |
| `linux-clang` | ubuntu-24.04 | Clang 12, 16, 19 | Debug + Release | |
| `linux-asan-ubsan` | ubuntu-24.04 | Clang 19 | Debug | Blocking |
| `linux-tsan` | ubuntu-24.04 | Clang 19 | Debug | Blocking |
| `linux-header-only` | ubuntu-24.04 | GCC 14 | Debug | `LIBSSHPP_HEADER_ONLY=ON` |
| `linux-minimal` | ubuntu-24.04 | GCC 14 | Release | All modules OFF |
| `linux-shared` | ubuntu-24.04 | GCC 14 | Release | `BUILD_SHARED_LIBS=ON` + ABI check |
| `macos` | macos-14 (arm64), macos-13 (x86_64) | AppleClang | Debug + Release | |
| `windows-msvc` | windows-2022 | MSVC 19.4x | Debug + Release | Static + shared |
| `windows-clang-cl` | windows-2022 | clang-cl | Release | |
| `libssh-matrix` | ubuntu-24.04 | GCC 14 | Release | libssh 0.10.4, 0.10.6, 0.11.0, 0.11.1, git master (non-blocking) |
| `cross-aarch64` | ubuntu-24.04 | GCC cross | Release | Build only, no tests |
| `conan` | ubuntu / macos / windows | default | Release | `conan create . --build=missing` + `test_package` |
| `nightly-system` | ubuntu-24.04 | GCC 14 | Release | Docker OpenSSH interop |
| `nightly-fuzz` | ubuntu-24.04 | Clang 19 | — | 30 min per target |
| `docs` | ubuntu-24.04 | — | — | Doxygen + link check, publishes to Pages |

The `libssh-matrix` job is the one that keeps the conditional-feature code
(`SSHPP_HAS_SFTP_AIO`, `SSHPP_HAS_CHANNEL_EXIT_STATE`) honest; without it, the fallback paths
rot immediately.

## 10.10 Definition of done for a feature PR

1. Public headers documented with Doxygen, including a `@warning` for every security-relevant
   caveat.
2. Both `try_*` and throwing forms exist and are tested.
3. At least one integration test against `TestServer`, plus unit tests for any pure logic.
4. New `errc` enumerators are produced by a test.
5. `CHANGELOG.md` entry.
6. If it touches a public header: ABI check reviewed.
7. If it parses untrusted input: a fuzz target exists.
8. An entry in the relevant design document is updated — the docs in `docs/design/` are
   normative and must not drift.
