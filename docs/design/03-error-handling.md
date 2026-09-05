# 03 — Error Handling

## 3.1 The problem being solved

libssh reports failures through **four** unrelated channels:

1. Sentinel return codes: `SSH_OK` (0), `SSH_ERROR` (-1), `SSH_AGAIN` (-2), `SSH_EINTR` (-3).
2. Auth-specific codes: `SSH_AUTH_SUCCESS/DENIED/PARTIAL/INFO/AGAIN/ERROR`.
3. Session-attached error state: `ssh_get_error(session)` → `const char*`,
   `ssh_get_error_code(session)` → `SSH_NO_ERROR | SSH_REQUEST_DENIED | SSH_FATAL | SSH_EINTR`.
4. SFTP status codes: `sftp_get_error(sftp)` → `SSH_FX_OK … SSH_FX_INVALID_PARAMETER`.

Plus host-key results (`ssh_known_hosts_e`) which are *not* errors but are frequently
mis-handled as such.

`libsshpp` normalizes all of these onto `std::error_code`.

## 3.2 Error categories

Three `std::error_category` instances, all reachable from `<sshpp/error.hpp>`:

| Category | Enum | Source |
|---|---|---|
| `sshpp::ssh_category()` | `sshpp::errc` | libssh session/transport/auth/protocol failures |
| `sshpp::sftp_category()` | `sshpp::sftp_errc` | `SSH_FX_*` status codes |
| `std::system_category()` | — | OS-level failures surfaced by libssh (socket, DNS) |

```cpp
namespace sshpp {

enum class errc : int {
    ok = 0,

    // --- transport / session -------------------------------------------
    fatal,                 // SSH_FATAL: connection unusable
    request_denied,        // SSH_REQUEST_DENIED
    interrupted,           // SSH_EINTR
    would_block,           // SSH_AGAIN in non-blocking mode
    timed_out,
    cancelled,             // Session::request_cancel()
    not_connected,
    already_connected,
    connection_lost,
    protocol_error,
    banner_exchange_failed,
    key_exchange_failed,
    rekey_failed,

    // --- host key ------------------------------------------------------
    host_key_unknown,      // not in known_hosts
    host_key_changed,      // MITM warning
    host_key_type_mismatch,// known host, different key type
    host_key_rejected,     // verifier policy said no
    known_hosts_io_error,

    // --- authentication -------------------------------------------------
    auth_denied,
    auth_partial,          // more methods required
    auth_method_unavailable,
    auth_no_more_methods,
    passphrase_required,
    passphrase_incorrect,
    agent_unavailable,
    gssapi_error,

    // --- keys -----------------------------------------------------------
    key_import_failed,
    key_export_failed,
    key_generation_failed,
    unsupported_key_type,

    // --- channels --------------------------------------------------------
    channel_open_failed,
    channel_closed,
    channel_eof,
    channel_request_failed,
    pty_request_failed,

    // --- subsystems -------------------------------------------------------
    sftp_unavailable,
    scp_error,
    forwarding_failed,
    x11_failed,

    // --- wrapper-level ----------------------------------------------------
    invalid_handle,        // moved-from / released object used
    invalid_argument,
    unsupported_operation, // linked libssh too old for this call
    out_of_memory,
    unknown,
};

enum class sftp_errc : int {
    ok = 0,                 // SSH_FX_OK
    eof = 1,                // SSH_FX_EOF
    no_such_file = 2,
    permission_denied = 3,
    failure = 4,
    bad_message = 5,
    no_connection = 6,
    connection_lost = 7,
    op_unsupported = 8,
    invalid_handle = 9,
    no_such_path = 10,
    file_already_exists = 11,
    write_protect = 12,
    no_media = 13,
    // libssh extension range
    invalid_parameter = 14,
};

SSHPP_API const std::error_category& ssh_category() noexcept;
SSHPP_API const std::error_category& sftp_category() noexcept;

SSHPP_API std::error_code make_error_code(errc e) noexcept;
SSHPP_API std::error_code make_error_code(sftp_errc e) noexcept;

} // namespace sshpp

namespace std {
template <> struct is_error_code_enum<sshpp::errc>      : true_type {};
template <> struct is_error_code_enum<sshpp::sftp_errc> : true_type {};
}
```

Both categories implement `default_error_condition()` so that common cases map onto
`std::errc` and interoperate with generic code:

| `sshpp::errc` | `std::errc` condition |
|---|---|
| `timed_out` | `timed_out` |
| `would_block` | `operation_would_block` |
| `interrupted` | `interrupted` |
| `cancelled` | `operation_canceled` |
| `connection_lost` | `connection_aborted` |
| `not_connected` | `not_connected` |
| `invalid_argument` | `invalid_argument` |
| `out_of_memory` | `not_enough_memory` |
| `unsupported_operation` | `function_not_supported` |
| `auth_denied`, `permission_denied` (sftp) | `permission_denied` |
| `sftp_errc::no_such_file` / `no_such_path` | `no_such_file_or_directory` |
| `sftp_errc::file_already_exists` | `file_exists` |

So `if (ec == std::errc::timed_out)` works regardless of which category produced it.

## 3.3 `ErrorInfo` — keeping the textual reason

`std::error_code` alone loses libssh's `ssh_get_error()` string, which is often the only way to
tell *why* key exchange failed. Every failure therefore carries an `ErrorInfo`:

```cpp
namespace sshpp {

struct ErrorInfo {
    std::error_code code;              // never default-constructed on failure
    std::string     message;           // ssh_get_error() snapshot, may be empty
    const char*     operation = "";    // static literal, e.g. "ssh_userauth_publickey"
    SourceLocation  where{};           // file/line/function; std::source_location under C++20

    [[nodiscard]] std::string to_string() const;  // "connect: <msg> [ssh:key_exchange_failed]"
    explicit operator bool() const noexcept { return static_cast<bool>(code); }
};

} // namespace sshpp
```

`ErrorInfo` is captured **at the point of failure**, before any other libssh call can overwrite
the session's error string. This is enforced by routing every C call through a single helper:

```cpp
// detail/invoke.hpp
template <class F, class... Args>
auto detail::checked(SessionCore& core, const char* op, F&& fn, Args&&... args)
    -> Result<detail::invoke_result_t<F, Args...>>;
```

`checked()` calls `fn`, inspects the return value, and on failure snapshots
`ssh_get_error(core.raw())` and `ssh_get_error_code(...)` immediately.

## 3.4 Exception hierarchy

```cpp
namespace sshpp {

class SSHPP_API Error : public std::system_error {
public:
    explicit Error(ErrorInfo info);

    const ErrorInfo& info()      const noexcept;
    const char*      operation() const noexcept;
    const SourceLocation& where() const noexcept;
    // what() == info().to_string()
};

class SSHPP_API ConnectionError    : public Error {};  // transport/session failures
class SSHPP_API TimeoutError       : public ConnectionError {};
class SSHPP_API CancelledError     : public ConnectionError {};

class SSHPP_API HostKeyError       : public Error {
public:
    KnownHostsStatus status() const noexcept;   // unknown / changed / other / not_found
    const PublicKey& presented_key() const noexcept;
    Fingerprint fingerprint(HashType) const;
};

class SSHPP_API AuthError          : public Error {
public:
    AuthMethods remaining_methods() const noexcept;  // from ssh_userauth_list
    bool partial() const noexcept;
};

class SSHPP_API KeyError           : public Error {};
class SSHPP_API ChannelError       : public Error {};
class SSHPP_API SftpError          : public Error {
public:
    sftp_errc status() const noexcept;
    const RemotePath& path() const noexcept;   // empty if not path-specific
};
class SSHPP_API ScpError           : public Error {};
class SSHPP_API ForwardingError    : public ChannelError {};
class SSHPP_API ServerError        : public Error {};
class SSHPP_API UsageError         : public Error {};  // invalid_handle, invalid_argument
```

Deriving from `std::system_error` means `catch (const std::system_error&)` and `e.code()` work
for callers who don't know about `libsshpp`, and `catch (const std::exception&)` always works.

Mapping from `errc` to exception class is a single `throw_error(ErrorInfo)` function in
`error.cpp`; no other file throws directly.

**Destructors never throw.** `Session::~Session`, `Channel::~Channel`, etc. call the
non-throwing paths and, if a close fails, route the `ErrorInfo` to
`Library::set_destructor_error_handler()` (default: no-op; test builds: abort).

## 3.5 `Result<T>`

```cpp
namespace sshpp {

#if SSHPP_HAS_STD_EXPECTED            // C++23
template <class T> using Result = std::expected<T, ErrorInfo>;
using Unexpected = std::unexpected<ErrorInfo>;
#else
template <class T> class Result;      // expected-like backport, see below
#endif

} // namespace sshpp
```

The C++17 backport implements the subset of `std::expected` that we commit to, so migrating to
`std::expected` later is source-compatible:

```cpp
template <class T>
class Result {
public:
    using value_type = T;
    using error_type = ErrorInfo;

    Result(T value);                                  // implicit, success
    Result(ErrorInfo error);                          // implicit, failure
    Result(Unexpected e);

    [[nodiscard]] bool has_value() const noexcept;
    explicit operator bool() const noexcept;

    T&        value() &;                              // throws sshpp::Error if !has_value()
    const T&  value() const&;
    T&&       value() &&;
    template <class U> T value_or(U&& fallback) const&;

    T*        operator->() noexcept;                  // UB if !has_value()
    T&        operator*() & noexcept;

    const ErrorInfo& error() const& noexcept;
    std::error_code  code()  const noexcept;          // {} on success

    // monadic subset (available in C++17 backport too)
    template <class F> auto and_then(F&&) &&;
    template <class F> auto transform(F&&) &&;
    template <class F> auto or_else(F&&) &&;

    void throw_if_error() const;                      // no-op on success
};

template <> class Result<void>;   // same, without value()
```

`Result<T>` is `[[nodiscard]]`.

### Convenience macros (optional, opt-in header `<sshpp/try.hpp>`)

```cpp
#define SSHPP_TRY(expr)        // GCC/Clang statement-expression: unwraps or returns the error
#define SSHPP_TRY_ASSIGN(var, expr)
```

Portable fallback for MSVC uses `and_then`. Macros are **not** included by `sshpp.hpp`.

## 3.6 The dual API rule

For every fallible public operation there are exactly two functions:

```cpp
class Session {
public:
    // Non-throwing. The primitive; the throwing one is generated from it.
    [[nodiscard]] Result<void> try_connect() noexcept;

    // Throwing. Equivalent to `try_connect().value()`.
    void connect();
};
```

Generation is mechanical, via a macro in `detail/throwing_wrapper.hpp`, so the two can never
drift:

```cpp
#define SSHPP_THROWING(RET, NAME, SIG, ARGS)                    \
    RET NAME SIG { auto r = try_##NAME ARGS; r.throw_if_error(); \
                   if constexpr (!std::is_void_v<RET>) return std::move(r).value(); }
```

Rules:

* `try_*` functions are `noexcept` unless they allocate a `std::string`/container for the
  result (documented per function). They never throw `sshpp::Error`.
* Throwing functions are never `noexcept`.
* Only the `try_*` form touches libssh.
* Constructors cannot follow this pattern, so **constructors never connect or perform I/O.**
  Objects are constructed empty/configured, and a named method performs the fallible step
  (`Session::connect`, `Sftp::open`, `Bind::listen`). Static factory helpers that do perform I/O
  return `Result<T>` (e.g. `Key::try_from_file`).

## 3.7 Non-error conditions that look like errors

Some libssh results are legitimate outcomes and must **not** be exceptions on the primary path:

| Situation | API |
|---|---|
| Host key not in `known_hosts` | `Session::check_known_host()` returns `KnownHostsStatus`, not an error. Only `Session::verify_host_key(policy)` can fail. |
| Auth requires more methods | `Session::try_authenticate(...)` returns `AuthStatus::partial`; only `authenticate_or_throw` style helpers throw. |
| `read()` hits EOF | `Channel::read_some()` returns `0` bytes and `Channel::is_eof()` is true. `Result` is a success. |
| SFTP `readdir` exhausted | `DirectoryIterator` compares equal to `end()`. |
| SCP `pull_request` returns `SSH_SCP_REQUEST_EOF` | `scp::Reader::next()` returns `std::nullopt`. |
| Non-blocking `SSH_AGAIN` | `errc::would_block` — an error code, but explicitly documented as retryable and never thrown by `wait_*` helpers. |

`AuthStatus`, `KnownHostsStatus`, `ScpRequestType` are therefore first-class enums, not codes.

## 3.8 Worked example

```cpp
#include <sshpp/sshpp.hpp>
#include <iostream>

int main() try {
    sshpp::Library lib;                                  // ssh_init + threading callbacks

    sshpp::SessionOptions opts;
    opts.host = "example.com";
    opts.user = "deploy";
    opts.timeout = std::chrono::seconds{10};

    sshpp::Session session{opts};
    session.connect();                                   // throws ConnectionError / TimeoutError
    session.verify_host_key(sshpp::StrictHostKeyPolicy{});// throws HostKeyError
    session.authenticate(sshpp::auth::PublicKeyAuto{});   // throws AuthError

    auto result = sshpp::Exec{session}.run("uname -a");   // throws ChannelError
    std::cout << result.stdout_text;
    return result.exit_code;
}
catch (const sshpp::HostKeyError& e) {
    std::cerr << "host key " << to_string(e.status()) << ": "
              << e.fingerprint(sshpp::HashType::sha256).to_string() << '\n';
    return 2;
}
catch (const sshpp::Error& e) {
    std::cerr << e.what() << '\n';                        // includes ssh_get_error() text
    return 1;
}
```

Same program, non-throwing:

```cpp
sshpp::Library lib;
sshpp::Session session{opts};

if (auto r = session.try_connect(); !r) {
    std::cerr << r.error().to_string() << '\n';
    return 1;
}
if (auto r = session.try_verify_host_key(sshpp::StrictHostKeyPolicy{}); !r) {
    if (r.code() == sshpp::errc::host_key_changed) { /* loud warning */ }
    return 2;
}
auto exec = sshpp::Exec{session}.try_run("uname -a");
if (!exec) { std::cerr << exec.error().to_string() << '\n'; return 1; }
std::cout << exec->stdout_text;
```
