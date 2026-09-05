# 04 — Core API: Library, Session, Authentication, Keys, Host Keys

All declarations below live in `namespace sshpp` (inline `v1`). `SSHPP_API` is the
visibility/DLL macro. `try_*` siblings are omitted for brevity where the pattern is obvious —
see [03 §3.6](03-error-handling.md#36-the-dual-api-rule); **every** fallible function listed has
one.

## 4.1 `<sshpp/library.hpp>` — global state

```cpp
namespace sshpp {

enum class LogLevel { none = 0, warning, info, debug, trace };

struct LogRecord {
    LogLevel    level;
    const char* function;   // libssh's originating function
    std::string message;
};

using LogCallback = std::function<void(const LogRecord&)>;

struct Features {
    std::string libssh_version;          // e.g. "0.11.1"
    int  libssh_version_int;             // SSH_VERSION_INT
    bool zlib;
    bool gssapi;
    bool sftp;
    bool server;
    bool sftp_aio;                       // >= 0.11
    bool control_master;                 // >= 0.11
    bool channel_exit_state;             // >= 0.11
    std::vector<std::string> ciphers, kex, macs, public_key_algorithms;
};

/// RAII guard around ssh_init()/ssh_finalize(). Reference-counted and thread-safe,
/// so multiple independent components may each hold one.
/// At least one instance must be alive for the whole time any other sshpp object exists.
class SSHPP_API Library {
public:
    struct Config {
        bool install_threading_callbacks = true;   // ssh_threads_get_native()
        LogLevel   log_level = LogLevel::none;
        LogCallback log_callback{};                // nullptr -> libssh default (stderr)
    };

    Library();                                     // Config{}
    explicit Library(const Config&);
    ~Library();
    Library(const Library&);                       // refcount++
    Library& operator=(const Library&);
    Library(Library&&) noexcept;
    Library& operator=(Library&&) noexcept;

    static bool initialized() noexcept;
    static Features features();                    // cached after first call
    static std::string version_string();           // "libsshpp 1.0.0 (libssh 0.11.1, OpenSSL 3.0)"

    static void set_log_level(LogLevel);
    static LogLevel log_level() noexcept;
    static void set_log_callback(LogCallback);     // pass {} to restore default

    /// Called when a destructor observes a failure it cannot report.
    /// Default: ignore. Test builds install an aborting handler.
    using DestructorErrorHandler = std::function<void(const ErrorInfo&)>;
    static void set_destructor_error_handler(DestructorErrorHandler);
};

} // namespace sshpp
```

Notes:

* `ssh_finalize()` is only called when the last `Library` is destroyed **and** no `SessionCore`
  is alive; a global weak registry enforces this and, on violation, reports through the
  destructor error handler instead of crashing.
* The `LogCallback` bridge is a `static` trampoline; the `std::function` is stored in a
  process-global with its own mutex. Exceptions escaping a user callback are swallowed and
  reported to the destructor error handler (libssh cannot unwind through C frames).

## 4.2 `<sshpp/session_options.hpp>`

A plain aggregate with `std::optional` members — unset members are simply not passed to
`ssh_options_set`, so libssh's own defaults and `~/.ssh/config` remain in effect.

```cpp
namespace sshpp {

enum class StrictHostKeyChecking { off, on };
enum class Locking { none, internal };
enum class Compression { off, on, zlib, zlib_openssh };

struct SSHPP_API SessionOptions {
    // --- connection ------------------------------------------------------
    std::string                  host;               // required
    std::optional<std::uint16_t> port;               // default 22
    std::optional<std::string>   user;               // default: local user
    std::optional<std::string>   bind_address;
    std::optional<int>           fd;                 // SSH_OPTIONS_FD (pre-connected socket)
    std::optional<std::string>   proxy_command;      // "none" disables
    std::optional<std::string>   proxy_jump;         // 0.11+; emulated via proxy_command below

    // --- timing -----------------------------------------------------------
    std::optional<std::chrono::microseconds> timeout;
    std::optional<bool>          tcp_nodelay;

    // --- files / config ----------------------------------------------------
    std::optional<std::filesystem::path> ssh_dir;             // SSH_OPTIONS_SSH_DIR
    std::optional<std::filesystem::path> known_hosts;         // user known_hosts
    std::optional<std::filesystem::path> global_known_hosts;
    std::vector<std::filesystem::path>   identities;          // ADD_IDENTITY, in order
    std::optional<std::filesystem::path> config_file;         // parsed via ssh_options_parse_config
    bool                                 process_config = true;// SSH_OPTIONS_PROCESS_CONFIG

    // --- crypto negotiation -------------------------------------------------
    std::optional<std::string> ciphers_client_to_server;
    std::optional<std::string> ciphers_server_to_client;
    std::optional<std::string> key_exchange;
    std::optional<std::string> hmac_client_to_server;
    std::optional<std::string> hmac_server_to_client;
    std::optional<std::string> host_key_algorithms;           // SSH_OPTIONS_HOSTKEYS
    std::optional<std::string> public_key_accepted_types;
    std::optional<Compression> compression;
    std::optional<int>         compression_level;             // 1..9

    // --- rekeying ------------------------------------------------------------
    std::optional<std::uint64_t>             rekey_data_bytes;
    std::optional<std::chrono::seconds>      rekey_time;

    // --- host key policy ------------------------------------------------------
    std::optional<StrictHostKeyChecking> strict_host_key_checking;

    // --- GSSAPI -----------------------------------------------------------------
    std::optional<std::string> gssapi_server_identity;
    std::optional<std::string> gssapi_client_identity;
    std::optional<bool>        gssapi_delegate_credentials;

    // --- wrapper behaviour --------------------------------------------------------
    Locking  locking  = Locking::none;
    LogLevel log_level = LogLevel::none;

    // --- helpers ------------------------------------------------------------------
    /// Parse "user@host:port" / "host" / "[v6::addr]:port".
    static Result<SessionOptions> parse_target(std::string_view);

    /// Populate from an OpenSSH client config alias without connecting.
    static Result<SessionOptions> from_ssh_config(
        std::string_view host_alias,
        const std::filesystem::path& config = {});

    Result<void> validate() const;   // pure, no libssh calls
};

} // namespace sshpp
```

Application order in `Session::apply(options)` matters and is fixed:
`SSH_DIR` → `KNOWNHOSTS`/`GLOBAL_KNOWNHOSTS` → `HOST` → `PORT` → `USER` → everything else →
`ssh_options_parse_config()` last (so explicit settings win where libssh honours precedence),
then `PROCESS_CONFIG`. Each `ssh_options_set` failure is reported with the offending option
name in `ErrorInfo::operation`.

A fluent builder is provided for call-site brevity but is a thin wrapper over the aggregate:

```cpp
auto opts = SessionOptions::builder()
                .host("example.com").port(2222).user("deploy")
                .timeout(std::chrono::seconds{10})
                .identity("~/.ssh/id_ed25519")
                .build();                 // Result<SessionOptions>
```

## 4.3 `<sshpp/session.hpp>`

```cpp
namespace sshpp {

enum class KnownHostsStatus { ok, changed, other_type, not_found, unknown, error };
enum class AuthStatus       { success, denied, partial, info_required, again, error };

struct AuthMethods {                              // bitset over SSH_AUTH_METHOD_*
    bool none = false, password = false, public_key = false,
         host_based = false, interactive = false, gssapi_mic = false;
    static AuthMethods from_bits(int);
    int  to_bits() const noexcept;
    bool any() const noexcept;
};

struct NegotiatedAlgorithms {
    std::string kex, host_key, cipher_in, cipher_out, hmac_in, hmac_out;
    std::optional<std::string> compression_in, compression_out;
};

class SSHPP_API Session {
public:
    Session();                                     // empty
    explicit Session(const SessionOptions&);       // allocates ssh_session, applies options; no I/O
    ~Session();                                    // disconnect (best effort) + release core
    Session(Session&&) noexcept;
    Session& operator=(Session&&) noexcept;
    Session(const Session&)            = delete;
    Session& operator=(const Session&) = delete;

    explicit operator bool() const noexcept;       // false if moved-from
    native_session native_handle() const noexcept;
    static Session from_native(native_session, Ownership);

    // ---- options ---------------------------------------------------------
    Result<void> try_set_options(const SessionOptions&);
    void         set_options(const SessionOptions&);
    Result<std::string> try_get_option(SessionOption);        // wraps ssh_options_get
    const SessionOptions& configured_options() const noexcept;// what we applied

    // ---- connection ------------------------------------------------------
    Result<void> try_connect();
    void         connect();
    void         disconnect() noexcept;            // ssh_disconnect; never throws
    [[nodiscard]] bool is_connected() const noexcept;
    Result<void> try_reconnect();                  // disconnect + fresh ssh_session + connect

    int socket_fd() const noexcept;                // ssh_get_fd
    Result<void> try_flush();                      // ssh_blocking_flush
    Result<void> try_set_blocking(bool);
    bool blocking() const noexcept;

    void request_cancel() noexcept;                // thread-safe (see 02 §2.5)
    void clear_cancel()  noexcept;
    bool cancel_requested() const noexcept;

    // ---- peer information -------------------------------------------------
    Result<std::string> try_server_banner()  const;   // ssh_get_serverbanner
    Result<std::string> try_client_banner()  const;
    Result<std::string> try_issue_banner()   const;   // ssh_get_issue_banner (pre-auth MOTD)
    int  openssh_version() const noexcept;            // 0 if peer is not OpenSSH
    NegotiatedAlgorithms negotiated() const;

    // ---- host key ----------------------------------------------------------
    Result<PublicKey>        try_server_public_key() const;    // ssh_get_server_publickey
    Result<KnownHostsStatus> try_check_known_host() const;     // ssh_session_is_known_server
    Result<void>             try_update_known_hosts();         // append/replace entry
    Result<void>             try_verify_host_key(const HostKeyVerifier&);
    void                     verify_host_key(const HostKeyVerifier&);

    // ---- authentication -------------------------------------------------------
    Result<AuthMethods> try_auth_methods();                    // none-auth probe + ssh_userauth_list
    Result<AuthStatus>  try_authenticate(const Authenticator&);
    void                authenticate(const Authenticator&);    // throws AuthError unless success
    Result<AuthStatus>  try_authenticate(std::initializer_list<const Authenticator*>);
    bool                authenticated() const noexcept;

    // ---- subsystem factories ---------------------------------------------------
    Result<Channel>            try_open_channel();
    Channel                    open_channel();
    Result<sftp::Sftp>         try_open_sftp();
    Result<scp::Writer>        try_open_scp_write(const RemotePath&, ScpMode);
    Result<scp::Reader>        try_open_scp_read (const RemotePath&, ScpMode);
    Result<RemoteForwardListener> try_listen_forward(std::string_view bind_addr,
                                                     std::uint16_t port);   // tcpip-forward
    Result<Channel>            try_open_direct_tcpip(std::string_view remote_host,
                                                     std::uint16_t remote_port,
                                                     std::string_view origin_host = "127.0.0.1",
                                                     std::uint16_t origin_port = 0);
    Result<Channel>            try_open_direct_unix(std::string_view socket_path,
                                                    std::string_view origin_host = "",
                                                    std::uint16_t origin_port = 0);

    // ---- diagnostics ------------------------------------------------------------
    Result<void> try_enable_pcap(const std::filesystem::path&);   // optional module
    void         set_log_level(LogLevel);

private:
    detail::SessionCorePtr core_;
};

} // namespace sshpp
```

### Notes

* **`Session(const SessionOptions&)` performs no I/O.** It can still fail (bad option value);
  in that case the object is constructed and `Session::last_option_error()` /
  `try_set_options` reports it. To get a `Result` at construction, use
  `Session::try_create(opts) -> Result<Session>`.
* `try_reconnect()` exists because libssh sessions are not reliably reusable after
  `ssh_disconnect`; the implementation builds a fresh `ssh_session` inside the *same*
  `SessionCore`, so existing `Channel` objects observe `errc::channel_closed` rather than UB.
* `try_auth_methods()` performs the standard `ssh_userauth_none` probe first (which is how
  libssh populates the method list) and treats `SSH_AUTH_SUCCESS` from it as a real
  (passwordless) success, reported via `AuthMethods::none == true` plus `authenticated()`.

## 4.4 `<sshpp/auth.hpp>` — authenticators

Authentication strategies are objects implementing a small interface, so callers can compose
them and libraries can inject their own (e.g. an HSM-backed signer).

```cpp
namespace sshpp {

class SSHPP_API Authenticator {
public:
    virtual ~Authenticator() = default;
    virtual std::string_view name() const noexcept = 0;
    /// Performs one full attempt. Must not throw.
    virtual Result<AuthStatus> attempt(detail::SessionCore&) const noexcept = 0;
};

namespace auth {

/// "none" — probes the server; sometimes succeeds outright.
class SSHPP_API None final : public Authenticator {};

class SSHPP_API Password final : public Authenticator {
public:
    explicit Password(SecureString);
    explicit Password(std::function<Result<SecureString>()> provider);  // lazy / re-promptable
};

/// ssh_userauth_publickey_auto: agent, then default identities, then configured identities.
class SSHPP_API PublicKeyAuto final : public Authenticator {
public:
    PublicKeyAuto() = default;
    explicit PublicKeyAuto(SecureString passphrase);
    explicit PublicKeyAuto(PassphraseCallback);      // prompts per key
};

/// Explicit key: does try_publickey (offer) then publickey (sign).
class SSHPP_API PublicKey final : public Authenticator {
public:
    explicit PublicKey(Key private_key);
    PublicKey(Key public_part, Key private_part);    // for agent-forwarded / split keys
    static Result<PublicKey> from_file(const std::filesystem::path&,
                                       PassphraseCallback = {});
};

class SSHPP_API Agent final : public Authenticator {};   // ssh_userauth_agent

/// Full keyboard-interactive loop; the handler receives the challenge set and returns answers.
class SSHPP_API KeyboardInteractive final : public Authenticator {
public:
    struct Prompt { std::string text; bool echo; };
    struct Challenge {
        std::string name, instruction;
        std::vector<Prompt> prompts;
    };
    using Handler = std::function<Result<std::vector<SecureString>>(const Challenge&)>;

    explicit KeyboardInteractive(Handler);
    static Handler console_handler();                 // reads from tty, disables echo
    /// Answers the first non-echo prompt with the password; the common "PAM password" case.
    static KeyboardInteractive with_password(SecureString);
};

class SSHPP_API Gssapi final : public Authenticator {};

/// Tries each authenticator in order until one succeeds; carries `partial` state forward.
class SSHPP_API Chain final : public Authenticator {
public:
    Chain& add(std::shared_ptr<Authenticator>);
    template <class A, class... Args> Chain& emplace(Args&&...);
    /// Default chain: Agent -> PublicKeyAuto -> KeyboardInteractive(cb) -> Password(cb)
    static Chain interactive_default(PassphraseCallback, PasswordCallback);
};

} // namespace auth
} // namespace sshpp
```

`Chain` implements the real-world multi-factor flow: while `attempt()` returns
`AuthStatus::partial`, it re-queries `ssh_userauth_list` and continues with the still-allowed
methods, which is exactly what OpenSSH's `AuthenticationMethods publickey,keyboard-interactive`
requires.

`PassphraseCallback` / `PasswordCallback` are
`std::function<Result<SecureString>(const PassphraseRequest&)>` where the request carries the
key path/comment and a retry counter, so UIs can say "wrong passphrase, try again (2/3)".

Console helpers (`auth::console_password_prompt()`) live in Layer 4 and are compiled only when
`LIBSSHPP_WITH_CONSOLE=ON` (they need termios/`SetConsoleMode`).

## 4.5 `<sshpp/key.hpp>` — PKI

```cpp
namespace sshpp {

enum class KeyType {
    unknown, dss, rsa, rsa1, ecdsa_p256, ecdsa_p384, ecdsa_p521,
    ed25519, dss_cert01, rsa_cert01, ecdsa_p256_cert01, ecdsa_p384_cert01,
    ecdsa_p521_cert01, ed25519_cert01, sk_ecdsa, sk_ed25519,
    sk_ecdsa_cert01, sk_ed25519_cert01,
};

enum class HashType { md5, sha1, sha256 };

class SSHPP_API Fingerprint {
public:
    HashType type() const noexcept;
    ByteView bytes() const noexcept;
    std::string to_string() const;        // "SHA256:base64" / "MD5:aa:bb:.." (OpenSSH format)
    std::string to_hex() const;
    std::string to_randomart() const;     // ssh_print_hash-style ASCII art, returned not printed
    bool operator==(const Fingerprint&) const noexcept;   // constant-time compare
};

class SSHPP_API Key {
public:
    Key() = default;                       // empty
    ~Key();                                // ssh_key_free
    Key(Key&&) noexcept;  Key& operator=(Key&&) noexcept;
    Key(const Key&) = delete;              // libssh has no key-dup; use export/import
    Key clone() const;                     // explicit deep copy via export/import

    explicit operator bool() const noexcept;
    native_key native_handle() const noexcept;
    static Key from_native(native_key, Ownership);

    // ---- import ---------------------------------------------------------
    static Result<Key> from_private_file(const std::filesystem::path&,
                                         PassphraseCallback = {});
    static Result<Key> from_private_pem(std::string_view pem,
                                        PassphraseCallback = {});
    static Result<Key> from_public_file(const std::filesystem::path&);
    static Result<Key> from_public_base64(std::string_view b64, KeyType);
    /// Parses a full "ssh-ed25519 AAAA... comment" line.
    static Result<Key> from_authorized_keys_line(std::string_view);

    // ---- export ----------------------------------------------------------
    Result<std::string> to_public_base64() const;             // no type prefix
    Result<std::string> to_authorized_keys_line(std::string_view comment = {}) const;
    Result<SecureString> to_private_pem(SecureString passphrase = {}) const;
    Result<void> write_private_file(const std::filesystem::path&,
                                    SecureString passphrase = {},
                                    std::filesystem::perms = owner_read_write) const;
    Result<void> write_public_file(const std::filesystem::path&) const;
    Result<Key>  public_part() const;                          // ssh_pki_export_privkey_to_pubkey

    // ---- inspection --------------------------------------------------------
    KeyType type() const noexcept;
    std::string type_name() const;                             // "ssh-ed25519"
    std::optional<std::string> ecdsa_curve_name() const;
    int  bits() const noexcept;
    bool is_private() const noexcept;
    bool is_public()  const noexcept;
    bool is_certificate() const noexcept;
    Result<Fingerprint> fingerprint(HashType = HashType::sha256) const;
    bool equals(const Key& other, bool compare_private = false) const noexcept;  // ssh_key_cmp

    // ---- generation ---------------------------------------------------------
    static Result<Key> generate(KeyType, int bits = 0);        // bits=0 -> sensible default
};

} // namespace sshpp
```

`PublicKey` in the host-key APIs is `using PublicKey = Key;` with a documented invariant
(`is_public()`), rather than a separate type — libssh uses one handle type and splitting it
would force conversions everywhere.

Security detail: `write_private_file` creates with `0600` **before** writing (open with
`O_CREAT|O_EXCL` + mode, or `CreateFile` with a restrictive DACL on Windows), never
world-readable-then-chmod.

## 4.6 `<sshpp/known_hosts.hpp>` and `<sshpp/host_key_verifier.hpp>`

```cpp
namespace sshpp {

struct KnownHostsEntry {
    std::string  hosts_field;      // may be hashed ("|1|...") or a pattern list
    std::string  marker;           // "", "@cert-authority", "@revoked"
    KeyType      key_type;
    Key          key;
    std::string  comment;
    std::filesystem::path file;
    int          line = 0;
};

class SSHPP_API KnownHosts {
public:
    explicit KnownHosts(std::filesystem::path user_file,
                        std::filesystem::path global_file = {});

    static KnownHosts default_files();                       // ~/.ssh/known_hosts + /etc/ssh/...

    Result<std::vector<KnownHostsEntry>> entries_for(std::string_view host,
                                                     std::uint16_t port = 22) const;
    Result<KnownHostsStatus> check(std::string_view host, std::uint16_t port,
                                   const Key& presented) const;
    Result<void> add(std::string_view host, std::uint16_t port, const Key&,
                     std::string_view comment = {});
    Result<void> remove(std::string_view host, std::uint16_t port);
    Result<void> replace(std::string_view host, std::uint16_t port, const Key&);

    /// Parse a single line without touching any file (wraps ssh_known_hosts_parse_line).
    static Result<KnownHostsEntry> parse_line(std::string_view host, std::string_view line);
};

/// Policy object consulted by Session::verify_host_key().
class SSHPP_API HostKeyVerifier {
public:
    struct Context {
        std::string_view host;
        std::uint16_t    port;
        KnownHostsStatus status;
        const Key&       presented_key;
        Fingerprint      sha256;
        Session&         session;      // to call try_update_known_hosts()
    };
    enum class Decision { accept, accept_and_remember, reject };

    virtual ~HostKeyVerifier() = default;
    virtual Decision verify(const Context&) const = 0;
};

/// Reject anything not already in known_hosts. The default and the only safe default.
class SSHPP_API StrictHostKeyPolicy final : public HostKeyVerifier {};

/// Accept-and-remember on first use; reject on change. Mirrors OpenSSH's
/// StrictHostKeyChecking=accept-new.
class SSHPP_API TofuHostKeyPolicy final : public HostKeyVerifier {};

/// Accept everything. Constructor is `explicit AcceptAnyHostKeyPolicy(InsecureOptIn)`
/// where InsecureOptIn is a tag type only constructible via
/// `sshpp::i_understand_this_is_insecure()`, so it cannot be typed by accident.
class SSHPP_API AcceptAnyHostKeyPolicy final : public HostKeyVerifier {};

/// Pin one or more fingerprints; ignores known_hosts entirely.
class SSHPP_API PinnedHostKeyPolicy final : public HostKeyVerifier {
public:
    explicit PinnedHostKeyPolicy(std::vector<Fingerprint>);
    static Result<PinnedHostKeyPolicy> from_strings(std::vector<std::string>); // "SHA256:..."
};

/// Delegates to a user callback (e.g. a GUI prompt).
class SSHPP_API CallbackHostKeyPolicy final : public HostKeyVerifier {
public:
    explicit CallbackHostKeyPolicy(std::function<Decision(const Context&)>);
};

} // namespace sshpp
```

Design points:

* `verify_host_key` is a **required, explicit step**. `Session::connect()` deliberately does
  not verify, and using a `Channel` before verification fails with `errc::host_key_rejected`
  unless `SessionOptions::strict_host_key_checking == off`. This makes the classic
  "forgot to verify the host key" vulnerability impossible to reach by omission.
* `Decision::accept_and_remember` triggers `ssh_session_update_known_hosts`.
* `PinnedHostKeyPolicy` uses constant-time fingerprint comparison.
* `AcceptAnyHostKeyPolicy` requires the `i_understand_this_is_insecure()` tag and emits a
  `[[deprecated]]`-style compiler note in non-test builds.

## 4.7 Complete client bootstrap, canonical form

```cpp
sshpp::Library lib{{.log_level = sshpp::LogLevel::warning}};

auto opts = sshpp::SessionOptions::from_ssh_config("prod-web").value();
opts.timeout = std::chrono::seconds{15};

sshpp::Session s{opts};
s.connect();
s.verify_host_key(sshpp::TofuHostKeyPolicy{});

sshpp::auth::Chain chain;
chain.emplace<sshpp::auth::Agent>()
     .emplace<sshpp::auth::PublicKeyAuto>(sshpp::auth::console_passphrase_prompt())
     .emplace<sshpp::auth::KeyboardInteractive>(
         sshpp::auth::KeyboardInteractive::console_handler());
s.authenticate(chain);
```
