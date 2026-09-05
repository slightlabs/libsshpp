# 08 — Server API

Headers: `<sshpp/server/bind.hpp>`, `<sshpp/server/server_session.hpp>`,
`<sshpp/server/message.hpp>`, `<sshpp/server/handlers.hpp>`, `<sshpp/server/test_server.hpp>`.

Enabled by `LIBSSHPP_WITH_SERVER` (`ON` by default; requires libssh built with server support,
detected at configure time).

## 8.1 Why the server API is in v1

1. It makes the test-suite hermetic: integration tests run a real SSHv2 server in-process
   (goal G9), so CI needs no Docker and no sshd.
2. Embedded/appliance use cases (management shells, custom SFTP endpoints, git-over-SSH
   servers) are a genuine libssh strength that most wrappers drop.
3. The client-side code paths get exercised against a server we control, including hostile
   behaviours that a real sshd will not produce (see [10 §10.4](10-testing-and-ci.md)).

## 8.2 Two styles, one object model

libssh offers two server programming models. We wrap **both**, because they are not
interchangeable:

* **Message API** (`ssh_message_get` / `ssh_message_type` / `ssh_message_*_reply_*`) —
  a synchronous pull loop. Simple, but cannot handle multiple channels concurrently well.
* **Callback API** (`ssh_set_server_callbacks`, `ssh_set_channel_callbacks`, `ssh_event_dopoll`)
  — event-driven, required for anything serving many channels/clients.

`server::Session` supports either; you pick by calling `set_handler()` (callback style) or
`next_message()` (message style). Mixing them on one session returns
`errc::invalid_argument`.

## 8.3 `server::Bind` — the listener

```cpp
namespace sshpp::server {

struct SSHPP_API BindOptions {
    std::string   bind_address = "0.0.0.0";
    std::uint16_t port = 22;
    std::optional<int> fd;                       // adopt an existing listening socket

    /// One or more host keys. At least one is required.
    std::vector<std::filesystem::path> host_key_files;
    std::vector<Key>                   host_keys;      // SSH_BIND_OPTIONS_IMPORT_KEY

    std::optional<std::string> banner;                 // SSH_BIND_OPTIONS_BANNER
    std::optional<std::string> ciphers, key_exchange, hmac, host_key_algorithms;
    std::optional<std::filesystem::path> config_dir;   // SSH_BIND_OPTIONS_CONFIG_DIR
    std::optional<std::filesystem::path> moduli_file;
    LogLevel log_level = LogLevel::none;
    std::optional<bool> process_config;

    Result<void> validate() const;
};

class SSHPP_API Bind {
public:
    Bind() = default;
    explicit Bind(const BindOptions&);
    ~Bind();                                    // ssh_bind_free
    Bind(Bind&&) noexcept;

    Result<void> try_listen();                  // ssh_bind_listen
    std::uint16_t local_port() const noexcept;  // resolved when port == 0
    int  fd() const noexcept;                   // for integration into an external loop

    /// Blocking accept. The returned session has NOT completed key exchange yet.
    Result<Session> try_accept();
    /// Accept on an already-connected socket (e.g. from your own accept loop / inetd).
    Result<Session> try_accept_fd(int);
    /// Blocks up to `timeout`; nullopt on timeout.
    Result<std::optional<Session>> try_accept(std::chrono::milliseconds timeout);

    native_bind native_handle() const noexcept;
};

} // namespace sshpp::server
```

## 8.4 `server::Session`

```cpp
namespace sshpp::server {

struct AuthMethodSet {                          // mirrors SSH_AUTH_METHOD_*
    bool none = false, password = false, public_key = false,
         host_based = false, interactive = false, gssapi_mic = false;
    int to_bits() const noexcept;
};

class SSHPP_API Session {
public:
    ~Session();                                  // disconnect + free
    Session(Session&&) noexcept;

    /// Performs the SSH transport handshake. Must be called before anything else.
    Result<void> try_handle_key_exchange();
    Result<void> try_handle_key_exchange(std::chrono::milliseconds timeout);

    void         set_auth_methods(AuthMethodSet);
    Result<void> try_disconnect(std::string_view reason = {});

    // ---- peer info -------------------------------------------------------
    Result<std::string> try_client_banner() const;
    std::optional<TcpEndpoint> peer_endpoint() const;   // from getpeername()
    NegotiatedAlgorithms negotiated() const;

    // ---- message style ----------------------------------------------------
    /// nullopt on timeout. The Message owns the libssh handle.
    Result<std::optional<Message>> try_next_message(std::chrono::milliseconds timeout);

    // ---- callback style ----------------------------------------------------
    /// Installs ssh_server_callbacks + drives via an Event.
    Result<void> try_set_handler(std::shared_ptr<SessionHandler>);
    Result<void> try_attach(Event&);
    Result<void> try_poll(std::chrono::milliseconds);   // convenience: private Event

    // ---- state -------------------------------------------------------------
    bool authenticated() const noexcept;
    const std::string& user() const noexcept;           // set once auth succeeds
    native_session native_handle() const noexcept;
};

} // namespace sshpp::server
```

## 8.5 Message style — `server::Message`

```cpp
namespace sshpp::server {

enum class MessageType { request_auth, request_auth_callback, request_service,
                         channel_open, channel_request, disconnect, ignore, unknown };
enum class AuthSubtype  { none, password, public_key, host_based, interactive, gssapi_mic, unknown };
enum class ChannelOpenSubtype { session, direct_tcpip, forwarded_tcpip, x11, auth_agent, unknown };
enum class ChannelRequestSubtype { pty, exec, shell, env, subsystem, window_change,
                                   x11, signal, exit_status, unknown };
enum class PublicKeyState { none, valid, wrong };

class SSHPP_API Message {
public:
    ~Message();                                      // ssh_message_free (unless replied+consumed)
    Message(Message&&) noexcept;

    MessageType type() const noexcept;
    int         subtype_raw() const noexcept;
    AuthSubtype auth_subtype() const noexcept;
    ChannelOpenSubtype    channel_open_subtype() const noexcept;
    ChannelRequestSubtype channel_request_subtype() const noexcept;

    // ---- auth accessors ---------------------------------------------------
    std::string_view auth_user() const noexcept;
    SecureString     auth_password() const;          // copies then the C buffer is untouched
    Key              auth_public_key() const;        // borrowed handle, non-owning
    PublicKeyState   auth_public_key_state() const noexcept;

    Result<void> try_reply_auth_success();
    Result<void> try_reply_auth_partial(AuthMethodSet remaining);
    Result<void> try_reply_auth_pk_ok(const Key& algo_and_blob);   // signature not yet required
    Result<void> try_reply_default();                              // deny

    // ---- keyboard-interactive -----------------------------------------------
    Result<void> try_reply_kbdint_prompts(std::string_view name, std::string_view instruction,
                                          const std::vector<KeyboardInteractive::Prompt>&);
    std::vector<SecureString> kbdint_answers() const;

    // ---- channel open ---------------------------------------------------------
    Result<Channel> try_accept_channel_open();       // returns a borrowed Channel
    /// direct-tcpip details, for a server that implements -L on behalf of clients.
    TcpEndpoint channel_open_destination() const;
    TcpEndpoint channel_open_originator()  const;

    // ---- channel request ---------------------------------------------------------
    std::string_view exec_command()    const noexcept;
    std::string_view subsystem_name()  const noexcept;
    std::pair<std::string_view, std::string_view> env_pair() const noexcept;
    PtySize          pty_size()        const noexcept;
    std::string_view pty_term()        const noexcept;

    Result<void> try_reply_success();
    Result<void> try_reply_failure();

    // ---- service / global request -----------------------------------------------
    std::string_view service_name() const noexcept;
};

} // namespace sshpp::server
```

**Reply discipline.** libssh requires exactly one reply per message; forgetting one hangs the
client. `Message`'s destructor detects "no reply sent" for message types that need one and
sends `ssh_message_reply_default()` automatically, then reports through the destructor error
handler in debug builds. This turns a hang into a clear failure.

**Secrets.** `auth_password()` returns a `SecureString` copy; `Message`'s destructor zeroes any
password buffer it exposed before `ssh_message_free`.

## 8.6 Callback style — `server::SessionHandler`

The ergonomic model, and what `TestServer` uses.

```cpp
namespace sshpp::server {

enum class AuthResult { success, denied, partial, again };

class SSHPP_API SessionHandler {
public:
    virtual ~SessionHandler() = default;

    // ---- authentication (all default to `denied`) --------------------------
    virtual AuthResult on_auth_none(Session&, std::string_view user);
    virtual AuthResult on_auth_password(Session&, std::string_view user, const SecureString&);
    /// state == none  -> client is *offering* a key; return success to say "acceptable"
    /// state == valid -> signature verified; return success to authenticate
    virtual AuthResult on_auth_public_key(Session&, std::string_view user,
                                          const Key&, PublicKeyState state);
    virtual AuthResult on_auth_gssapi_mic(Session&, std::string_view user,
                                          std::string_view principal);
    virtual std::optional<KeyboardInteractive::Challenge>
            on_auth_interactive_start(Session&, std::string_view user);
    virtual AuthResult on_auth_interactive_answers(Session&, std::string_view user,
                                                   const std::vector<SecureString>&);

    // ---- channels ------------------------------------------------------------
    /// Return nullptr to refuse the channel.
    virtual std::shared_ptr<ChannelHandler> on_channel_open_session(Session&);
    virtual std::shared_ptr<ChannelHandler> on_channel_open_direct_tcpip(
        Session&, const TcpEndpoint& destination, const TcpEndpoint& originator);

    // ---- global requests --------------------------------------------------------
    /// `ssh -R`: return the actually-bound port, or nullopt to refuse.
    virtual std::optional<std::uint16_t> on_tcpip_forward(Session&, std::string_view addr,
                                                          std::uint16_t port);
    virtual bool on_cancel_tcpip_forward(Session&, std::string_view addr, std::uint16_t port);

    virtual void on_service_request(Session&, std::string_view service);
    virtual void on_disconnect(Session&);
    virtual void on_error(Session&, const ErrorInfo&);
};

class SSHPP_API ChannelHandler {
public:
    virtual ~ChannelHandler() = default;

    virtual bool on_pty_request(Channel&, std::string_view term, PtySize);
    virtual bool on_pty_resize(Channel&, PtySize);
    virtual bool on_shell_request(Channel&);
    virtual bool on_exec_request(Channel&, std::string_view command);
    virtual bool on_subsystem_request(Channel&, std::string_view name);
    virtual bool on_env_request(Channel&, std::string_view name, std::string_view value);
    virtual bool on_x11_request(Channel&, const X11Request&);
    virtual bool on_signal(Channel&, std::string_view signal_name);

    /// Return the number of bytes consumed (libssh re-delivers the remainder).
    virtual std::size_t on_data(Channel&, ByteView, Stream);
    virtual void on_eof(Channel&);
    virtual void on_close(Channel&);
    /// Called when the channel's send window opens up again.
    virtual void on_writable(Channel&);
};

} // namespace sshpp::server
```

Implementation notes:

* The C callback structs are stored in a `detail::HandlerBridge` owned by the session; the
  `userdata` pointer is the bridge, never the user's object directly, so handler lifetime is
  controlled by `shared_ptr` and a dangling `userdata` is impossible.
* **Exceptions must not propagate into libssh's C frames.** Every bridge trampoline is wrapped
  in `try { … } catch (...) { handler->on_error(...); return SSH_ERROR; }`.
* `ChannelHandler` is per channel; the bridge keeps a `shared_ptr` alive until libssh reports
  the channel closed.

## 8.7 Ready-made handlers

```cpp
namespace sshpp::server {

/// Authenticates against an in-memory table. For tests, appliances, and quick starts.
class SSHPP_API SimpleAuthHandler : public SessionHandler {
public:
    void allow_password(std::string user, SecureString password);   // stored as a salted hash
    void allow_public_key(std::string user, Key public_key);
    void allow_authorized_keys(std::string user, const std::filesystem::path&);
    void allow_none(std::string user);                              // testing only
    void set_max_attempts(int);                                     // default 6, then disconnect
};

/// Serves SFTP by running libssh's SFTP server helpers over a rooted directory.
/// Every path is resolved and checked against the root; ".." and absolute escapes are refused.
class SSHPP_API SftpSubsystemHandler : public ChannelHandler {
public:
    struct Options {
        std::filesystem::path root;
        bool read_only = false;
        bool follow_symlinks_out_of_root = false;   // default false
        std::uint64_t max_file_size = 0;            // 0 = unlimited
    };
    explicit SftpSubsystemHandler(Options);
};

/// Runs a fixed callback per exec request; no local process is spawned.
class SSHPP_API CommandHandler : public ChannelHandler {
public:
    using Runner = std::function<int(std::string_view command,
                                     std::istream& in, std::ostream& out, std::ostream& err)>;
    explicit CommandHandler(Runner);
};

} // namespace sshpp::server
```

`SftpSubsystemHandler` deliberately does **not** shell out and does **not** support arbitrary
absolute paths — it is a chroot-style server. Path resolution: join → `weakly_canonical` →
verify `starts_with(root)`; any failure returns `SSH_FX_PERMISSION_DENIED`. This is the single
most security-sensitive component in the library and gets dedicated fuzz + unit tests.

There is **no** built-in "spawn a shell / PTY for the authenticated user" handler. Doing that
correctly requires privilege separation, `setuid`, PAM session setup and utmp handling — out of
scope, and shipping a half-correct version would be dangerous. The documentation says so
explicitly and points at OpenSSH.

## 8.8 `server::TestServer` — Layer 4

```cpp
namespace sshpp::server {

/// A complete SSH server on 127.0.0.1:<ephemeral>, running on its own thread.
/// Generates a throwaway ed25519 host key in a temp dir. Designed for tests.
class SSHPP_API TestServer {
public:
    struct Options {
        std::string user = "testuser";
        SecureString password{"testpass"};
        std::vector<Key> authorized_keys;
        bool allow_password = true, allow_public_key = true,
             allow_interactive = false, allow_none = false;
        std::optional<std::filesystem::path> sftp_root;   // enables the SFTP subsystem
        std::function<int(std::string_view, std::istream&, std::ostream&, std::ostream&)> exec;
        bool allow_port_forwarding = false;
        /// Fault injection for negative testing.
        struct Faults {
            bool truncate_banner = false;
            bool wrong_host_key_after_first_connect = false;
            std::optional<std::chrono::milliseconds> delay_kex;
            std::optional<std::size_t> drop_after_bytes;
        } faults;
    };

    explicit TestServer(Options = {});
    ~TestServer();                                 // stops and joins

    std::uint16_t port() const noexcept;
    const Key&    host_key() const noexcept;
    Fingerprint   host_key_fingerprint(HashType = HashType::sha256) const;
    /// Ready-made client options pointing at this server.
    SessionOptions client_options() const;
    std::filesystem::path known_hosts_file() const;   // pre-populated

    struct Stats { std::uint64_t connections, auth_failures, channels, bytes; };
    Stats stats() const noexcept;
};

} // namespace sshpp::server
```

`Options::faults` is what lets the client-side tests cover `host_key_changed`,
`connection_lost` mid-transfer, and slow-handshake timeouts deterministically — behaviours no
real sshd will produce on demand.

## 8.9 Minimal server example

```cpp
#include <sshpp/sshpp.hpp>
#include <sshpp/server/bind.hpp>

using namespace sshpp;

struct EchoChannel : server::ChannelHandler {
    bool on_shell_request(Channel&) override { return true; }
    std::size_t on_data(Channel& ch, ByteView b, Stream) override {
        ch.try_write_all(b);
        return b.size();
    }
};

struct Handler : server::SimpleAuthHandler {
    std::shared_ptr<server::ChannelHandler> on_channel_open_session(server::Session&) override {
        return std::make_shared<EchoChannel>();
    }
};

int main() {
    Library lib;

    server::BindOptions bo;
    bo.port = 2222;
    bo.host_key_files = {"/etc/libsshpp/ssh_host_ed25519_key"};

    server::Bind bind{bo};
    bind.try_listen().value();

    auto handler = std::make_shared<Handler>();
    handler->allow_authorized_keys("demo", "/etc/libsshpp/authorized_keys");

    for (;;) {
        auto s = bind.try_accept();
        if (!s) continue;
        std::thread{[session = std::move(*s), handler]() mutable {
            if (!session.try_handle_key_exchange()) return;
            session.set_auth_methods({.public_key = true});
            session.try_set_handler(handler);
            while (session.try_poll(std::chrono::milliseconds{200})) {}
        }}.detach();
    }
}
```

(The example uses `.detach()` for brevity; the shipped `examples/10_minimal_server.cpp` uses a
bounded thread pool with a connection cap and a handshake timeout, because an unbounded
accept-and-detach loop is a trivial DoS — OWASP A04.)

## 8.10 Server-side security requirements

These are normative for the implementation, not suggestions:

| ID | Requirement |
|----|-------------|
| SRV-1 | Handshake (`try_handle_key_exchange`) must have a timeout in every shipped example and in `TestServer`; the default `Bind::try_accept` documents the risk of not setting one. |
| SRV-2 | `SimpleAuthHandler` stores passwords as a salted hash (Argon2id if libssh's crypto backend exposes it, otherwise PBKDF2-HMAC-SHA256) and compares in constant time. |
| SRV-3 | Failed-auth counting per connection, with a hard disconnect after `max_attempts`. |
| SRV-4 | `SftpSubsystemHandler` path confinement as described in §8.7, verified by fuzzing. |
| SRV-5 | Channel and global-request limits per session (max channels, max forwards), default-on. |
| SRV-6 | Any data read from the client is length-checked before allocation; no `resize(n)` where `n` comes from the wire without a cap. |
| SRV-7 | Host key files are refused if group/world-readable on POSIX (matching sshd), unless `BindOptions::allow_insecure_host_key_permissions` is set. |
| SRV-8 | The library never logs passwords, private keys, or session keys at any log level. A unit test greps the log output of a full auth flow for the test password. |
