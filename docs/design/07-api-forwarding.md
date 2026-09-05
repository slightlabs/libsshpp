# 07 — Port Forwarding and X11

Header: `<sshpp/forwarding.hpp>`.

Forwarding is where a thin wrapper is least useful: the libssh calls are easy, but wiring
channels to sockets with correct back-pressure, EOF and shutdown semantics is where everyone
loses a week. This module therefore ships both the primitives and complete, tested pumps.

## 7.1 Terminology

| SSH term | Direction | libssh call | `libsshpp` type |
|---|---|---|---|
| `direct-tcpip` (`ssh -L`) | client opens a channel; server connects out | `ssh_channel_open_forward` | `LocalForward` |
| `direct-streamlocal@openssh.com` | same, to a UNIX socket | `ssh_channel_open_forward_unix` | `LocalForward` (unix target) |
| `tcpip-forward` (`ssh -R`) | server listens; client accepts inbound channels | `ssh_channel_listen_forward` + `ssh_channel_accept_forward` | `RemoteForwardListener` |
| X11 | server opens `x11` channels back to the client | `ssh_channel_request_x11` + `ssh_channel_accept_x11` | `X11Forwarder` |
| Dynamic (`ssh -D`, SOCKS) | client-side SOCKS proxy over `direct-tcpip` | — (not in libssh) | `SocksProxy` (Layer 4, ours) |

## 7.2 Local forwarding — `LocalForward`

```cpp
namespace sshpp {

struct TcpEndpoint {
    std::string   host;
    std::uint16_t port = 0;
};

struct UnixEndpoint { std::string path; };

using ForwardTarget = std::variant<TcpEndpoint, UnixEndpoint>;

/// Primitive: one channel to one remote endpoint. No local listener involved.
SSHPP_API Result<Channel> open_direct(Session&, const ForwardTarget& remote,
                                      TcpEndpoint origin = {"127.0.0.1", 0});

/// Full `ssh -L` equivalent: local TCP listener -> one channel per accepted connection.
class SSHPP_API LocalForward {
public:
    struct Options {
        TcpEndpoint   listen{"127.0.0.1", 0};   // port 0 = ephemeral, query with local_endpoint()
        ForwardTarget target;
        std::size_t   max_connections = 64;
        std::size_t   buffer_size = 64 * 1024;
        std::chrono::milliseconds idle_timeout{0};   // 0 = none
        /// Called before a connection is accepted; return false to reject.
        std::function<bool(const TcpEndpoint& peer)> accept_filter;
        std::function<void(const ErrorInfo&)> on_error;
    };

    LocalForward(Session&, Options);
    ~LocalForward();                                   // stop() + join

    Result<void>  try_start();                         // binds and starts the pump thread(s)
    void          stop() noexcept;                     // idempotent, wakes the loop
    bool          running() const noexcept;
    TcpEndpoint   local_endpoint() const noexcept;     // resolved port after start()

    struct Stats { std::uint64_t connections, active, bytes_out, bytes_in, rejected; };
    Stats stats() const noexcept;

    /// Drive the loop on the calling thread instead of spawning one.
    Result<void> try_run_until_stopped();
};

} // namespace sshpp
```

### Threading

`LocalForward` needs a thread because the local `accept()` and the SSH session must both be
serviced. Two modes:

* **`try_start()`** — spawns one worker thread that owns an `Event` with the session socket and
  the listening socket registered. All SSH traffic happens on that thread, so the parent
  `Session` **must** be in `Locking::internal` mode if the application also uses it. This is
  checked at `try_start()` and returns `errc::invalid_argument` otherwise, with a clear message.
* **`try_run_until_stopped()`** — single-threaded; the caller donates its thread. No locking
  requirement.

Default listen address is `127.0.0.1`, never `0.0.0.0`. Binding to a wildcard address requires
setting it explicitly, and the docs call out that it exposes the tunnel to the whole network
(OWASP A05 — security misconfiguration).

## 7.3 Remote forwarding — `RemoteForwardListener`

```cpp
namespace sshpp {

struct IncomingForward {
    Channel       channel;
    std::uint16_t bound_port = 0;      // which forwarded port this arrived on
    TcpEndpoint   originator;          // as reported by the server, untrusted
};

class SSHPP_API RemoteForwardListener {
public:
    RemoteForwardListener() = default;
    ~RemoteForwardListener();                       // cancel_forward

    /// bind_address: "" = all interfaces (server policy permitting), "localhost", an IP, or
    /// "*"; port 0 asks the server to allocate — read it back with bound_port().
    static Result<RemoteForwardListener> create(Session&, std::string_view bind_address,
                                                std::uint16_t port);

    std::uint16_t bound_port() const noexcept;

    /// Blocks up to `timeout`; nullopt on timeout.
    Result<std::optional<IncomingForward>> try_accept(std::chrono::milliseconds timeout);
    Result<void> try_cancel();                      // ssh_channel_cancel_forward
};

/// `ssh -R` equivalent: accept loop that connects each inbound channel to a local endpoint.
class SSHPP_API RemoteForward {
public:
    struct Options {
        std::string   bind_address = "localhost";
        std::uint16_t remote_port = 0;
        ForwardTarget local_target;
        std::size_t   max_connections = 64;
        std::size_t   buffer_size = 64 * 1024;
        std::function<bool(const TcpEndpoint& originator)> accept_filter;
        std::function<void(const ErrorInfo&)> on_error;
    };

    RemoteForward(Session&, Options);
    ~RemoteForward();
    Result<void>  try_start();
    Result<void>  try_run_until_stopped();
    void          stop() noexcept;
    std::uint16_t remote_port() const noexcept;
    Stats         stats() const noexcept;
};

} // namespace sshpp
```

`IncomingForward::originator` is explicitly documented as **attacker-controlled** — the remote
server supplies it and it must never be used for authorization decisions without an
`accept_filter` that the application actually trusts.

## 7.4 X11

```cpp
namespace sshpp {

struct X11Request {
    bool        single_connection = false;
    std::string auth_protocol = "MIT-MAGIC-COOKIE-1";
    std::string auth_cookie;              // hex; empty -> generate a random one
    std::uint32_t screen_number = 0;
};

class SSHPP_API X11Forwarder {
public:
    struct Options {
        X11Request request;
        /// Where to connect X11 channels locally. Defaults to $DISPLAY parsing.
        ForwardTarget display_target;
        bool trusted = false;             // false -> use a restricted cookie (xauth -f)
    };

    X11Forwarder(Channel& session_channel, Options = {});

    Result<void> try_request();                       // ssh_channel_request_x11
    /// Blocks up to `timeout` for the server to open an x11 channel.
    Result<std::optional<Channel>> try_accept(std::chrono::milliseconds timeout);
    Result<void> try_run_until_stopped();             // accept + pump to the local display
    void stop() noexcept;

    /// Parses $DISPLAY (":0", "localhost:10.0", "host:0") into a ForwardTarget.
    static Result<ForwardTarget> target_from_display(std::string_view display);
    /// Reads the local cookie via `xauth list` if available.
    static Result<std::string> local_cookie(std::string_view display);
};

} // namespace sshpp
```

X11 forwarding is a well-known security hazard (a compromised remote host gets keylogging
access to the local display). The header documents this, `trusted` defaults to `false`, and
`single_connection` is recommended. When `auth_cookie` is empty we generate 16 random bytes
from a CSPRNG rather than reusing the real local cookie.

## 7.5 `Connector` — the byte pump

All four forwarding types share one primitive built on `ssh_connector_*`:

```cpp
namespace sshpp {

/// Bidirectionally copies bytes between two endpoints, one of which is usually a Channel.
/// Registered with an Event; the Event drives it.
class SSHPP_API Connector {
public:
    Connector(Session&);
    ~Connector();

    Result<void> try_set_in_channel(Channel&, Stream = Stream::stdout_);
    Result<void> try_set_out_channel(Channel&, Stream = Stream::stdout_);
    Result<void> try_set_in_fd(int);
    Result<void> try_set_out_fd(int);

    native_connector native_handle() const noexcept;
};

/// Pairs two Connectors (A->B and B->A) plus lifetime/EOF handling.
class SSHPP_API BidirectionalPump {
public:
    BidirectionalPump(Session&, Channel&, int local_fd, std::size_t buffer_size = 64 * 1024);
    Result<void> try_attach(Event&);
    bool finished() const noexcept;
    std::pair<std::uint64_t, std::uint64_t> byte_counts() const noexcept;
};

} // namespace sshpp
```

If the linked libssh lacks `ssh_connector_*` (it is present since 0.7 but has had bugs), a
build option `LIBSSHPP_USE_SSH_CONNECTOR=OFF` swaps in our own poll-based pump with identical
semantics. Both implementations are covered by the same test suite.

Correct EOF handling is the part worth writing down, because it is the usual bug:

1. Local socket read returns 0 → `channel.try_send_eof()`, keep reading from the channel.
2. `channel.is_eof()` → `shutdown(fd, SHUT_WR)`, keep reading from the socket.
3. Both directions done → `channel.try_close()`, `close(fd)`, remove from the `Event`.
4. Local socket error → `channel.try_close()` immediately.

## 7.6 Dynamic forwarding — `SocksProxy` (Layer 4)

libssh has no SOCKS support; this is ours, ~200 lines, and it is what makes `ssh -D`
possible.

```cpp
namespace sshpp {

class SSHPP_API SocksProxy {
public:
    struct Options {
        TcpEndpoint listen{"127.0.0.1", 1080};
        bool allow_socks4 = false;                   // SOCKS5 only by default
        bool allow_udp_associate = false;            // not supported over SSH; rejects cleanly
        std::size_t max_connections = 128;
        /// Called with the requested destination; return false to refuse (CONNECT policy).
        std::function<bool(const ForwardTarget&)> allow;
        std::function<void(const ErrorInfo&)> on_error;
    };

    SocksProxy(Session&, Options);
    Result<void> try_start();
    Result<void> try_run_until_stopped();
    void stop() noexcept;
    TcpEndpoint local_endpoint() const noexcept;
};

} // namespace sshpp
```

Hardening: SOCKS5 only by default, no authentication methods advertised other than "no auth"
(the listener is loopback-only), hostnames forwarded to the SSH server rather than resolved
locally (matching `ssh -D` and avoiding DNS leaks), strict length checks on every field of the
SOCKS request, and a hard cap on in-flight connections.

## 7.7 Examples

```cpp
// ssh -L 5432:db.internal:5432
sshpp::LocalForward::Options o;
o.listen = {"127.0.0.1", 5432};
o.target = sshpp::TcpEndpoint{"db.internal", 5432};
sshpp::LocalForward fwd{session, o};
fwd.try_start().value();
// ... application uses localhost:5432 ...
fwd.stop();
```

```cpp
// ssh -R 8080:localhost:3000, single-threaded
sshpp::RemoteForward::Options o;
o.bind_address = "0.0.0.0";
o.remote_port  = 8080;
o.local_target = sshpp::TcpEndpoint{"127.0.0.1", 3000};
sshpp::RemoteForward rf{session, o};
rf.try_run_until_stopped().value();       // blocks
```

```cpp
// One-off tunnelled connection, no listener
auto ch = sshpp::open_direct(session, sshpp::TcpEndpoint{"10.0.0.5", 6379}).value();
ch.try_write_all("PING\r\n").value();
std::array<std::byte, 64> buf{};
auto n = ch.try_read_some(buf).value();
```
