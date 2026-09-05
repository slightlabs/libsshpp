// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port forwarding primitives (direct-tcpip / tcpip-forward) plus LocalForward
// and RemoteForward pumps, the Connector/BidirectionalPump primitive,
// X11Forwarder and SocksProxy. See docs/design/07-api-forwarding.md.
//
// Scope note: LocalForward/RemoteForward serve one active connection at a
// time (simple poll-based byte pump, POSIX sockets only). BidirectionalPump
// always uses that same poll-based pump internally (rather than
// ssh_connector_*) so it can report accurate byte_counts()/finished(); the
// real ssh_connector_* API is still exposed as Connector for callers who want
// to drive it via an Event directly.
#pragma once

#include <sshpp/config.hpp>

#include <sshpp/channel.hpp>
#include <sshpp/detail/session_core.hpp>
#include <sshpp/export.hpp>
#include <sshpp/fwd.hpp>
#include <sshpp/result.hpp>
#include <sshpp/types.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <variant>

namespace sshpp {

struct TcpEndpoint {
    std::string   host;
    std::uint16_t port = 0;
};

struct UnixEndpoint { std::string path; };

using ForwardTarget = std::variant<TcpEndpoint, UnixEndpoint>;

/// Primitive: one channel to one remote endpoint (direct-tcpip / direct-streamlocal).
/// No local listener involved.
SSHPP_API Result<Channel> open_direct(Session&, const ForwardTarget& remote,
                                      TcpEndpoint origin = {"127.0.0.1", 0});

struct SSHPP_API ForwardStats {
    std::uint64_t connections = 0;
    std::uint64_t bytes_out = 0;
    std::uint64_t bytes_in = 0;
    std::uint64_t rejected = 0;
};

/// `ssh -R` originator/listener primitive: server listens, hands us inbound channels.
struct IncomingForward {
    Channel       channel;
    std::uint16_t bound_port = 0;
    /// Attacker-controlled: the server reports this, never use it for authorization.
    TcpEndpoint   originator;
};

class SSHPP_API RemoteForwardListener {
public:
    RemoteForwardListener() = default;
    ~RemoteForwardListener();
    RemoteForwardListener(RemoteForwardListener&&) noexcept;
    RemoteForwardListener& operator=(RemoteForwardListener&&) noexcept;
    RemoteForwardListener(const RemoteForwardListener&) = delete;

    /// bind_address: "" = all interfaces (server policy permitting), "localhost", an IP.
    /// port 0 asks the server to allocate one; read it back with bound_port().
    static Result<RemoteForwardListener> create(Session&, std::string_view bind_address,
                                                std::uint16_t port);

    explicit operator bool() const noexcept { return core_ != nullptr; }
    std::uint16_t bound_port() const noexcept { return bound_port_; }

    /// Blocks up to `timeout`; nullopt on timeout.
    Result<std::optional<IncomingForward>> try_accept(std::chrono::milliseconds timeout);
    Result<void> try_cancel();

private:
    RemoteForwardListener(detail::SessionCorePtr core, std::string bind_address, std::uint16_t bound_port)
        : core_(std::move(core)), bind_address_(std::move(bind_address)), bound_port_(bound_port) {}

    detail::SessionCorePtr core_;
    std::string             bind_address_;
    std::uint16_t           bound_port_ = 0;
    bool                    cancelled_ = false;
};

/// `ssh -L` equivalent: local TCP listener -> one channel per accepted connection.
/// Connections are served one at a time (see the scope note at the top of this file).
class SSHPP_API LocalForward {
public:
    struct Options {
        TcpEndpoint   listen{"127.0.0.1", 0};
        ForwardTarget target;
        std::size_t   buffer_size = 64 * 1024;
        std::function<bool(const TcpEndpoint& peer)> accept_filter;
        std::function<void(const ErrorInfo&)>         on_error;
    };

    LocalForward(Session&, Options);
    ~LocalForward();
    LocalForward(const LocalForward&) = delete;
    LocalForward& operator=(const LocalForward&) = delete;

    Result<void>  try_start();
    void          stop() noexcept;
    bool          running() const noexcept { return running_.load(); }
    TcpEndpoint   local_endpoint() const noexcept;
    ForwardStats  stats() const noexcept;

    /// Drives the accept loop on the calling thread instead of spawning one.
    Result<void> try_run_until_stopped();

private:
    Result<void> bind_listener();
    void         accept_loop();
    void         pump_one_connection(int client_fd);

    Session*             session_;
    Options               options_;
    int                    listen_fd_ = -1;
    std::uint16_t          bound_port_ = 0;
    std::atomic<bool>      running_{false};
    std::atomic<bool>      stop_requested_{false};
    std::thread            thread_;
    mutable std::mutex     stats_mutex_;
    ForwardStats           stats_;
};

/// `ssh -R` equivalent: accept loop that connects each inbound channel to a local endpoint.
class SSHPP_API RemoteForward {
public:
    struct Options {
        std::string   bind_address = "localhost";
        std::uint16_t remote_port = 0;
        ForwardTarget local_target;
        std::function<bool(const TcpEndpoint& originator)> accept_filter;
        std::function<void(const ErrorInfo&)>               on_error;
    };

    RemoteForward(Session&, Options);
    ~RemoteForward();
    RemoteForward(const RemoteForward&) = delete;
    RemoteForward& operator=(const RemoteForward&) = delete;

    Result<void>  try_start();
    Result<void>  try_run_until_stopped();
    void          stop() noexcept;
    std::uint16_t remote_port() const noexcept { return listener_.bound_port(); }
    ForwardStats  stats() const noexcept;

private:
    void run_loop();
    void pump_one_connection(IncomingForward&&);

    Session*                session_;
    Options                  options_;
    RemoteForwardListener   listener_;
    std::atomic<bool>       stop_requested_{false};
    std::thread             thread_;
    mutable std::mutex      stats_mutex_;
    ForwardStats            stats_;
};

#if SSHPP_HAS_CONNECTOR
/// Thin wrapper around ssh_connector_* (see docs/design/07 §7.5). Bidirectionally
/// copies bytes between two endpoints once registered with an Event, which drives it.
class SSHPP_API Connector {
public:
    explicit Connector(Session&);
    ~Connector();
    Connector(Connector&&) noexcept;
    Connector& operator=(Connector&&) noexcept;
    Connector(const Connector&) = delete;

    Result<void> try_set_in_channel(Channel&, Stream = Stream::stdout_);
    Result<void> try_set_out_channel(Channel&, Stream = Stream::stdout_);
    Result<void> try_set_in_fd(int) noexcept;
    Result<void> try_set_out_fd(int) noexcept;

    native_connector native_handle() const noexcept { return native_; }

private:
    native_connector native_ = nullptr;
};
#endif

/// Pairs two byte pumps (fd->channel and channel->fd) with lifetime/EOF handling.
/// Uses the same poll-based pump as LocalForward/RemoteForward so byte_counts()
/// and finished() are always accurate (see the scope note at the top of this file).
/// Deliberately takes no Session& (unlike the design doc's sketch): nothing it
/// does needs one, and callers that only have a Channel (e.g. X11Forwarder)
/// would not be able to supply one.
class SSHPP_API BidirectionalPump {
public:
    BidirectionalPump(Channel&, int local_fd, std::size_t buffer_size = 64 * 1024);
    ~BidirectionalPump();
    BidirectionalPump(const BidirectionalPump&) = delete;
    BidirectionalPump& operator=(const BidirectionalPump&) = delete;

    /// Drives the pump on the calling thread until both directions reach EOF/close.
    Result<void> try_run_until_stopped();
    void         stop() noexcept;
    bool         finished() const noexcept { return finished_.load(); }
    std::pair<std::uint64_t, std::uint64_t> byte_counts() const noexcept;

private:
    Channel*            channel_;
    int                  local_fd_;
    std::size_t          buffer_size_;
    std::atomic<bool>    stop_requested_{false};
    std::atomic<bool>    finished_{false};
    mutable std::mutex   stats_mutex_;
    ForwardStats         stats_;
};

// -------------------------------------------------------------------- X11 ----

struct X11Request {
    bool          single_connection = false;
    std::string   auth_protocol = "MIT-MAGIC-COOKIE-1";
    std::string   auth_cookie;              // hex; empty -> generate a random one
    std::uint32_t screen_number = 0;
};

/// Client-side X11 forwarding: request it on an open session channel, then accept
/// and pump the (usually single) resulting x11 channel to a local X display.
/// See docs/design/07 §7.4. X11 forwarding is a well-known security hazard: a
/// compromised remote host gets access to the local display, so `trusted`
/// defaults to false and `single_connection` is recommended.
class SSHPP_API X11Forwarder {
public:
    struct Options {
        X11Request    request;
        ForwardTarget display_target;      // defaults to $DISPLAY parsing if left empty
        bool          trusted = false;
    };

    // No `= {}` default here: GCC rejects a default argument whose type is a
    // nested class of the same enclosing class when that nested class has a
    // default member initializer (a `<brace-enclosed initializer list>` from
    // conversion error). Callers wanting defaults pass `Options{}` explicitly.
    explicit X11Forwarder(Channel& session_channel, Options options);

    Result<void> try_request();
    /// Blocks up to `timeout` for the server to open an x11 channel.
    Result<std::optional<Channel>> try_accept(std::chrono::milliseconds timeout);
    /// Accepts then pumps x11 channels to the local display until stop() is called.
    Result<void> try_run_until_stopped();
    void stop() noexcept;

    /// Parses $DISPLAY (":0", "localhost:10.0", "host:0") into a ForwardTarget.
    static Result<ForwardTarget> target_from_display(std::string_view display);

private:
    Channel*          session_channel_;
    Options            options_;
    std::atomic<bool>  stop_requested_{false};
};

// ----------------------------------------------------------------- SOCKS ----

/// Dynamic forwarding (`ssh -D`): a minimal local SOCKS4/5 proxy tunnelling
/// CONNECT requests over `direct-tcpip` channels. libssh has no SOCKS support;
/// this is ours. See docs/design/07 §7.6.
///
/// Hardening: SOCKS5 only by default (allow_socks4 opts in), no auth method
/// advertised other than "no auth" (the listener is loopback-only by
/// default), hostnames are forwarded to the SSH server rather than resolved
/// locally (matches `ssh -D`, avoids local DNS leaks), strict length checks
/// on every field of the request, and a hard cap on in-flight connections.
class SSHPP_API SocksProxy {
public:
    struct Options {
        TcpEndpoint   listen{"127.0.0.1", 1080};
        bool          allow_socks4 = false;
        std::size_t   max_connections = 128;
        std::size_t   buffer_size = 64 * 1024;
        /// Called with the requested destination; return false to refuse.
        std::function<bool(const ForwardTarget&)>     allow;
        std::function<void(const ErrorInfo&)>          on_error;
    };

    SocksProxy(Session&, Options);
    ~SocksProxy();
    SocksProxy(const SocksProxy&) = delete;
    SocksProxy& operator=(const SocksProxy&) = delete;

    Result<void>  try_start();
    Result<void>  try_run_until_stopped();
    void          stop() noexcept;
    bool          running() const noexcept { return running_.load(); }
    TcpEndpoint   local_endpoint() const noexcept { return {options_.listen.host, bound_port_}; }
    ForwardStats  stats() const noexcept;

private:
    Result<void> bind_listener();
    void         accept_loop();
    void         serve_one_connection(int client_fd);

    Session*             session_;
    Options               options_;
    int                    listen_fd_ = -1;
    std::uint16_t          bound_port_ = 0;
    std::atomic<bool>      running_{false};
    std::atomic<bool>      stop_requested_{false};
    std::thread            thread_;
    mutable std::mutex     stats_mutex_;
    ForwardStats           stats_;
};

} // namespace sshpp

#if SSHPP_HEADER_ONLY
#include <sshpp/detail/forwarding.ipp>
#endif
