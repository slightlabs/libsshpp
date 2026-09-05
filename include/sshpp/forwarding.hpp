// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Port forwarding primitives (direct-tcpip / tcpip-forward) plus LocalForward
// and RemoteForward pumps. See docs/design/07-api-forwarding.md.
//
// Scope note: this implementation covers -L/-R with one active connection
// pumped at a time per forwarder (simple poll-based byte pump, POSIX sockets
// only). X11Forwarder, SocksProxy and the ssh_connector-based Connector /
// BidirectionalPump primitives from the design are not implemented yet.
#pragma once

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

} // namespace sshpp
