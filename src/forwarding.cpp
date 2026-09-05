// SPDX-License-Identifier: LGPL-2.1-or-later
//
// POSIX-only for now (uses <sys/socket.h> etc. directly rather than a
// portable socket abstraction); Windows support is future work.
#include <sshpp/forwarding.hpp>
#include <sshpp/detail/invoke.hpp>
#include <sshpp/session.hpp>

#include <libssh/libssh.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <vector>

namespace sshpp {

namespace {

void report_error(const std::function<void(const ErrorInfo&)>& on_error, const ErrorInfo& info) {
    if (on_error) on_error(info);
}

int connect_tcp(const TcpEndpoint& target, ErrorInfo& out_error) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* results = nullptr;
    std::string port_str = std::to_string(target.port);
    int rc = getaddrinfo(target.host.c_str(), port_str.c_str(), &hints, &results);
    if (rc != 0 || results == nullptr) {
        out_error = ErrorInfo{make_error_code(errc::forwarding_failed), gai_strerror(rc), "getaddrinfo"};
        return -1;
    }
    int fd = -1;
    for (addrinfo* p = results; p != nullptr; p = p->ai_next) {
        fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        if (::connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        ::close(fd);
        fd = -1;
    }
    freeaddrinfo(results);
    if (fd < 0) {
        out_error = ErrorInfo{make_error_code(errc::forwarding_failed), std::strerror(errno), "connect"};
    }
    return fd;
}

/// Simple poll-based bidirectional byte pump between `client_fd` and `channel`.
/// A production pump would use ssh_connector/Event; this is the pragmatic
/// stand-in documented at the top of forwarding.hpp.
void pump(Channel& channel, int client_fd, std::size_t buffer_size, ForwardStats& stats,
         std::mutex& stats_mutex, const std::atomic<bool>& stop_requested) {
    std::vector<std::byte> buf(buffer_size);
    bool client_eof = false;
    bool channel_eof = false;

    while (!stop_requested.load() && !(client_eof && channel_eof)) {
        bool progressed = false;

        if (!channel_eof) {
            auto avail = channel.try_bytes_available();
            if (avail && *avail > 0) {
                auto r = channel.try_read_some(MutableByteView(buf.data(), std::min(buf.size(), *avail)));
                if (r && *r > 0) {
                    ::send(client_fd, buf.data(), *r, 0);
                    std::lock_guard<std::mutex> lock(stats_mutex);
                    stats.bytes_out += *r;
                    progressed = true;
                }
            }
            if (channel.is_eof()) {
                ::shutdown(client_fd, SHUT_WR);
                channel_eof = true;
            }
        }

        if (!client_eof) {
            pollfd pfd{client_fd, POLLIN, 0};
            if (::poll(&pfd, 1, progressed ? 0 : 50) > 0 && (pfd.revents & POLLIN)) {
                ssize_t n = ::recv(client_fd, buf.data(), buf.size(), 0);
                if (n > 0) {
                    (void)channel.try_write_all(ByteView(buf.data(), static_cast<std::size_t>(n)));
                    std::lock_guard<std::mutex> lock(stats_mutex);
                    stats.bytes_in += static_cast<std::uint64_t>(n);
                    progressed = true;
                } else {
                    (void)channel.try_send_eof();
                    client_eof = true;
                }
            }
        }

        if (!progressed && channel_eof == false && client_eof == false) {
            // Nothing ready on either side; avoid a hot spin.
        }
    }
    (void)channel.try_close();
    ::close(client_fd);
}

} // namespace

// ------------------------------------------------------------ open_direct ----

Result<Channel> open_direct(Session& session, const ForwardTarget& remote, TcpEndpoint origin) {
    if (const auto* tcp = std::get_if<TcpEndpoint>(&remote)) {
        return Channel::open_forward(session, tcp->host, tcp->port, origin.host, origin.port);
    }
    const auto& unix_ep = std::get<UnixEndpoint>(remote);
    return Channel::open_forward_unix(session, unix_ep.path, origin.host, origin.port);
}

// ------------------------------------------------------ RemoteForwardListener ----

RemoteForwardListener::~RemoteForwardListener() {
    if (core_ && !cancelled_ && core_->valid()) {
        ssh_channel_cancel_forward(core_->raw(), bind_address_.empty() ? nullptr : bind_address_.c_str(),
                                   bound_port_);
    }
}

RemoteForwardListener::RemoteForwardListener(RemoteForwardListener&& other) noexcept
    : core_(std::move(other.core_)), bind_address_(std::move(other.bind_address_)),
      bound_port_(other.bound_port_), cancelled_(std::exchange(other.cancelled_, true)) {}

RemoteForwardListener& RemoteForwardListener::operator=(RemoteForwardListener&& other) noexcept {
    if (this != &other) {
        if (core_ && !cancelled_ && core_->valid()) {
            ssh_channel_cancel_forward(core_->raw(), bind_address_.empty() ? nullptr : bind_address_.c_str(),
                                       bound_port_);
        }
        core_ = std::move(other.core_);
        bind_address_ = std::move(other.bind_address_);
        bound_port_ = other.bound_port_;
        cancelled_ = std::exchange(other.cancelled_, true);
    }
    return *this;
}

Result<RemoteForwardListener> RemoteForwardListener::create(Session& session, std::string_view bind_address,
                                                             std::uint16_t port) {
    std::string addr(bind_address);
    int bound = 0;
    int rc = ssh_channel_listen_forward(session.native_handle(), addr.empty() ? nullptr : addr.c_str(),
                                        port, &bound);
    if (rc != SSH_OK) {
        return detail::make_error_info(session.native_handle(), "ssh_channel_listen_forward", SSHPP_HERE,
                                       errc::forwarding_failed);
    }
    return RemoteForwardListener(session.core_, std::move(addr), static_cast<std::uint16_t>(bound));
}

Result<std::optional<IncomingForward>> RemoteForwardListener::try_accept(std::chrono::milliseconds timeout) {
    if (!core_) return ErrorInfo{make_error_code(errc::invalid_handle), "", "RemoteForwardListener::try_accept"};
    int destination_port = 0;
    char* originator = nullptr;
    int originator_port = 0;
    ssh_channel raw = ssh_channel_open_forward_port(core_->raw(), static_cast<int>(timeout.count()),
                                                    &destination_port, &originator, &originator_port);
    if (raw == nullptr) {
        if (ssh_get_error_code(core_->raw()) == SSH_NO_ERROR) {
            return std::optional<IncomingForward>{};
        }
        return detail::make_error_info(core_->raw(), "ssh_channel_open_forward_port", SSHPP_HERE,
                                       errc::forwarding_failed);
    }
    IncomingForward result;
    result.bound_port = static_cast<std::uint16_t>(destination_port);
    result.originator.host = originator ? originator : "";
    result.originator.port = static_cast<std::uint16_t>(originator_port);
    if (originator != nullptr) ssh_string_free_char(originator);
    result.channel = Channel::from_native(raw, core_, Ownership::owning);
    return std::optional<IncomingForward>{std::move(result)};
}

Result<void> RemoteForwardListener::try_cancel() {
    if (!core_) return ErrorInfo{make_error_code(errc::invalid_handle), "", "RemoteForwardListener::try_cancel"};
    int rc = ssh_channel_cancel_forward(core_->raw(), bind_address_.empty() ? nullptr : bind_address_.c_str(),
                                        bound_port_);
    cancelled_ = true;
    if (rc != SSH_OK) {
        return detail::make_error_info(core_->raw(), "ssh_channel_cancel_forward", SSHPP_HERE,
                                       errc::forwarding_failed);
    }
    return {};
}

// ------------------------------------------------------------- LocalForward ----

LocalForward::LocalForward(Session& session, Options opts) : session_(&session), options_(std::move(opts)) {}

LocalForward::~LocalForward() {
    stop();
    if (thread_.joinable()) thread_.join();
    if (listen_fd_ >= 0) ::close(listen_fd_);
}

Result<void> LocalForward::bind_listener() {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    addrinfo* results = nullptr;
    std::string port_str = std::to_string(options_.listen.port);
    int rc = getaddrinfo(options_.listen.host.c_str(), port_str.c_str(), &hints, &results);
    if (rc != 0 || results == nullptr) {
        return ErrorInfo{make_error_code(errc::forwarding_failed), gai_strerror(rc), "getaddrinfo"};
    }
    int fd = -1;
    for (addrinfo* p = results; p != nullptr; p = p->ai_next) {
        fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        int yes = 1;
        ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        if (::bind(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        ::close(fd);
        fd = -1;
    }
    freeaddrinfo(results);
    if (fd < 0) {
        return ErrorInfo{make_error_code(errc::forwarding_failed), std::strerror(errno), "bind"};
    }
    if (::listen(fd, 16) != 0) {
        ::close(fd);
        return ErrorInfo{make_error_code(errc::forwarding_failed), std::strerror(errno), "listen"};
    }
    sockaddr_storage addr{};
    socklen_t addr_len = sizeof(addr);
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &addr_len) == 0) {
        bound_port_ = ntohs(reinterpret_cast<sockaddr_in*>(&addr)->sin_port);
    }
    listen_fd_ = fd;
    return {};
}

void LocalForward::pump_one_connection(int client_fd) {
    if (options_.accept_filter) {
        sockaddr_storage addr{};
        socklen_t addr_len = sizeof(addr);
        TcpEndpoint peer;
        if (::getpeername(client_fd, reinterpret_cast<sockaddr*>(&addr), &addr_len) == 0 &&
            addr.ss_family == AF_INET) {
            char host[INET6_ADDRSTRLEN] = {};
            auto* in4 = reinterpret_cast<sockaddr_in*>(&addr);
            ::inet_ntop(AF_INET, &in4->sin_addr, host, sizeof(host));
            peer.host = host;
            peer.port = ntohs(in4->sin_port);
        }
        if (!options_.accept_filter(peer)) {
            ::close(client_fd);
            std::lock_guard<std::mutex> lock(stats_mutex_);
            ++stats_.rejected;
            return;
        }
    }

    auto channel_result = open_direct(*session_, options_.target);
    if (!channel_result) {
        report_error(options_.on_error, channel_result.error());
        ::close(client_fd);
        return;
    }
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        ++stats_.connections;
    }
    pump(*channel_result, client_fd, options_.buffer_size, stats_, stats_mutex_, stop_requested_);
}

void LocalForward::accept_loop() {
    running_.store(true);
    while (!stop_requested_.load()) {
        pollfd pfd{listen_fd_, POLLIN, 0};
        int rv = ::poll(&pfd, 1, 200);
        if (rv <= 0) continue;
        int client_fd = ::accept(listen_fd_, nullptr, nullptr);
        if (client_fd < 0) continue;
        pump_one_connection(client_fd);
    }
    running_.store(false);
}

Result<void> LocalForward::try_start() {
    if (running_.load()) return ErrorInfo{make_error_code(errc::already_connected), "", "LocalForward::try_start"};
    auto r = bind_listener();
    if (!r) return r;
    stop_requested_.store(false);
    thread_ = std::thread([this] { accept_loop(); });
    return {};
}

Result<void> LocalForward::try_run_until_stopped() {
    if (running_.load()) return ErrorInfo{make_error_code(errc::already_connected), "", "LocalForward::try_run_until_stopped"};
    if (listen_fd_ < 0) {
        auto r = bind_listener();
        if (!r) return r;
    }
    stop_requested_.store(false);
    accept_loop();
    return {};
}

void LocalForward::stop() noexcept {
    stop_requested_.store(true);
    if (thread_.joinable()) thread_.join();
}

TcpEndpoint LocalForward::local_endpoint() const noexcept { return {options_.listen.host, bound_port_}; }

ForwardStats LocalForward::stats() const noexcept {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

// ------------------------------------------------------------ RemoteForward ----

RemoteForward::RemoteForward(Session& session, Options opts) : session_(&session), options_(std::move(opts)) {}

RemoteForward::~RemoteForward() {
    stop();
    if (thread_.joinable()) thread_.join();
}

void RemoteForward::pump_one_connection(IncomingForward&& incoming) {
    if (options_.accept_filter && !options_.accept_filter(incoming.originator)) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        ++stats_.rejected;
        return;
    }
    ErrorInfo connect_error;
    const auto* tcp_target = std::get_if<TcpEndpoint>(&options_.local_target);
    int client_fd = tcp_target != nullptr ? connect_tcp(*tcp_target, connect_error) : -1;
    if (client_fd < 0) {
        report_error(options_.on_error, connect_error);
        return;
    }
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        ++stats_.connections;
    }
    pump(incoming.channel, client_fd, 64 * 1024, stats_, stats_mutex_, stop_requested_);
}

void RemoteForward::run_loop() {
    while (!stop_requested_.load()) {
        auto accepted = listener_.try_accept(std::chrono::milliseconds(200));
        if (!accepted) {
            report_error(options_.on_error, accepted.error());
            continue;
        }
        if (!*accepted) continue;
        pump_one_connection(std::move(**accepted));
    }
}

Result<void> RemoteForward::try_start() {
    auto listener_result = RemoteForwardListener::create(*session_, options_.bind_address, options_.remote_port);
    if (!listener_result) return listener_result.error();
    listener_ = std::move(*listener_result);
    stop_requested_.store(false);
    thread_ = std::thread([this] { run_loop(); });
    return {};
}

Result<void> RemoteForward::try_run_until_stopped() {
    if (!listener_) {
        auto listener_result = RemoteForwardListener::create(*session_, options_.bind_address, options_.remote_port);
        if (!listener_result) return listener_result.error();
        listener_ = std::move(*listener_result);
    }
    stop_requested_.store(false);
    run_loop();
    return {};
}

void RemoteForward::stop() noexcept {
    stop_requested_.store(true);
    if (thread_.joinable()) thread_.join();
}

ForwardStats RemoteForward::stats() const noexcept {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

} // namespace sshpp
