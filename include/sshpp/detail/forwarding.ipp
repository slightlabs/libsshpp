// SPDX-License-Identifier: LGPL-2.1-or-later
// Generated from src/forwarding.cpp; see docs/design/09 §9.3.
#include <sshpp/config.hpp>
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
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <random>
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

int connect_unix(const UnixEndpoint& target, ErrorInfo& out_error) {
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (target.path.size() >= sizeof(addr.sun_path)) {
        out_error = ErrorInfo{make_error_code(errc::invalid_argument), "path too long", "connect_unix"};
        return -1;
    }
    std::strncpy(addr.sun_path, target.path.c_str(), sizeof(addr.sun_path) - 1);
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        out_error = ErrorInfo{make_error_code(errc::forwarding_failed), std::strerror(errno), "socket"};
        return -1;
    }
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        out_error = ErrorInfo{make_error_code(errc::forwarding_failed), std::strerror(errno), "connect"};
        ::close(fd);
        return -1;
    }
    return fd;
}

int connect_target(const ForwardTarget& target, ErrorInfo& out_error) {
    if (const auto* tcp = std::get_if<TcpEndpoint>(&target)) return connect_tcp(*tcp, out_error);
    return connect_unix(std::get<UnixEndpoint>(target), out_error);
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

// Defined here rather than in channel.ipp: these need Session's complete
// type, and channel.hpp is included from session.hpp *before* class Session,
// so a dependency in the other direction would create an unresolvable
// header-only include cycle. See docs/design/09 §9.3.
SSHPP_INLINE Result<Channel> Channel::open_forward(Session& session, std::string_view remote_host,
                                      std::uint16_t remote_port, std::string_view origin_host,
                                      std::uint16_t origin_port) {
    ssh_channel raw = ssh_channel_new(session.native_handle());
    if (raw == nullptr) {
        return detail::make_error_info(session.native_handle(), "ssh_channel_new", SSHPP_HERE, errc::channel_open_failed);
    }
    std::string remote(remote_host), origin(origin_host);
    int rc = ssh_channel_open_forward(raw, remote.c_str(), remote_port, origin.c_str(), origin_port);
    if (rc != SSH_OK) {
        auto info = detail::make_error_info(session.native_handle(), "ssh_channel_open_forward", SSHPP_HERE,
                                            errc::forwarding_failed);
        ssh_channel_free(raw);
        return info;
    }
    return Channel::from_native(raw, session.core_, Ownership::owning);
}

SSHPP_INLINE Result<Channel> Channel::open_forward_unix(Session& session, std::string_view remote_socket,
                                           std::string_view origin_host, std::uint16_t origin_port) {
    ssh_channel raw = ssh_channel_new(session.native_handle());
    if (raw == nullptr) {
        return detail::make_error_info(session.native_handle(), "ssh_channel_new", SSHPP_HERE, errc::channel_open_failed);
    }
    std::string remote(remote_socket), origin(origin_host);
    int rc = ssh_channel_open_forward_unix(raw, remote.c_str(), origin.c_str(), origin_port);
    if (rc != SSH_OK) {
        auto info = detail::make_error_info(session.native_handle(), "ssh_channel_open_forward_unix", SSHPP_HERE,
                                            errc::forwarding_failed);
        ssh_channel_free(raw);
        return info;
    }
    return Channel::from_native(raw, session.core_, Ownership::owning);
}


SSHPP_INLINE Result<Channel> open_direct(Session& session, const ForwardTarget& remote, TcpEndpoint origin) {
    if (const auto* tcp = std::get_if<TcpEndpoint>(&remote)) {
        return Channel::open_forward(session, tcp->host, tcp->port, origin.host, origin.port);
    }
    const auto& unix_ep = std::get<UnixEndpoint>(remote);
    return Channel::open_forward_unix(session, unix_ep.path, origin.host, origin.port);
}

// ------------------------------------------------------ RemoteForwardListener ----

SSHPP_INLINE RemoteForwardListener::~RemoteForwardListener() {
    if (core_ && !cancelled_ && core_->valid()) {
        ssh_channel_cancel_forward(core_->raw(), bind_address_.empty() ? nullptr : bind_address_.c_str(),
                                   bound_port_);
    }
}

SSHPP_INLINE RemoteForwardListener::RemoteForwardListener(RemoteForwardListener&& other) noexcept
    : core_(std::move(other.core_)), bind_address_(std::move(other.bind_address_)),
      bound_port_(other.bound_port_), cancelled_(std::exchange(other.cancelled_, true)) {}

SSHPP_INLINE RemoteForwardListener& RemoteForwardListener::operator=(RemoteForwardListener&& other) noexcept {
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

SSHPP_INLINE Result<RemoteForwardListener> RemoteForwardListener::create(Session& session, std::string_view bind_address,
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

SSHPP_INLINE Result<std::optional<IncomingForward>> RemoteForwardListener::try_accept(std::chrono::milliseconds timeout) {
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

SSHPP_INLINE Result<void> RemoteForwardListener::try_cancel() {
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

SSHPP_INLINE LocalForward::LocalForward(Session& session, Options opts) : session_(&session), options_(std::move(opts)) {}

SSHPP_INLINE LocalForward::~LocalForward() {
    stop();
    if (thread_.joinable()) thread_.join();
    if (listen_fd_ >= 0) ::close(listen_fd_);
}

SSHPP_INLINE Result<void> LocalForward::bind_listener() {
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

SSHPP_INLINE void LocalForward::pump_one_connection(int client_fd) {
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

SSHPP_INLINE void LocalForward::accept_loop() {
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

SSHPP_INLINE Result<void> LocalForward::try_start() {
    if (running_.load()) return ErrorInfo{make_error_code(errc::already_connected), "", "LocalForward::try_start"};
    auto r = bind_listener();
    if (!r) return r;
    stop_requested_.store(false);
    thread_ = std::thread([this] { accept_loop(); });
    return {};
}

SSHPP_INLINE Result<void> LocalForward::try_run_until_stopped() {
    if (running_.load()) return ErrorInfo{make_error_code(errc::already_connected), "", "LocalForward::try_run_until_stopped"};
    if (listen_fd_ < 0) {
        auto r = bind_listener();
        if (!r) return r;
    }
    stop_requested_.store(false);
    accept_loop();
    return {};
}

SSHPP_INLINE void LocalForward::stop() noexcept {
    stop_requested_.store(true);
    if (thread_.joinable()) thread_.join();
}

SSHPP_INLINE TcpEndpoint LocalForward::local_endpoint() const noexcept { return {options_.listen.host, bound_port_}; }

SSHPP_INLINE ForwardStats LocalForward::stats() const noexcept {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

// ------------------------------------------------------------ RemoteForward ----

SSHPP_INLINE RemoteForward::RemoteForward(Session& session, Options opts) : session_(&session), options_(std::move(opts)) {}

SSHPP_INLINE RemoteForward::~RemoteForward() {
    stop();
    if (thread_.joinable()) thread_.join();
}

SSHPP_INLINE void RemoteForward::pump_one_connection(IncomingForward&& incoming) {
    if (options_.accept_filter && !options_.accept_filter(incoming.originator)) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        ++stats_.rejected;
        return;
    }
    ErrorInfo connect_error;
    int client_fd = connect_target(options_.local_target, connect_error);
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

SSHPP_INLINE void RemoteForward::run_loop() {
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

SSHPP_INLINE Result<void> RemoteForward::try_start() {
    auto listener_result = RemoteForwardListener::create(*session_, options_.bind_address, options_.remote_port);
    if (!listener_result) return listener_result.error();
    listener_ = std::move(*listener_result);
    stop_requested_.store(false);
    thread_ = std::thread([this] { run_loop(); });
    return {};
}

SSHPP_INLINE Result<void> RemoteForward::try_run_until_stopped() {
    if (!listener_) {
        auto listener_result = RemoteForwardListener::create(*session_, options_.bind_address, options_.remote_port);
        if (!listener_result) return listener_result.error();
        listener_ = std::move(*listener_result);
    }
    stop_requested_.store(false);
    run_loop();
    return {};
}

SSHPP_INLINE void RemoteForward::stop() noexcept {
    stop_requested_.store(true);
    if (thread_.joinable()) thread_.join();
}

SSHPP_INLINE ForwardStats RemoteForward::stats() const noexcept {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

// ------------------------------------------------------------------ Connector ----

#if SSHPP_HAS_CONNECTOR
SSHPP_INLINE Connector::Connector(Session& session) : native_(ssh_connector_new(session.native_handle())) {}

SSHPP_INLINE Connector::~Connector() {
    if (native_ != nullptr) ssh_connector_free(native_);
}

SSHPP_INLINE Connector::Connector(Connector&& other) noexcept : native_(std::exchange(other.native_, nullptr)) {}

SSHPP_INLINE Connector& Connector::operator=(Connector&& other) noexcept {
    if (this != &other) {
        if (native_ != nullptr) ssh_connector_free(native_);
        native_ = std::exchange(other.native_, nullptr);
    }
    return *this;
}

namespace {
ssh_connector_flags_e connector_flags(Stream s) {
    return s == Stream::stderr_ ? SSH_CONNECTOR_STDERR : SSH_CONNECTOR_STDOUT;
}
} // namespace

SSHPP_INLINE Result<void> Connector::try_set_in_channel(Channel& channel, Stream stream) {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Connector::try_set_in_channel"};
    if (ssh_connector_set_in_channel(native_, channel.native_handle(), connector_flags(stream)) != SSH_OK) {
        return ErrorInfo{make_error_code(errc::forwarding_failed), "", "ssh_connector_set_in_channel"};
    }
    return {};
}

SSHPP_INLINE Result<void> Connector::try_set_out_channel(Channel& channel, Stream stream) {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Connector::try_set_out_channel"};
    if (ssh_connector_set_out_channel(native_, channel.native_handle(), connector_flags(stream)) != SSH_OK) {
        return ErrorInfo{make_error_code(errc::forwarding_failed), "", "ssh_connector_set_out_channel"};
    }
    return {};
}

SSHPP_INLINE Result<void> Connector::try_set_in_fd(int fd) noexcept {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Connector::try_set_in_fd"};
    ssh_connector_set_in_fd(native_, fd);
    return {};
}

SSHPP_INLINE Result<void> Connector::try_set_out_fd(int fd) noexcept {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Connector::try_set_out_fd"};
    ssh_connector_set_out_fd(native_, fd);
    return {};
}
#endif // SSHPP_HAS_CONNECTOR

// ------------------------------------------------------------ BidirectionalPump ----

SSHPP_INLINE BidirectionalPump::BidirectionalPump(Channel& channel, int local_fd, std::size_t buffer_size)
    : channel_(&channel), local_fd_(local_fd), buffer_size_(buffer_size) {}

SSHPP_INLINE BidirectionalPump::~BidirectionalPump() { stop(); }

SSHPP_INLINE Result<void> BidirectionalPump::try_run_until_stopped() {
    stop_requested_.store(false);
    pump(*channel_, local_fd_, buffer_size_, stats_, stats_mutex_, stop_requested_);
    finished_.store(true);
    return {};
}

SSHPP_INLINE void BidirectionalPump::stop() noexcept { stop_requested_.store(true); }

SSHPP_INLINE std::pair<std::uint64_t, std::uint64_t> BidirectionalPump::byte_counts() const noexcept {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return {stats_.bytes_out, stats_.bytes_in};
}

// ------------------------------------------------------------------- X11 ----

namespace {

/// 16 random bytes hex-encoded, read from the OS CSPRNG (never the real
/// local cookie, which stays local rather than being sent to the server).
std::string random_hex_cookie() {
    std::array<unsigned char, 16> bytes{};
    std::random_device rd;
    for (auto& b : bytes) b = static_cast<unsigned char>(rd());
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (auto b : bytes) {
        out.push_back(hex[b >> 4]);
        out.push_back(hex[b & 0x0F]);
    }
    return out;
}

} // namespace

SSHPP_INLINE X11Forwarder::X11Forwarder(Channel& session_channel, Options opts)
    : session_channel_(&session_channel), options_(std::move(opts)) {}

SSHPP_INLINE Result<void> X11Forwarder::try_request() {
    if (options_.request.auth_cookie.empty()) options_.request.auth_cookie = random_hex_cookie();
    int rc = ssh_channel_request_x11(session_channel_->native_handle(),
                                     options_.request.single_connection ? 1 : 0,
                                     options_.request.auth_protocol.c_str(),
                                     options_.request.auth_cookie.c_str(),
                                     static_cast<int>(options_.request.screen_number));
    if (rc != SSH_OK) {
        return ErrorInfo{make_error_code(errc::x11_failed), "", "ssh_channel_request_x11"};
    }
    return {};
}

SSHPP_INLINE Result<std::optional<Channel>> X11Forwarder::try_accept(std::chrono::milliseconds timeout) {
    native_channel raw = ssh_channel_accept_x11(session_channel_->native_handle(), static_cast<int>(timeout.count()));
    if (raw == nullptr) {
        return std::optional<Channel>{};
    }
    return std::optional<Channel>{Channel::from_native(raw, session_channel_->core_, Ownership::owning)};
}

SSHPP_INLINE Result<void> X11Forwarder::try_run_until_stopped() {
    ForwardTarget target = options_.display_target;
    if (std::holds_alternative<TcpEndpoint>(target) && std::get<TcpEndpoint>(target).host.empty()) {
        const char* display = std::getenv("DISPLAY");
        auto parsed = target_from_display(display != nullptr ? display : "");
        if (!parsed) return parsed.error();
        target = *parsed;
    }
    while (!stop_requested_.load()) {
        auto accepted = try_accept(std::chrono::milliseconds(200));
        if (!accepted) return accepted.error();
        if (!*accepted) continue;
        ErrorInfo connect_error;
        int fd = connect_target(target, connect_error);
        if (fd < 0) continue;
        BidirectionalPump pump_x11(**accepted, fd);
        (void)pump_x11.try_run_until_stopped();
        if (options_.request.single_connection) break;
    }
    return {};
}

SSHPP_INLINE void X11Forwarder::stop() noexcept { stop_requested_.store(true); }

SSHPP_INLINE Result<ForwardTarget> X11Forwarder::target_from_display(std::string_view display) {
    if (display.empty()) {
        return ErrorInfo{make_error_code(errc::invalid_argument), "DISPLAY is not set", "X11Forwarder::target_from_display"};
    }
    auto colon = display.rfind(':');
    if (colon == std::string_view::npos) {
        return ErrorInfo{make_error_code(errc::invalid_argument), "malformed DISPLAY", "X11Forwarder::target_from_display"};
    }
    std::string_view host = display.substr(0, colon);
    std::string_view rest = display.substr(colon + 1);
    auto dot = rest.find('.');
    std::string number_part(dot == std::string_view::npos ? rest : rest.substr(0, dot));
    int display_num = 0;
    try {
        display_num = std::stoi(number_part);
    } catch (...) {
        return ErrorInfo{make_error_code(errc::invalid_argument), "malformed DISPLAY", "X11Forwarder::target_from_display"};
    }
    if (host.empty() || host == "unix") {
        return ForwardTarget{UnixEndpoint{"/tmp/.X11-unix/X" + std::to_string(display_num)}};
    }
    return ForwardTarget{TcpEndpoint{std::string(host), static_cast<std::uint16_t>(6000 + display_num)}};
}

// ----------------------------------------------------------------- SOCKS ----

namespace {

constexpr unsigned char kSocksVersion5 = 0x05;
constexpr unsigned char kSocksVersion4 = 0x04;

bool recv_exact(int fd, void* buf, std::size_t len) {
    auto* p = static_cast<unsigned char*>(buf);
    std::size_t got = 0;
    while (got < len) {
        ssize_t n = ::recv(fd, p + got, len - got, 0);
        if (n <= 0) return false;
        got += static_cast<std::size_t>(n);
    }
    return true;
}

bool send_exact(int fd, const void* buf, std::size_t len) {
    const auto* p = static_cast<const unsigned char*>(buf);
    std::size_t sent = 0;
    while (sent < len) {
        ssize_t n = ::send(fd, p + sent, len - sent, 0);
        if (n <= 0) return false;
        sent += static_cast<std::size_t>(n);
    }
    return true;
}

/// Reads a SOCKS5 CONNECT request's method-negotiation and address/port
/// fields off `client_fd` (the version byte has already been consumed by the
/// caller). Returns nullopt on any protocol violation (strict length checks
/// throughout, per the SOCKS hardening notes in forwarding.hpp).
std::optional<ForwardTarget> read_socks5_request(int client_fd) {
    unsigned char nmethods = 0;
    if (!recv_exact(client_fd, &nmethods, 1)) return std::nullopt;
    std::vector<unsigned char> methods(nmethods);
    if (nmethods > 0 && !recv_exact(client_fd, methods.data(), nmethods)) return std::nullopt;
    // Only "no authentication required" is ever advertised.
    bool has_no_auth = std::find(methods.begin(), methods.end(), 0x00) != methods.end();
    unsigned char method_reply[2] = {kSocksVersion5, static_cast<unsigned char>(has_no_auth ? 0x00 : 0xFF)};
    if (!send_exact(client_fd, method_reply, 2) || !has_no_auth) return std::nullopt;

    unsigned char req[4];
    if (!recv_exact(client_fd, req, 4)) return std::nullopt;
    if (req[0] != kSocksVersion5 || req[1] != 0x01 /* CONNECT */) return std::nullopt;
    unsigned char atyp = req[3];

    TcpEndpoint ep;
    if (atyp == 0x01) { // IPv4
        unsigned char addr[4];
        if (!recv_exact(client_fd, addr, 4)) return std::nullopt;
        char text[INET_ADDRSTRLEN] = {};
        ::inet_ntop(AF_INET, addr, text, sizeof(text));
        ep.host = text;
    } else if (atyp == 0x03) { // domain name
        unsigned char len = 0;
        if (!recv_exact(client_fd, &len, 1) || len == 0) return std::nullopt;
        std::string host(len, '\0');
        if (!recv_exact(client_fd, host.data(), len)) return std::nullopt;
        ep.host = std::move(host);
    } else if (atyp == 0x04) { // IPv6
        unsigned char addr[16];
        if (!recv_exact(client_fd, addr, 16)) return std::nullopt;
        char text[INET6_ADDRSTRLEN] = {};
        ::inet_ntop(AF_INET6, addr, text, sizeof(text));
        ep.host = text;
    } else {
        return std::nullopt;
    }
    unsigned char port_bytes[2];
    if (!recv_exact(client_fd, port_bytes, 2)) return std::nullopt;
    ep.port = static_cast<std::uint16_t>((port_bytes[0] << 8) | port_bytes[1]);
    return ForwardTarget{ep};
}

void reply_socks5(int client_fd, unsigned char status) {
    unsigned char reply[10] = {kSocksVersion5, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    send_exact(client_fd, reply, sizeof(reply));
}

std::optional<ForwardTarget> read_socks4_request(int client_fd, unsigned char first_byte) {
    unsigned char rest[7];
    if (!recv_exact(client_fd, rest, 7)) return std::nullopt;
    if (rest[0] != 0x01 /* CONNECT */) return std::nullopt;
    std::uint16_t port = static_cast<std::uint16_t>((rest[1] << 8) | rest[2]);
    char ip_text[INET_ADDRSTRLEN] = {};
    ::inet_ntop(AF_INET, &rest[3], ip_text, sizeof(ip_text));
    // Drain the null-terminated userid field (bounded: SOCKS4 has no length prefix).
    for (int i = 0; i < 256; ++i) {
        unsigned char c = 0;
        if (!recv_exact(client_fd, &c, 1)) return std::nullopt;
        if (c == 0) break;
        if (i == 255) return std::nullopt;
    }
    (void)first_byte;
    return ForwardTarget{TcpEndpoint{ip_text, port}};
}

void reply_socks4(int client_fd, bool granted) {
    unsigned char reply[8] = {0x00, static_cast<unsigned char>(granted ? 0x5A : 0x5B), 0, 0, 0, 0, 0, 0};
    send_exact(client_fd, reply, sizeof(reply));
}

} // namespace

SSHPP_INLINE SocksProxy::SocksProxy(Session& session, Options opts) : session_(&session), options_(std::move(opts)) {}

SSHPP_INLINE SocksProxy::~SocksProxy() {
    stop();
    if (thread_.joinable()) thread_.join();
    if (listen_fd_ >= 0) ::close(listen_fd_);
}

SSHPP_INLINE Result<void> SocksProxy::bind_listener() {
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
    if (fd < 0) return ErrorInfo{make_error_code(errc::forwarding_failed), std::strerror(errno), "bind"};
    if (::listen(fd, 16) != 0) {
        ::close(fd);
        return ErrorInfo{make_error_code(errc::forwarding_failed), std::strerror(errno), "listen"};
    }
    sockaddr_storage addr{};
    socklen_t addr_len = sizeof(addr);
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &addr_len) == 0 && addr.ss_family == AF_INET) {
        bound_port_ = ntohs(reinterpret_cast<sockaddr_in*>(&addr)->sin_port);
    }
    listen_fd_ = fd;
    return {};
}

SSHPP_INLINE void SocksProxy::serve_one_connection(int client_fd) {
    unsigned char first_byte = 0;
    if (!recv_exact(client_fd, &first_byte, 1)) {
        ::close(client_fd);
        return;
    }

    bool is_socks4 = (first_byte == kSocksVersion4);
    if (is_socks4 && !options_.allow_socks4) {
        ::close(client_fd);
        return;
    }
    if (first_byte != kSocksVersion4 && first_byte != kSocksVersion5) {
        ::close(client_fd);
        return;
    }

    std::optional<ForwardTarget> target =
        is_socks4 ? read_socks4_request(client_fd, first_byte) : read_socks5_request(client_fd);
    if (!target) {
        ::close(client_fd);
        return;
    }
    if (options_.allow && !options_.allow(*target)) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        ++stats_.rejected;
        if (is_socks4) reply_socks4(client_fd, false); else reply_socks5(client_fd, 0x02 /* not allowed */);
        ::close(client_fd);
        return;
    }

    auto channel_result = open_direct(*session_, *target);
    if (!channel_result) {
        report_error(options_.on_error, channel_result.error());
        if (is_socks4) reply_socks4(client_fd, false); else reply_socks5(client_fd, 0x01 /* general failure */);
        ::close(client_fd);
        return;
    }
    if (is_socks4) reply_socks4(client_fd, true); else reply_socks5(client_fd, 0x00 /* granted */);
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        ++stats_.connections;
    }
    pump(*channel_result, client_fd, options_.buffer_size, stats_, stats_mutex_, stop_requested_);
}

SSHPP_INLINE void SocksProxy::accept_loop() {
    running_.store(true);
    while (!stop_requested_.load()) {
        pollfd pfd{listen_fd_, POLLIN, 0};
        int rv = ::poll(&pfd, 1, 200);
        if (rv <= 0) continue;
        int client_fd = ::accept(listen_fd_, nullptr, nullptr);
        if (client_fd < 0) continue;
        serve_one_connection(client_fd);
    }
    running_.store(false);
}

SSHPP_INLINE Result<void> SocksProxy::try_start() {
    if (running_.load()) return ErrorInfo{make_error_code(errc::already_connected), "", "SocksProxy::try_start"};
    auto r = bind_listener();
    if (!r) return r;
    stop_requested_.store(false);
    thread_ = std::thread([this] { accept_loop(); });
    return {};
}

SSHPP_INLINE Result<void> SocksProxy::try_run_until_stopped() {
    if (running_.load()) return ErrorInfo{make_error_code(errc::already_connected), "", "SocksProxy::try_run_until_stopped"};
    if (listen_fd_ < 0) {
        auto r = bind_listener();
        if (!r) return r;
    }
    stop_requested_.store(false);
    accept_loop();
    return {};
}

SSHPP_INLINE void SocksProxy::stop() noexcept {
    stop_requested_.store(true);
    if (thread_.joinable()) thread_.join();
}

SSHPP_INLINE ForwardStats SocksProxy::stats() const noexcept {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

} // namespace sshpp
