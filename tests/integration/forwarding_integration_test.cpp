#include <catch2/catch_test_macros.hpp>
#include <sshpp/forwarding.hpp>
#include <sshpp/sshpp.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <array>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>

using namespace sshpp;

namespace {

std::string env(const char* name) {
    const char* v = std::getenv(name);
    if (v == nullptr) {
        FAIL("missing required environment variable " << name);
    }
    return v;
}

Session make_connected_session() {
    SessionOptions opts;
    opts.host = env("SSHPP_TEST_HOST");
    opts.port = static_cast<std::uint16_t>(std::stoi(env("SSHPP_TEST_PORT")));
    opts.user = env("SSHPP_TEST_USER");
    opts.identities.push_back(env("SSHPP_TEST_KEY"));
    opts.known_hosts = env("SSHPP_TEST_KNOWN_HOSTS");
    opts.timeout = std::chrono::seconds{5};

    Session session{opts};
    session.connect();
    session.verify_host_key(TofuHostKeyPolicy{});
    auth::PublicKeyAuto authenticator;
    session.authenticate(authenticator);
    return session;
}

/// Minimal single-connection TCP echo server used as the forwarding target;
/// there is no sshpp server module yet to serve this role.
class EchoServer {
public:
    EchoServer() {
        listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        int yes = 1;
        ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        ::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        ::listen(listen_fd_, 4);
        socklen_t len = sizeof(addr);
        ::getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&addr), &len);
        port_ = ntohs(addr.sin_port);
        thread_ = std::thread([this] { run(); });
    }

    ~EchoServer() {
        stop_.store(true);
        if (thread_.joinable()) thread_.join();
        ::close(listen_fd_);
    }

    std::uint16_t port() const noexcept { return port_; }

private:
    void run() {
        while (!stop_.load()) {
            pollfd pfd{listen_fd_, POLLIN, 0};
            if (::poll(&pfd, 1, 200) <= 0) continue;
            int client = ::accept(listen_fd_, nullptr, nullptr);
            if (client < 0) continue;
            char buf[4096];
            for (;;) {
                ssize_t n = ::recv(client, buf, sizeof(buf), 0);
                if (n <= 0) break;
                ::send(client, buf, static_cast<std::size_t>(n), 0);
            }
            ::close(client);
        }
    }

    int               listen_fd_ = -1;
    std::uint16_t     port_ = 0;
    std::atomic<bool> stop_{false};
    std::thread       thread_;
};

int connect_to(std::uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

} // namespace

TEST_CASE("open_direct opens a working direct-tcpip channel", "[integration][forwarding]") {
    Session session = make_connected_session();
    EchoServer echo;

    auto channel_result = open_direct(session, TcpEndpoint{"127.0.0.1", echo.port()});
    REQUIRE(channel_result.has_value());

    const std::string msg = "hello-direct";
    REQUIRE(channel_result->try_write_all(std::string_view(msg)).has_value());

    std::array<std::byte, 64> buf{};
    auto read_result = channel_result->try_read_some(MutableByteView(buf.data(), buf.size()),
                                                     Stream::stdout_, std::chrono::milliseconds(2000));
    REQUIRE(read_result.has_value());
    CHECK(std::string(reinterpret_cast<const char*>(buf.data()), *read_result) == msg);
}

TEST_CASE("LocalForward (-L) round trip against a real sshd", "[integration][forwarding]") {
    Session session = make_connected_session();
    EchoServer echo;

    LocalForward::Options opts;
    opts.listen = {"127.0.0.1", 0};
    opts.target = TcpEndpoint{"127.0.0.1", echo.port()};
    LocalForward fwd(session, opts);
    REQUIRE(fwd.try_start().has_value());

    auto local = fwd.local_endpoint();
    REQUIRE(local.port != 0);

    int client = connect_to(local.port);
    REQUIRE(client >= 0);
    const std::string msg = "hello-local-forward";
    ::send(client, msg.data(), msg.size(), 0);
    char buf[128] = {};
    ssize_t n = ::recv(client, buf, sizeof(buf) - 1, 0);
    REQUIRE(n > 0);
    CHECK(std::string(buf, static_cast<std::size_t>(n)) == msg);
    ::close(client);

    auto stats = fwd.stats();
    CHECK(stats.connections == 1);
    fwd.stop();
}

TEST_CASE("RemoteForward (-R) round trip against a real sshd", "[integration][forwarding]") {
    Session session = make_connected_session();
    EchoServer echo;

    RemoteForward::Options opts;
    opts.bind_address = "127.0.0.1";
    opts.remote_port = 0;
    opts.local_target = TcpEndpoint{"127.0.0.1", echo.port()};
    RemoteForward fwd(session, opts);
    REQUIRE(fwd.try_start().has_value());

    auto remote_port = fwd.remote_port();
    REQUIRE(remote_port != 0);

    int client = connect_to(remote_port);
    REQUIRE(client >= 0);
    const std::string msg = "hello-remote-forward";
    ::send(client, msg.data(), msg.size(), 0);
    char buf[128] = {};
    ssize_t n = ::recv(client, buf, sizeof(buf) - 1, 0);
    REQUIRE(n > 0);
    CHECK(std::string(buf, static_cast<std::size_t>(n)) == msg);
    ::close(client);

    fwd.stop();
}
