#include <catch2/catch_test_macros.hpp>
#include <sshpp/server/bind.hpp>
#include <sshpp/sshpp.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <atomic>
#include <thread>

using namespace sshpp;

namespace {

/// Runs one accepted connection: authenticates "alice"/"s3cret" via password,
/// accepts a session channel, replies to the exec request with a fixed
/// stdout payload and exit status, then closes.
void serve_one_connection(server::Session& srv) {
    REQUIRE(srv.try_handle_key_exchange().has_value());
    server::AuthMethodSet methods;
    methods.password = true;
    srv.set_auth_methods(methods);

    Channel channel;
    bool have_channel = false;

    while (!srv.authenticated() || !have_channel) {
        auto msg_result = srv.try_next_message(std::chrono::milliseconds(5000));
        REQUIRE(msg_result.has_value());
        REQUIRE(msg_result->has_value());
        server::Message& msg = **msg_result;

        switch (msg.type()) {
            case server::MessageType::request_auth:
                if (msg.auth_subtype() == server::AuthSubtype::password &&
                    msg.auth_user() == "alice" && msg.auth_password().view() == "s3cret") {
                    REQUIRE(msg.try_reply_auth_success().has_value());
                } else {
                    REQUIRE(msg.try_reply_auth_failure().has_value());
                }
                break;
            case server::MessageType::channel_open:
                if (msg.channel_open_subtype() == server::ChannelOpenSubtype::session) {
                    auto ch = msg.try_accept_channel_open();
                    REQUIRE(ch.has_value());
                    channel = std::move(*ch);
                    have_channel = true;
                } else {
                    REQUIRE(msg.try_reply_default().has_value());
                }
                break;
            default:
                REQUIRE(msg.try_reply_default().has_value());
                break;
        }
    }

    // Now service channel requests on the accepted session channel until exec arrives.
    for (;;) {
        auto msg_result = srv.try_next_message(std::chrono::milliseconds(5000));
        REQUIRE(msg_result.has_value());
        REQUIRE(msg_result->has_value());
        server::Message& msg = **msg_result;
        REQUIRE(msg.type() == server::MessageType::channel_request);
        if (msg.channel_request_subtype() == server::ChannelRequestSubtype::exec) {
            REQUIRE(msg.try_reply_success().has_value());
            break;
        }
        REQUIRE(msg.try_reply_default().has_value());
    }

    REQUIRE(channel.try_write_all(std::string_view("hello-from-sshpp-server\n")).has_value());
    REQUIRE(channel.try_send_eof().has_value());
    REQUIRE(channel.try_close().has_value());
}

} // namespace

TEST_CASE("sshpp server accepts a connection from an sshpp client", "[integration][server]") {
    Library lib;

    auto host_key = Key::generate(KeyType::ed25519);
    REQUIRE(host_key.has_value());

    server::BindOptions bind_opts;
    bind_opts.bind_address = "127.0.0.1";
    bind_opts.port = 0;
    bind_opts.host_keys.push_back(std::move(*host_key));

    server::Bind bind{bind_opts};
    REQUIRE(bind.try_listen().has_value());
    // BindOptions::port == 0 requested an ephemeral port; local_port() only
    // echoes the configured value, so read the OS-assigned one back directly.
    std::uint16_t port = 0;
    {
        sockaddr_in addr{};
        socklen_t len = sizeof(addr);
        ::getsockname(bind.fd(), reinterpret_cast<sockaddr*>(&addr), &len);
        port = ntohs(addr.sin_port);
    }
    REQUIRE(port != 0);

    std::thread server_thread([&bind] {
        auto accepted = bind.try_accept();
        REQUIRE(accepted.has_value());
        serve_one_connection(*accepted);
    });

    SessionOptions opts;
    opts.host = "127.0.0.1";
    opts.port = port;
    opts.user = "alice";
    opts.timeout = std::chrono::seconds{5};

    Session client{opts};
    REQUIRE(client.try_connect().has_value());
    REQUIRE(client.try_verify_host_key(AcceptAnyHostKeyPolicy{i_understand_this_is_insecure()}).has_value());

    auth::Password password("s3cret");
    auto auth_result = client.try_authenticate(password);
    REQUIRE(auth_result.has_value());
    REQUIRE(*auth_result == AuthStatus::success);

    auto result = Exec{client}.try_run("anything");
    REQUIRE(result.has_value());
    CHECK(result->stdout_text == "hello-from-sshpp-server\n");

    server_thread.join();
}
