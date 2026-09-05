// SPDX-License-Identifier: LGPL-2.1-or-later
// Generated from src/server_test_server.cpp; see docs/design/09 §9.3.
#pragma once

#include <sshpp/server/test_server.hpp>
#include <sshpp/error.hpp>
#include <sshpp/known_hosts.hpp>
#include <sshpp/server/handlers.hpp>
#include <sshpp/server/sftp_subsystem.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <memory>

namespace sshpp::server {

namespace {

/// One ChannelHandler per session channel: runs the fixed Options::exec
/// callback for "exec" requests, or an SftpSubsystemHandler for a "sftp"
/// subsystem request if Options::sftp_root is set. Denies shell/pty/etc.
class TestServerChannelHandler : public ChannelHandler {
public:
    explicit TestServerChannelHandler(const TestServer::Options& options) : options_(&options) {}

    bool on_exec_request(Channel& channel, std::string_view command) override {
        if (!options_->exec) return false;
        command_handler_ = std::make_unique<CommandHandler>(options_->exec);
        return command_handler_->on_exec_request(channel, command);
    }

    bool on_subsystem_request(Channel& channel, std::string_view name) override {
        if (name != "sftp" || !options_->sftp_root) return false;
        SftpSubsystemHandler::Options sftp_opts;
        sftp_opts.root = *options_->sftp_root;
        sftp_handler_ = std::make_shared<SftpSubsystemHandler>(sftp_opts);
        return sftp_handler_->on_subsystem_request(channel, name);
    }

    std::size_t on_data(Channel& channel, ByteView data, Stream stream) override {
        if (command_handler_) return command_handler_->on_data(channel, data, stream);
        return data.size();
    }

    void on_eof(Channel& channel) override {
        if (command_handler_) command_handler_->on_eof(channel);
    }

private:
    const TestServer::Options*            options_;
    std::unique_ptr<CommandHandler>        command_handler_;
    std::shared_ptr<SftpSubsystemHandler> sftp_handler_;
};

class TestServerSessionHandler : public SessionHandler {
public:
    explicit TestServerSessionHandler(const TestServer::Options& options) : options_(options) {}

    AuthResult on_auth_password(Session&, std::string_view user, const SecureString& password) override {
        if (!options_.allow_password || user != options_.user) return AuthResult::denied;
        return password.view() == options_.password.view() ? AuthResult::success : AuthResult::denied;
    }

    AuthResult on_auth_public_key(Session&, std::string_view user, const Key& key, PublicKeyState state) override {
        if (!options_.allow_public_key || user != options_.user) return AuthResult::denied;
        auto presented_fp = key.fingerprint();
        if (!presented_fp) return AuthResult::denied;
        for (const auto& allowed : options_.authorized_keys) {
            auto allowed_fp = allowed.fingerprint();
            if (allowed_fp && *allowed_fp == *presented_fp) {
                (void)state;
                return AuthResult::success;
            }
        }
        return AuthResult::denied;
    }

    std::shared_ptr<ChannelHandler> on_channel_open_session(Session&) override {
        return std::make_shared<TestServerChannelHandler>(options_);
    }

private:
    const TestServer::Options& options_;
};

} // namespace

SSHPP_INLINE TestServer::TestServer(Options options) : options_(std::move(options)) {
    auto key = Key::generate(KeyType::ed25519);
    if (!key) throw_error(key.error());
    host_key_ = std::move(*key);

    known_hosts_path_ = std::filesystem::temp_directory_path() /
                       ("sshpp_test_known_hosts_" + std::to_string(::getpid()) + "_" +
                        std::to_string(reinterpret_cast<std::uintptr_t>(this)));

    BindOptions bind_opts;
    bind_opts.bind_address = "127.0.0.1";
    bind_opts.port = 0;
    // Bind's ctor ssh_key_dup()s every entry before handing it to libssh, so a
    // borrowed (non-owning) view of host_key_ is safe here; host_key_ itself
    // stays owned by this TestServer for host_key()/host_key_fingerprint().
    bind_opts.host_keys.push_back(Key::from_native(host_key_.native_handle(), Ownership::borrowed));

    bind_ = Bind(bind_opts);
    auto listened = bind_.try_listen();
    if (!listened) throw_error(listened.error());

    sockaddr_in addr{};
    socklen_t addr_len = sizeof(addr);
    if (::getsockname(bind_.fd(), reinterpret_cast<sockaddr*>(&addr), &addr_len) == 0) {
        port_ = ntohs(addr.sin_port);
    }

    (void)KnownHosts(known_hosts_path_).add("127.0.0.1", port_, host_key_);

    accept_thread_ = std::thread([this] { accept_loop(); });
}

SSHPP_INLINE TestServer::~TestServer() {
    stop_requested_.store(true);
    if (accept_thread_.joinable()) accept_thread_.join();
    for (auto& t : connection_threads_) {
        if (t.joinable()) t.join();
    }
    std::error_code ec;
    std::filesystem::remove(known_hosts_path_, ec);
}

SSHPP_INLINE void TestServer::accept_loop() {
    while (!stop_requested_.load()) {
        auto accepted = bind_.try_accept(std::chrono::milliseconds(200));
        if (!accepted || !*accepted) continue;
        connection_threads_.emplace_back([this, session = std::move(**accepted)]() mutable {
            serve_connection(std::move(session));
        });
    }
}

SSHPP_INLINE void TestServer::serve_connection(Session session) {
    AuthMethodSet methods;
    methods.password = options_.allow_password;
    methods.public_key = options_.allow_public_key;
    session.set_auth_methods(methods);

    auto handler = std::make_shared<TestServerSessionHandler>(options_);
    if (!session.try_set_handler(handler)) return;

    if (!session.try_handle_key_exchange()) return;

    while (!stop_requested_.load() && session) {
        auto polled = session.try_poll(std::chrono::milliseconds(200));
        if (!polled) break;
    }
}

SSHPP_INLINE Fingerprint TestServer::host_key_fingerprint(HashType type) const {
    auto fp = host_key_.fingerprint(type);
    return fp ? *fp : Fingerprint{};
}

SSHPP_INLINE SessionOptions TestServer::client_options() const {
    SessionOptions opts;
    opts.host = "127.0.0.1";
    opts.port = port_;
    opts.user = options_.user;
    opts.known_hosts = known_hosts_path_;
    opts.timeout = std::chrono::seconds(5);
    return opts;
}

} // namespace sshpp::server
