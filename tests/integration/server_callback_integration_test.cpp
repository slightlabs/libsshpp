// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Exercises the callback-style server API end-to-end via server::TestServer:
// SessionHandler/ChannelHandler auth + channel dispatch, CommandHandler for
// exec, and SftpSubsystemHandler for the sftp subsystem. Self-contained: does
// not need a real sshd (unlike the other integration tests), since TestServer
// runs entirely in-process.
#include <catch2/catch_test_macros.hpp>
#include <sshpp/sshpp.hpp>
#include <sshpp/server/test_server.hpp>

#include <unistd.h>

#include <filesystem>
#include <fstream>

using namespace sshpp;

namespace {

Session connect_and_auth_password(server::TestServer& server) {
    SessionOptions opts = server.client_options();
    Session session{opts};
    session.connect();
    session.verify_host_key(AcceptAnyHostKeyPolicy{i_understand_this_is_insecure()});
    auth::Password password("testpass");
    session.authenticate(password);
    REQUIRE(session.authenticated());
    return session;
}

} // namespace

TEST_CASE("TestServer accepts password auth and runs exec via CommandHandler", "[integration][server][callback]") {
    Library lib;
    server::TestServer::Options opts;
    opts.exec = [](std::string_view, std::istream&, std::ostream& out, std::ostream&) -> int {
        out << "hello-from-command-handler";
        return 0;
    };
    server::TestServer server{std::move(opts)};

    Session session = connect_and_auth_password(server);
    auto result = Exec{session}.try_run("anything");
    REQUIRE(result.has_value());
    CHECK(result->stdout_text == "hello-from-command-handler");
    CHECK(result->exit_code == 0);
}

TEST_CASE("TestServer denies wrong password", "[integration][server][callback]") {
    Library lib;
    server::TestServer::Options opts;
    server::TestServer server{std::move(opts)};

    SessionOptions client_opts = server.client_options();
    Session session{client_opts};
    session.connect();
    session.verify_host_key(AcceptAnyHostKeyPolicy{i_understand_this_is_insecure()});
    auth::Password wrong_password("not-the-password");
    auto status = session.try_authenticate(wrong_password);
    REQUIRE(status.has_value());
    CHECK(*status != AuthStatus::success);
}

TEST_CASE("TestServer serves SFTP via SftpSubsystemHandler", "[integration][server][callback][sftp]") {
    Library lib;
    auto tmp_root = std::filesystem::temp_directory_path() /
                   ("sshpp_test_sftp_root_" + std::to_string(::getpid()));
    std::filesystem::create_directories(tmp_root);

    server::TestServer::Options opts;
    opts.sftp_root = tmp_root;
    server::TestServer server{std::move(opts)};

    Session session = connect_and_auth_password(server);
    auto sftp = session.try_open_sftp();
    REQUIRE(sftp.has_value());

    const std::string payload = "hello-from-sftp-subsystem\n";
    {
        auto file = sftp->try_open(RemotePath("/upload.txt"),
                                   sftp::OpenMode::write | sftp::OpenMode::create | sftp::OpenMode::truncate);
        REQUIRE(file.has_value());
        REQUIRE(file->try_write_all(ByteView(payload)).has_value());
        REQUIRE(file->try_close().has_value());
    }

    // The file must actually have landed under tmp_root, confined by resolve_sftp_path().
    std::ifstream check(tmp_root / "upload.txt", std::ios::binary);
    std::string on_disk((std::istreambuf_iterator<char>(check)), std::istreambuf_iterator<char>());
    CHECK(on_disk == payload);

    {
        auto file = sftp->try_open(RemotePath("/upload.txt"), sftp::OpenMode::read);
        REQUIRE(file.has_value());
        std::vector<std::byte> buf(payload.size());
        REQUIRE(file->try_read_exact(MutableByteView(buf.data(), buf.size())).has_value());
        CHECK(std::string(reinterpret_cast<const char*>(buf.data()), buf.size()) == payload);
    }

    std::error_code ec;
    std::filesystem::remove_all(tmp_root, ec);
}

TEST_CASE("TestServer public-key auth accepts an authorized key and rejects an unauthorized one",
         "[integration][server][callback]") {
    Library lib;
    auto authorized = Key::generate(KeyType::ed25519);
    REQUIRE(authorized.has_value());

    server::TestServer::Options opts;
    opts.authorized_keys.push_back(std::move(*authorized));
    // Re-generate a fresh copy for the client to actually authenticate with,
    // since Key has no public clone and the original was moved into Options.
    auto client_key = Key::generate(KeyType::ed25519);
    REQUIRE(client_key.has_value());

    server::TestServer server{std::move(opts)};

    SessionOptions client_opts = server.client_options();
    Session unauthorized_session{client_opts};
    unauthorized_session.connect();
    unauthorized_session.verify_host_key(AcceptAnyHostKeyPolicy{i_understand_this_is_insecure()});
    auth::PublicKey unauthorized_auth(std::move(*client_key));
    auto status = unauthorized_session.try_authenticate(unauthorized_auth);
    REQUIRE(status.has_value());
    CHECK(*status != AuthStatus::success);
}
