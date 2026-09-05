#include <catch2/catch_test_macros.hpp>
#include <sshpp/error.hpp>

using namespace sshpp;

TEST_CASE("errc maps to ssh_category with sensible messages", "[error]") {
    std::error_code ec = make_error_code(errc::timed_out);
    CHECK(ec.category() == ssh_category());
    CHECK(ec == std::errc::timed_out);
    CHECK_FALSE(ec.message().empty());
}

TEST_CASE("sftp_errc maps to sftp_category", "[error]") {
    std::error_code ec = make_error_code(sftp_errc::no_such_file);
    CHECK(ec.category() == sftp_category());
    CHECK(ec == std::errc::no_such_file_or_directory);
}

TEST_CASE("ErrorInfo::to_string includes operation and message", "[error]") {
    ErrorInfo info;
    info.code = make_error_code(errc::auth_denied);
    info.operation = "ssh_userauth_password";
    info.message = "Access denied";
    auto s = info.to_string();
    CHECK(s.find("ssh_userauth_password") != std::string::npos);
    CHECK(s.find("Access denied") != std::string::npos);
}

TEST_CASE("throw_error dispatches to the correct exception subclass", "[error]") {
    ErrorInfo info;
    info.code = make_error_code(errc::timed_out);
    CHECK_THROWS_AS(throw_error(info), TimeoutError);

    info.code = make_error_code(errc::host_key_changed);
    CHECK_THROWS_AS(throw_error(info), HostKeyError);

    info.code = make_error_code(errc::auth_denied);
    CHECK_THROWS_AS(throw_error(info), AuthError);

    info.code = make_error_code(sftp_errc::no_such_file);
    CHECK_THROWS_AS(throw_error(info), SftpError);
}
