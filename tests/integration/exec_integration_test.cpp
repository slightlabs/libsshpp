#include <catch2/catch_test_macros.hpp>
#include <sshpp/sshpp.hpp>

#include <cstdlib>
#include <string>

using namespace sshpp;

namespace {

std::string env(const char* name) {
    const char* v = std::getenv(name);
    if (v == nullptr) {
        FAIL("missing required environment variable " << name);
    }
    return v;
}

} // namespace

TEST_CASE("full client flow against a real sshd", "[integration]") {
    Library lib;

    SessionOptions opts;
    opts.host = env("SSHPP_TEST_HOST");
    opts.port = static_cast<std::uint16_t>(std::stoi(env("SSHPP_TEST_PORT")));
    opts.user = env("SSHPP_TEST_USER");
    opts.identities.push_back(env("SSHPP_TEST_KEY"));
    opts.known_hosts = env("SSHPP_TEST_KNOWN_HOSTS");
    opts.timeout = std::chrono::seconds{5};

    Session session{opts};
    REQUIRE(session.try_connect().has_value());

    auto verify_result = session.try_verify_host_key(TofuHostKeyPolicy{});
    if (!verify_result) {
        UNSCOPED_INFO("verify_host_key error: " << verify_result.error().to_string());
    }
    REQUIRE(verify_result.has_value());

    auth::PublicKeyAuto authenticator;
    auto auth_result = session.try_authenticate(authenticator);
    REQUIRE(auth_result.has_value());
    REQUIRE(*auth_result == AuthStatus::success);
    REQUIRE(session.authenticated());

    auto exec_result = Exec{session}.try_run("echo hello-from-sshpp");
    REQUIRE(exec_result.has_value());
    CHECK(exec_result->exit_code == 0);
    CHECK(exec_result->stdout_text == "hello-from-sshpp\n");
}
