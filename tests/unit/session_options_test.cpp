#include <catch2/catch_test_macros.hpp>
#include <sshpp/session_options.hpp>

using namespace sshpp;

TEST_CASE("SessionOptions::parse_target plain host", "[session_options]") {
    auto r = SessionOptions::parse_target("example.com");
    REQUIRE(r.has_value());
    CHECK(r->host == "example.com");
    CHECK_FALSE(r->user.has_value());
    CHECK_FALSE(r->port.has_value());
}

TEST_CASE("SessionOptions::parse_target user@host:port", "[session_options]") {
    auto r = SessionOptions::parse_target("deploy@example.com:2222");
    REQUIRE(r.has_value());
    CHECK(r->host == "example.com");
    CHECK(r->user.value() == "deploy");
    CHECK(r->port.value() == 2222);
}

TEST_CASE("SessionOptions::parse_target bracketed IPv6", "[session_options]") {
    auto r = SessionOptions::parse_target("user@[::1]:2222");
    REQUIRE(r.has_value());
    CHECK(r->host == "::1");
    CHECK(r->user.value() == "user");
    CHECK(r->port.value() == 2222);
}

TEST_CASE("SessionOptions::validate rejects empty host", "[session_options]") {
    SessionOptions opts;
    auto r = opts.validate();
    CHECK_FALSE(r.has_value());
}
