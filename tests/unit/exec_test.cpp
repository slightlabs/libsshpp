#include <catch2/catch_test_macros.hpp>
#include <sshpp/exec.hpp>

using namespace sshpp;

TEST_CASE("shell_quote leaves safe tokens untouched", "[exec]") {
    CHECK(shell_quote("hello") == "hello");
    CHECK(shell_quote("/var/log/app.log") == "/var/log/app.log");
}

TEST_CASE("shell_quote escapes shell metacharacters", "[exec]") {
    CHECK(shell_quote("a b") == "'a b'");
    CHECK(shell_quote("$(rm -rf /)") == "'$(rm -rf /)'");
    CHECK(shell_quote("it's") == "'it'\\''s'");
}
