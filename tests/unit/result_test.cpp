#include <catch2/catch_test_macros.hpp>
#include <sshpp/result.hpp>

using namespace sshpp;

namespace {
ErrorInfo make_test_error() {
    ErrorInfo info;
    info.code = make_error_code(errc::invalid_argument);
    info.operation = "test";
    return info;
}
} // namespace

TEST_CASE("Result<T> success path", "[result]") {
    Result<int> r(42);
    REQUIRE(r.has_value());
    CHECK(*r == 42);
    CHECK(r.value() == 42);
    CHECK(r.code() == std::error_code{});
}

TEST_CASE("Result<T> error path", "[result]") {
    Result<int> r(make_test_error());
    REQUIRE_FALSE(r.has_value());
    CHECK(r.code() == make_error_code(errc::invalid_argument));
    CHECK_THROWS_AS(r.value(), UsageError);
}

TEST_CASE("Result<T>::value_or", "[result]") {
    Result<int> ok(1);
    Result<int> err(make_test_error());
    CHECK(ok.value_or(99) == 1);
    CHECK(err.value_or(99) == 99);
}

TEST_CASE("Result<void>", "[result]") {
    Result<void> ok;
    CHECK(ok.has_value());
    Result<void> err(make_test_error());
    CHECK_FALSE(err.has_value());
    CHECK_THROWS(err.throw_if_error());
}

TEST_CASE("Result<T>::transform", "[result]") {
    Result<int> r(2);
    auto doubled = std::move(r).transform([](int v) { return v * 2; });
    REQUIRE(doubled.has_value());
    CHECK(*doubled == 4);
}
