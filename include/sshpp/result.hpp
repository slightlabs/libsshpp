// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include <sshpp/error.hpp>

#include <optional>
#include <type_traits>
#include <utility>

namespace sshpp {

/// C++17 backport of the subset of std::expected<T, ErrorInfo> this library commits to.
/// Uses std::optional<T> for storage so T need not be default-constructible.
/// See docs/design/03 §3.5.
template <class T>
class [[nodiscard]] Result {
public:
    using value_type = T;
    using error_type = ErrorInfo;

    Result(T value) : value_(std::move(value)) {}
    Result(ErrorInfo error) : error_(std::move(error)) {}

    Result(const Result&)            = default;
    Result(Result&&) noexcept        = default;
    Result& operator=(const Result&) = default;
    Result& operator=(Result&&) noexcept = default;
    ~Result() = default;

    [[nodiscard]] bool has_value() const noexcept { return value_.has_value(); }
    explicit operator bool() const noexcept { return value_.has_value(); }

    T& value() & {
        if (!value_) throw_error(error_);
        return *value_;
    }
    const T& value() const& {
        if (!value_) throw_error(error_);
        return *value_;
    }
    T&& value() && {
        if (!value_) throw_error(error_);
        return std::move(*value_);
    }

    template <class U>
    T value_or(U&& fallback) const& {
        return value_ ? *value_ : static_cast<T>(std::forward<U>(fallback));
    }

    T*       operator->() noexcept { return &*value_; }
    const T* operator->() const noexcept { return &*value_; }
    T&       operator*() & noexcept { return *value_; }
    const T& operator*() const& noexcept { return *value_; }

    const ErrorInfo& error() const& noexcept { return error_; }
    std::error_code  code() const noexcept { return value_ ? std::error_code{} : error_.code; }

    void throw_if_error() const {
        if (!value_) throw_error(error_);
    }

    template <class F>
    auto and_then(F&& f) && {
        using R = std::invoke_result_t<F, T&&>;
        if (value_) return std::forward<F>(f)(std::move(*value_));
        return R(error_);
    }

    template <class F>
    auto transform(F&& f) && {
        using U = std::invoke_result_t<F, T&&>;
        if (value_) return Result<U>(std::forward<F>(f)(std::move(*value_)));
        return Result<U>(error_);
    }

    template <class F>
    Result or_else(F&& f) && {
        if (value_) return std::move(*this);
        return std::forward<F>(f)(error_);
    }

private:
    std::optional<T> value_;
    ErrorInfo         error_{};
};

template <>
class [[nodiscard]] Result<void> {
public:
    using value_type = void;
    using error_type = ErrorInfo;

    Result() : has_value_(true) {}
    Result(ErrorInfo error) : has_value_(false), error_(std::move(error)) {}

    [[nodiscard]] bool has_value() const noexcept { return has_value_; }
    explicit operator bool() const noexcept { return has_value_; }

    void value() const {
        if (!has_value_) throw_error(error_);
    }

    const ErrorInfo& error() const& noexcept { return error_; }
    std::error_code  code() const noexcept { return has_value_ ? std::error_code{} : error_.code; }

    void throw_if_error() const {
        if (!has_value_) throw_error(error_);
    }

    template <class F>
    auto and_then(F&& f) && {
        using R = std::invoke_result_t<F>;
        if (has_value_) return std::forward<F>(f)();
        return R(error_);
    }

private:
    bool      has_value_;
    ErrorInfo error_{};
};

} // namespace sshpp
