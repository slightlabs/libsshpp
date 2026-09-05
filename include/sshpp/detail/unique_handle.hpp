// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include <utility>

namespace sshpp::detail {

/// Zero-overhead move-only owner for a libssh C handle. See docs/design/02 §2.2.
template <class Handle, class Deleter>
class UniqueHandle {
public:
    UniqueHandle() = default;
    explicit UniqueHandle(Handle h) noexcept : h_(h) {}

    UniqueHandle(UniqueHandle&& o) noexcept : h_(std::exchange(o.h_, Handle{})) {}
    UniqueHandle& operator=(UniqueHandle&& o) noexcept {
        if (this != &o) {
            reset();
            h_ = std::exchange(o.h_, Handle{});
        }
        return *this;
    }

    UniqueHandle(const UniqueHandle&)            = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    ~UniqueHandle() { reset(); }

    Handle get() const noexcept { return h_; }
    explicit operator bool() const noexcept { return h_ != Handle{}; }

    [[nodiscard]] Handle release() noexcept { return std::exchange(h_, Handle{}); }

    void reset(Handle h = Handle{}) noexcept {
        if (h_ != Handle{}) {
            Deleter{}(h_);
        }
        h_ = h;
    }

private:
    Handle h_{};
};

} // namespace sshpp::detail
