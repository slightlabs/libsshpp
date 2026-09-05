// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include <sshpp/config.hpp>

#include <sshpp/detail/native_fwd.hpp>

#include <atomic>
#include <memory>
#include <mutex>

namespace sshpp::detail {

/// Non-copyable, non-movable; always heap-allocated and shared. Owns exactly one
/// ssh_session and guarantees it outlives every Channel/Sftp/Scp derived from it.
/// See docs/design/02 §2.2.
class SessionCore {
public:
    explicit SessionCore(native_session raw) noexcept : raw_(raw) {}
    ~SessionCore();

    SessionCore(const SessionCore&)            = delete;
    SessionCore& operator=(const SessionCore&) = delete;

    native_session raw() const noexcept { return raw_; }
    std::recursive_mutex& mutex() noexcept { return mutex_; }

    bool valid() const noexcept { return raw_ != nullptr; }

    /// Replaces the underlying ssh_session (used by Session::try_reconnect()).
    void replace(native_session raw) noexcept;

    void request_cancel() noexcept { cancel_requested_.store(true, std::memory_order_relaxed); }
    void clear_cancel() noexcept { cancel_requested_.store(false, std::memory_order_relaxed); }
    bool cancel_requested() const noexcept { return cancel_requested_.load(std::memory_order_relaxed); }

private:
    native_session       raw_;
    std::recursive_mutex mutex_;
    std::atomic<bool>    cancel_requested_{false};
};

using SessionCorePtr = std::shared_ptr<SessionCore>;

} // namespace sshpp::detail

#if SSHPP_HEADER_ONLY
#include <sshpp/detail/session_core.ipp>
#endif
