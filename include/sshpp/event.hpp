// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include <sshpp/config.hpp>

#include <sshpp/detail/native_fwd.hpp>
#include <sshpp/export.hpp>
#include <sshpp/fwd.hpp>
#include <sshpp/result.hpp>

#include <chrono>

namespace sshpp {

/// Poll-loop integration seam around ssh_event. See docs/design/05 §5.5.
class SSHPP_API Event {
public:
    Event();
    ~Event();
    Event(Event&&) noexcept;
    Event& operator=(Event&&) noexcept;
    Event(const Event&) = delete;

    Result<void> try_add_session(Session&);
    Result<void> try_remove_session(Session&);

#if SSHPP_HAS_CONNECTOR
    Result<void> try_add_connector(native_connector);
    Result<void> try_remove_connector(native_connector);
#endif

    /// SSH_OK / SSH_AGAIN(timeout) / SSH_ERROR.
    Result<void> try_poll(std::chrono::milliseconds timeout);

    native_event native_handle() const noexcept { return native_; }

private:
    native_event native_ = nullptr;
};

} // namespace sshpp

#if SSHPP_HEADER_ONLY
#include <sshpp/detail/event.ipp>
#endif
