// SPDX-License-Identifier: LGPL-2.1-or-later
#include <sshpp/event.hpp>
#include <sshpp/detail/invoke.hpp>
#include <sshpp/session.hpp>

#include <libssh/libssh.h>

namespace sshpp {

Event::Event() : native_(ssh_event_new()) {}

Event::~Event() {
    if (native_ != nullptr) ssh_event_free(native_);
}

Event::Event(Event&& other) noexcept : native_(std::exchange(other.native_, nullptr)) {}

Event& Event::operator=(Event&& other) noexcept {
    if (this != &other) {
        if (native_ != nullptr) ssh_event_free(native_);
        native_ = std::exchange(other.native_, nullptr);
    }
    return *this;
}

Result<void> Event::try_add_session(Session& session) {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Event::try_add_session"};
    int rc = ssh_event_add_session(native_, session.native_handle());
    if (rc != SSH_OK) {
        return ErrorInfo{make_error_code(errc::unknown), "", "ssh_event_add_session"};
    }
    return {};
}

Result<void> Event::try_remove_session(Session& session) {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Event::try_remove_session"};
    ssh_event_remove_session(native_, session.native_handle());
    return {};
}

Result<void> Event::try_poll(std::chrono::milliseconds timeout) {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Event::try_poll"};
    int rc = ssh_event_dopoll(native_, static_cast<int>(timeout.count()));
    if (rc == SSH_ERROR) {
        return ErrorInfo{make_error_code(errc::unknown), "", "ssh_event_dopoll"};
    }
    return {};
}

} // namespace sshpp
