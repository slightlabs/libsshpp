// SPDX-License-Identifier: LGPL-2.1-or-later
// Generated from src/server_session.cpp; see docs/design/09 §9.3.
#include <sshpp/config.hpp>
// SPDX-License-Identifier: LGPL-2.1-or-later
#include <sshpp/server/server_session.hpp>
#include <sshpp/detail/invoke.hpp>

#include <libssh/libssh.h>
#include <libssh/server.h>

#include <poll.h>

namespace sshpp::server {

SSHPP_INLINE int AuthMethodSet::to_bits() const noexcept {
    int bits = 0;
    if (none) bits |= SSH_AUTH_METHOD_NONE;
    if (password) bits |= SSH_AUTH_METHOD_PASSWORD;
    if (public_key) bits |= SSH_AUTH_METHOD_PUBLICKEY;
    if (host_based) bits |= SSH_AUTH_METHOD_HOSTBASED;
    if (interactive) bits |= SSH_AUTH_METHOD_INTERACTIVE;
    if (gssapi_mic) bits |= SSH_AUTH_METHOD_GSSAPI_MIC;
    return bits;
}

SSHPP_INLINE Session::~Session() = default;
SSHPP_INLINE Session::Session(Session&&) noexcept = default;
SSHPP_INLINE Session& Session::operator=(Session&&) noexcept = default;

SSHPP_INLINE Result<void> Session::try_handle_key_exchange() {
    if (!core_) return ErrorInfo{make_error_code(errc::invalid_handle), "", "server::Session::try_handle_key_exchange"};
    if (ssh_handle_key_exchange(core_->raw()) != SSH_OK) {
        return detail::make_error_info(core_->raw(), "ssh_handle_key_exchange", SSHPP_HERE, errc::key_exchange_failed);
    }
    return {};
}

SSHPP_INLINE void Session::set_auth_methods(AuthMethodSet methods) {
    if (core_) ssh_set_auth_methods(core_->raw(), methods.to_bits());
}

SSHPP_INLINE Result<void> Session::try_disconnect(std::string_view /*reason*/) {
    if (!core_) return ErrorInfo{make_error_code(errc::invalid_handle), "", "server::Session::try_disconnect"};
    ssh_disconnect(core_->raw());
    return {};
}

SSHPP_INLINE Result<std::string> Session::try_client_banner() const {
    if (!core_) return ErrorInfo{make_error_code(errc::invalid_handle), "", "server::Session::try_client_banner"};
    const char* banner = ssh_get_clientbanner(core_->raw());
    return std::string(banner ? banner : "");
}

SSHPP_INLINE Result<std::optional<Message>> Session::try_next_message(std::chrono::milliseconds timeout) {
    if (!core_) return ErrorInfo{make_error_code(errc::invalid_handle), "", "server::Session::try_next_message"};
    if (timeout.count() >= 0) {
        pollfd pfd{static_cast<int>(ssh_get_fd(core_->raw())), POLLIN, 0};
        if (::poll(&pfd, 1, static_cast<int>(timeout.count())) <= 0) {
            return std::optional<Message>{};
        }
    }
    ssh_message raw = ssh_message_get(core_->raw());
    if (raw == nullptr) {
        return std::optional<Message>{};
    }
    return std::optional<Message>{Message(raw, *this)};
}

// Defined here rather than in server_message.ipp: these need server::Session's
// complete type, and message.hpp is included from server_session.hpp *before*
// class Session, so a dependency in the other direction would create an
// unresolvable header-only include cycle. See docs/design/09 §9.3.
SSHPP_INLINE Result<void> Message::try_reply_auth_success() {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Message::try_reply_auth_success"};
    int rc = ssh_message_auth_reply_success(native_, 0);
    replied_ = true;
    if (session_ != nullptr) {
        session_->authenticated_ = true;
        session_->user_ = std::string(auth_user());
    }
    if (rc != SSH_OK) return ErrorInfo{make_error_code(errc::auth_denied), "", "ssh_message_auth_reply_success"};
    return {};
}

SSHPP_INLINE Result<Channel> Message::try_accept_channel_open() {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Message::try_accept_channel_open"};
    ssh_channel raw = ssh_message_channel_request_open_reply_accept(native_);
    replied_ = true;
    if (raw == nullptr) {
        return ErrorInfo{make_error_code(errc::channel_open_failed), "", "ssh_message_channel_request_open_reply_accept"};
    }
    detail::SessionCorePtr core = session_ != nullptr ? session_->core_ : nullptr;
    return Channel::from_native(raw, std::move(core), Ownership::owning);
}

} // namespace sshpp::server
