// SPDX-License-Identifier: LGPL-2.1-or-later
#include <sshpp/server/server_session.hpp>
#include <sshpp/detail/invoke.hpp>

#include <libssh/libssh.h>
#include <libssh/server.h>

#include <poll.h>

namespace sshpp::server {

int AuthMethodSet::to_bits() const noexcept {
    int bits = 0;
    if (none) bits |= SSH_AUTH_METHOD_NONE;
    if (password) bits |= SSH_AUTH_METHOD_PASSWORD;
    if (public_key) bits |= SSH_AUTH_METHOD_PUBLICKEY;
    if (host_based) bits |= SSH_AUTH_METHOD_HOSTBASED;
    if (interactive) bits |= SSH_AUTH_METHOD_INTERACTIVE;
    if (gssapi_mic) bits |= SSH_AUTH_METHOD_GSSAPI_MIC;
    return bits;
}

Session::~Session() = default;
Session::Session(Session&&) noexcept = default;
Session& Session::operator=(Session&&) noexcept = default;

Result<void> Session::try_handle_key_exchange() {
    if (!core_) return ErrorInfo{make_error_code(errc::invalid_handle), "", "server::Session::try_handle_key_exchange"};
    if (ssh_handle_key_exchange(core_->raw()) != SSH_OK) {
        return detail::make_error_info(core_->raw(), "ssh_handle_key_exchange", SSHPP_HERE, errc::key_exchange_failed);
    }
    return {};
}

void Session::set_auth_methods(AuthMethodSet methods) {
    if (core_) ssh_set_auth_methods(core_->raw(), methods.to_bits());
}

Result<void> Session::try_disconnect(std::string_view /*reason*/) {
    if (!core_) return ErrorInfo{make_error_code(errc::invalid_handle), "", "server::Session::try_disconnect"};
    ssh_disconnect(core_->raw());
    return {};
}

Result<std::string> Session::try_client_banner() const {
    if (!core_) return ErrorInfo{make_error_code(errc::invalid_handle), "", "server::Session::try_client_banner"};
    const char* banner = ssh_get_clientbanner(core_->raw());
    return std::string(banner ? banner : "");
}

Result<std::optional<Message>> Session::try_next_message(std::chrono::milliseconds timeout) {
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

} // namespace sshpp::server
