// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Several ssh_message_auth_*/pty accessors are marked deprecated upstream in
// favour of the callback API; the message-pull style still needs them.
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

#include <sshpp/server/message.hpp>
#include <sshpp/server/server_session.hpp>
#include <sshpp/detail/invoke.hpp>

#include <libssh/libssh.h>
#include <libssh/server.h>

namespace sshpp::server {

namespace {

AuthSubtype auth_subtype_from_native(int subtype) {
    switch (subtype) {
        case SSH_AUTH_METHOD_NONE: return AuthSubtype::none;
        case SSH_AUTH_METHOD_PASSWORD: return AuthSubtype::password;
        case SSH_AUTH_METHOD_PUBLICKEY: return AuthSubtype::public_key;
        case SSH_AUTH_METHOD_INTERACTIVE: return AuthSubtype::keyboard_interactive;
        default: return AuthSubtype::unknown;
    }
}

ChannelOpenSubtype channel_open_subtype_from_native(int subtype) {
    switch (subtype) {
        case SSH_CHANNEL_SESSION: return ChannelOpenSubtype::session;
        case SSH_CHANNEL_DIRECT_TCPIP: return ChannelOpenSubtype::direct_tcpip;
        default: return ChannelOpenSubtype::unknown;
    }
}

ChannelRequestSubtype channel_request_subtype_from_native(int subtype) {
    switch (subtype) {
        case SSH_CHANNEL_REQUEST_PTY: return ChannelRequestSubtype::pty;
        case SSH_CHANNEL_REQUEST_EXEC: return ChannelRequestSubtype::exec;
        case SSH_CHANNEL_REQUEST_SHELL: return ChannelRequestSubtype::shell;
        case SSH_CHANNEL_REQUEST_ENV: return ChannelRequestSubtype::env;
        case SSH_CHANNEL_REQUEST_SUBSYSTEM: return ChannelRequestSubtype::subsystem;
        case SSH_CHANNEL_REQUEST_WINDOW_CHANGE: return ChannelRequestSubtype::window_change;
        case SSH_CHANNEL_REQUEST_X11: return ChannelRequestSubtype::x11;
        default: return ChannelRequestSubtype::unknown;
    }
}

} // namespace

Message::~Message() {
    if (native_ != nullptr) {
        if (!replied_) ssh_message_reply_default(native_);
        ssh_message_free(native_);
    }
}

Message::Message(Message&& other) noexcept
    : native_(std::exchange(other.native_, nullptr)), session_(other.session_),
      replied_(std::exchange(other.replied_, true)) {}

Message& Message::operator=(Message&& other) noexcept {
    if (this != &other) {
        if (native_ != nullptr) {
            if (!replied_) ssh_message_reply_default(native_);
            ssh_message_free(native_);
        }
        native_ = std::exchange(other.native_, nullptr);
        session_ = other.session_;
        replied_ = std::exchange(other.replied_, true);
    }
    return *this;
}

MessageType Message::type() const noexcept {
    if (native_ == nullptr) return MessageType::unknown;
    switch (ssh_message_type(native_)) {
        case SSH_REQUEST_AUTH: return MessageType::request_auth;
        case SSH_REQUEST_SERVICE: return MessageType::request_service;
        case SSH_REQUEST_CHANNEL_OPEN: return MessageType::channel_open;
        case SSH_REQUEST_CHANNEL: return MessageType::channel_request;
        default: return MessageType::unknown;
    }
}

AuthSubtype Message::auth_subtype() const noexcept {
    return native_ != nullptr ? auth_subtype_from_native(ssh_message_subtype(native_)) : AuthSubtype::unknown;
}

ChannelOpenSubtype Message::channel_open_subtype() const noexcept {
    return native_ != nullptr ? channel_open_subtype_from_native(ssh_message_subtype(native_))
                              : ChannelOpenSubtype::unknown;
}

ChannelRequestSubtype Message::channel_request_subtype() const noexcept {
    return native_ != nullptr ? channel_request_subtype_from_native(ssh_message_subtype(native_))
                              : ChannelRequestSubtype::unknown;
}

std::string_view Message::auth_user() const noexcept {
    if (native_ == nullptr) return {};
    const char* u = ssh_message_auth_user(native_);
    return u ? std::string_view(u) : std::string_view{};
}

SecureString Message::auth_password() const {
    if (native_ == nullptr) return {};
    const char* p = ssh_message_auth_password(native_);
    return SecureString(p ? std::string_view(p) : std::string_view{});
}

PublicKeyState Message::auth_public_key_state() const noexcept {
    if (native_ == nullptr) return PublicKeyState::none;
    switch (ssh_message_auth_publickey_state(native_)) {
        case SSH_PUBLICKEY_STATE_VALID: return PublicKeyState::valid;
        case SSH_PUBLICKEY_STATE_WRONG: return PublicKeyState::wrong;
        case SSH_PUBLICKEY_STATE_NONE:
        default: return PublicKeyState::none;
    }
}

Key Message::auth_public_key() const {
    if (native_ == nullptr) return Key{};
    ssh_key k = ssh_message_auth_pubkey(native_);
    return k != nullptr ? Key::from_native(k, Ownership::borrowed) : Key{};
}

Result<void> Message::try_reply_auth_success() {
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

Result<void> Message::try_reply_auth_failure(bool partial) {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Message::try_reply_auth_failure"};
    // libssh's "failure" reply for auth is the default deny reply; `partial`
    // is expressed by the server calling set_auth_methods() beforehand.
    (void)partial;
    int rc = ssh_message_reply_default(native_);
    replied_ = true;
    if (rc != SSH_OK) return ErrorInfo{make_error_code(errc::fatal), "", "ssh_message_reply_default"};
    return {};
}

Result<void> Message::try_reply_auth_pk_ok() {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Message::try_reply_auth_pk_ok"};
    int rc = ssh_message_auth_reply_pk_ok_simple(native_);
    replied_ = true;
    if (rc != SSH_OK) return ErrorInfo{make_error_code(errc::fatal), "", "ssh_message_auth_reply_pk_ok_simple"};
    return {};
}

Result<void> Message::try_reply_default() {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Message::try_reply_default"};
    int rc = ssh_message_reply_default(native_);
    replied_ = true;
    if (rc != SSH_OK) return ErrorInfo{make_error_code(errc::fatal), "", "ssh_message_reply_default"};
    return {};
}

Result<Channel> Message::try_accept_channel_open() {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Message::try_accept_channel_open"};
    ssh_channel raw = ssh_message_channel_request_open_reply_accept(native_);
    replied_ = true;
    if (raw == nullptr) {
        return ErrorInfo{make_error_code(errc::channel_open_failed), "", "ssh_message_channel_request_open_reply_accept"};
    }
    detail::SessionCorePtr core = session_ != nullptr ? session_->core_ : nullptr;
    return Channel::from_native(raw, std::move(core), Ownership::owning);
}

std::string_view Message::exec_command() const noexcept {
    if (native_ == nullptr) return {};
    const char* c = ssh_message_channel_request_command(native_);
    return c ? std::string_view(c) : std::string_view{};
}

std::string_view Message::subsystem_name() const noexcept {
    if (native_ == nullptr) return {};
    const char* s = ssh_message_channel_request_subsystem(native_);
    return s ? std::string_view(s) : std::string_view{};
}

std::pair<std::string_view, std::string_view> Message::env_pair() const noexcept {
    if (native_ == nullptr) return {};
    const char* name = ssh_message_channel_request_env_name(native_);
    const char* value = ssh_message_channel_request_env_value(native_);
    return {name ? std::string_view(name) : std::string_view{}, value ? std::string_view(value) : std::string_view{}};
}

Result<void> Message::try_reply_success() {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Message::try_reply_success"};
    int rc = ssh_message_channel_request_reply_success(native_);
    replied_ = true;
    if (rc != SSH_OK) return ErrorInfo{make_error_code(errc::channel_request_failed), "", "ssh_message_channel_request_reply_success"};
    return {};
}

Result<void> Message::try_reply_failure() {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Message::try_reply_failure"};
    int rc = ssh_message_reply_default(native_);
    replied_ = true;
    if (rc != SSH_OK) return ErrorInfo{make_error_code(errc::channel_request_failed), "", "ssh_message_reply_default"};
    return {};
}

} // namespace sshpp::server
