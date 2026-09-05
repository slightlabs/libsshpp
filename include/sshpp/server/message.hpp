// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Message-style server API. See docs/design/08-api-server.md.
// Scope note: this implements the message-pull style only (§8.5); the
// event-driven callback style (§8.6, SessionHandler/ChannelHandler) and the
// ready-made SimpleAuthHandler / SftpSubsystemHandler are not implemented yet.
#pragma once

#include <sshpp/channel.hpp>
#include <sshpp/detail/native_fwd.hpp>
#include <sshpp/export.hpp>
#include <sshpp/key.hpp>
#include <sshpp/result.hpp>
#include <sshpp/types.hpp>

#include <string_view>
#include <utility>

namespace sshpp::server {

class Session;

enum class MessageType { request_auth, request_service, channel_open, channel_request, unknown };
enum class AuthSubtype { none, password, public_key, keyboard_interactive, unknown };
enum class ChannelOpenSubtype { session, direct_tcpip, unknown };
enum class ChannelRequestSubtype { pty, exec, shell, env, subsystem, window_change, x11, unknown };
enum class PublicKeyState { none, valid, wrong };

/// One pulled protocol message (ssh_message_get()). Exactly one reply must be
/// sent per message; the destructor sends a default (deny) reply if the
/// caller forgot, so a missing reply becomes a clear failure rather than a
/// hung client. See docs/design/08 §8.5.
class SSHPP_API Message {
public:
    Message() = default;
    ~Message();
    Message(Message&&) noexcept;
    Message& operator=(Message&&) noexcept;
    Message(const Message&) = delete;

    explicit operator bool() const noexcept { return native_ != nullptr; }

    MessageType            type() const noexcept;
    AuthSubtype             auth_subtype() const noexcept;
    ChannelOpenSubtype      channel_open_subtype() const noexcept;
    ChannelRequestSubtype   channel_request_subtype() const noexcept;

    // ---- auth accessors ---------------------------------------------------
    std::string_view auth_user() const noexcept;
    SecureString     auth_password() const;
    PublicKeyState   auth_public_key_state() const noexcept;
    /// The offered/verified key. Borrowed: valid only for this message's lifetime.
    Key              auth_public_key() const;

    Result<void> try_reply_auth_success();
    Result<void> try_reply_auth_failure(bool partial = false);
    /// Tells the client its offered key is acceptable; signature not yet required.
    Result<void> try_reply_auth_pk_ok();
    Result<void> try_reply_default();

    // ---- channel open ---------------------------------------------------------
    /// Accepts the channel-open request and returns the resulting Channel.
    Result<Channel> try_accept_channel_open();

    // ---- channel request ---------------------------------------------------------
    std::string_view exec_command()   const noexcept;
    std::string_view subsystem_name() const noexcept;
    std::pair<std::string_view, std::string_view> env_pair() const noexcept;

    Result<void> try_reply_success();
    Result<void> try_reply_failure();

private:
    friend class Session;
    Message(native_message n, Session& session) noexcept : native_(n), session_(&session) {}

    native_message native_ = nullptr;
    Session*        session_ = nullptr;
    bool            replied_ = false;
};

} // namespace sshpp::server
