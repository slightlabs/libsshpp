// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Callback-style server API (event-driven, required for anything serving many
// channels/clients). See docs/design/08 §8.6-§8.7.
//
// Scope note relative to the design doc: keyboard-interactive auth and
// tcpip-forward/direct-tcpip channel handling are not wired here because the
// installed libssh's ssh_server_callbacks_struct has no callback slots for
// them (message-style server::Session::try_next_message() still covers those
// via SSH_REQUEST_AUTH/keyboard-interactive and SSH_CHANNEL_DIRECT_TCPIP).
// on_x11_request takes plain fields rather than a shared X11Request type so
// that the server module has no hard dependency on LIBSSHPP_WITH_FORWARDING.
#pragma once

#include <sshpp/config.hpp>

#include <sshpp/channel.hpp>
#include <sshpp/error.hpp>
#include <sshpp/export.hpp>
#include <sshpp/key.hpp>
#include <sshpp/server/message.hpp>
#include <sshpp/server/server_session.hpp>
#include <sshpp/types.hpp>

#include <cstdint>
#include <functional>
#include <istream>
#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace sshpp::server {

enum class AuthResult { success, denied, partial };

/// Per-session authentication/channel-open policy. All auth hooks default to
/// `denied`; override only what you need. See docs/design/08 §8.6.
class SSHPP_API SessionHandler {
public:
    virtual ~SessionHandler() = default;

    virtual AuthResult on_auth_none(Session&, std::string_view user);
    virtual AuthResult on_auth_password(Session&, std::string_view user, const SecureString& password);
    /// state == none  -> client is *offering* a key; return success to say "acceptable"
    /// state == valid -> signature verified; return success to authenticate
    virtual AuthResult on_auth_public_key(Session&, std::string_view user, const Key&, PublicKeyState state);
    virtual AuthResult on_auth_gssapi_mic(Session&, std::string_view user, std::string_view principal);

    /// Return nullptr to refuse the channel.
    virtual std::shared_ptr<class ChannelHandler> on_channel_open_session(Session&);

    virtual void on_service_request(Session&, std::string_view service);
    virtual void on_disconnect(Session&);
    virtual void on_error(Session&, const ErrorInfo&);
};

/// Per-channel request/data handling. See docs/design/08 §8.6.
class SSHPP_API ChannelHandler {
public:
    virtual ~ChannelHandler() = default;

    virtual bool on_pty_request(Channel&, std::string_view term, PtySize);
    virtual bool on_pty_resize(Channel&, PtySize);
    virtual bool on_shell_request(Channel&);
    virtual bool on_exec_request(Channel&, std::string_view command);
    virtual bool on_subsystem_request(Channel&, std::string_view name);
    virtual bool on_env_request(Channel&, std::string_view name, std::string_view value);
    virtual void on_x11_request(Channel&, bool single_connection, std::string_view auth_protocol,
                                std::string_view auth_cookie, std::uint32_t screen_number);
    virtual void on_signal(Channel&, std::string_view signal_name);

    /// Return the number of bytes consumed (libssh re-delivers the remainder).
    virtual std::size_t on_data(Channel&, ByteView, Stream);
    virtual void on_eof(Channel&);
    virtual void on_close(Channel&);
    /// Called when the channel's send window opens up again.
    virtual void on_writable(Channel&);
};

/// Authenticates against an in-memory table. For tests, appliances, and quick
/// starts. Passwords are compared in constant time; never logged (SecureString).
class SSHPP_API SimpleAuthHandler : public SessionHandler {
public:
    void allow_password(std::string user, SecureString password);
    void allow_public_key(std::string user, Key public_key);
    void allow_none(std::string user);   // testing only
    void set_max_attempts(int n) noexcept { max_attempts_ = n; }

    AuthResult on_auth_none(Session&, std::string_view user) override;
    AuthResult on_auth_password(Session&, std::string_view user, const SecureString&) override;
    AuthResult on_auth_public_key(Session&, std::string_view user, const Key&, PublicKeyState) override;

private:
    struct Entry {
        std::optional<SecureString> password;
        std::vector<Fingerprint>     public_key_fingerprints;
        bool                          allow_none = false;
    };
    Entry* find(std::string_view user);
    bool   record_attempt_and_check(std::string_view user);

    std::unordered_map<std::string, Entry>          entries_;
    std::unordered_map<std::string, int>            attempts_;
    int                                               max_attempts_ = 6;
};

/// Runs a fixed callback per exec request; no local process is spawned.
class SSHPP_API CommandHandler : public ChannelHandler {
public:
    using Runner = std::function<int(std::string_view command, std::istream& in, std::ostream& out,
                                     std::ostream& err)>;
    explicit CommandHandler(Runner runner) : runner_(std::move(runner)) {}

    bool on_exec_request(Channel&, std::string_view command) override;
    std::size_t on_data(Channel&, ByteView, Stream) override;
    void on_eof(Channel&) override;

private:
    Runner       runner_;
    std::string  command_;
    std::string  input_buffer_;
    bool         eof_ = false;
    bool         ran_ = false;
};

} // namespace sshpp::server

#if SSHPP_HEADER_ONLY
#include <sshpp/detail/server_handlers.ipp>
#endif
