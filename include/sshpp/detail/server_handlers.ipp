// SPDX-License-Identifier: LGPL-2.1-or-later
// Generated from src/server_handlers.cpp; see docs/design/09 §9.3.
//
// Defines SessionHandler/ChannelHandler's default bodies, SimpleAuthHandler,
// CommandHandler, and server::Session::try_set_handler/try_attach/try_poll.
// These need detail::HandlerBridge (and SessionHandler/ChannelHandler)
// complete; server/handlers.hpp includes server_session.hpp *before* those
// types exist, so this must live here rather than in server_session.ipp
// (same include-cycle pattern noted in docs/design/09 §9.3).
#include <sshpp/config.hpp>
#include <sshpp/detail/handler_bridge.ipp>
#include <sshpp/detail/invoke.hpp>
#include <sshpp/server/handlers.hpp>

#include <libssh/libssh.h>

#include <algorithm>
#include <memory>
#include <sstream>
#include <thread>

namespace sshpp::server {

// ------------------------------------------------------- SessionHandler ----

SSHPP_INLINE AuthResult SessionHandler::on_auth_none(Session&, std::string_view) { return AuthResult::denied; }
SSHPP_INLINE AuthResult SessionHandler::on_auth_password(Session&, std::string_view, const SecureString&) {
    return AuthResult::denied;
}
SSHPP_INLINE AuthResult SessionHandler::on_auth_public_key(Session&, std::string_view, const Key&, PublicKeyState) {
    return AuthResult::denied;
}
SSHPP_INLINE AuthResult SessionHandler::on_auth_gssapi_mic(Session&, std::string_view, std::string_view) {
    return AuthResult::denied;
}
SSHPP_INLINE std::shared_ptr<ChannelHandler> SessionHandler::on_channel_open_session(Session&) { return nullptr; }
SSHPP_INLINE void SessionHandler::on_service_request(Session&, std::string_view) {}
SSHPP_INLINE void SessionHandler::on_disconnect(Session&) {}
SSHPP_INLINE void SessionHandler::on_error(Session&, const ErrorInfo&) {}

// ------------------------------------------------------- ChannelHandler ----

SSHPP_INLINE bool ChannelHandler::on_pty_request(Channel&, std::string_view, PtySize) { return false; }
SSHPP_INLINE bool ChannelHandler::on_pty_resize(Channel&, PtySize) { return false; }
SSHPP_INLINE bool ChannelHandler::on_shell_request(Channel&) { return false; }
SSHPP_INLINE bool ChannelHandler::on_exec_request(Channel&, std::string_view) { return false; }
SSHPP_INLINE bool ChannelHandler::on_subsystem_request(Channel&, std::string_view) { return false; }
SSHPP_INLINE bool ChannelHandler::on_env_request(Channel&, std::string_view, std::string_view) { return false; }
SSHPP_INLINE void ChannelHandler::on_x11_request(Channel&, bool, std::string_view, std::string_view,
                                                 std::uint32_t) {}
SSHPP_INLINE void ChannelHandler::on_signal(Channel&, std::string_view) {}
SSHPP_INLINE std::size_t ChannelHandler::on_data(Channel&, ByteView data, Stream) { return data.size(); }
SSHPP_INLINE void ChannelHandler::on_eof(Channel&) {}
SSHPP_INLINE void ChannelHandler::on_close(Channel&) {}
SSHPP_INLINE void ChannelHandler::on_writable(Channel&) {}

// ------------------------------------------------------- SimpleAuthHandler ----

SSHPP_INLINE void SimpleAuthHandler::allow_password(std::string user, SecureString password) {
    entries_[user].password = std::move(password);
}

SSHPP_INLINE void SimpleAuthHandler::allow_public_key(std::string user, Key public_key) {
    auto fp = public_key.fingerprint();
    if (fp) entries_[user].public_key_fingerprints.push_back(std::move(*fp));
}

SSHPP_INLINE void SimpleAuthHandler::allow_none(std::string user) { entries_[user].allow_none = true; }

SSHPP_INLINE SimpleAuthHandler::Entry* SimpleAuthHandler::find(std::string_view user) {
    auto it = entries_.find(std::string(user));
    return it != entries_.end() ? &it->second : nullptr;
}

SSHPP_INLINE bool SimpleAuthHandler::record_attempt_and_check(std::string_view user) {
    std::string key(user);
    int& count = attempts_[key];
    ++count;
    return count <= max_attempts_;
}

SSHPP_INLINE AuthResult SimpleAuthHandler::on_auth_none(Session&, std::string_view user) {
    if (!record_attempt_and_check(user)) return AuthResult::denied;
    auto* e = find(user);
    return (e != nullptr && e->allow_none) ? AuthResult::success : AuthResult::denied;
}

SSHPP_INLINE AuthResult SimpleAuthHandler::on_auth_password(Session&, std::string_view user,
                                                            const SecureString& password) {
    if (!record_attempt_and_check(user)) return AuthResult::denied;
    auto* e = find(user);
    if (e == nullptr || !e->password) return AuthResult::denied;
    // Fixed-time-ish compare: always walk both buffers fully rather than
    // short-circuiting on the first mismatch (mitigates a timing side channel).
    std::string_view a = e->password->view();
    std::string_view b = password.view();
    bool equal = a.size() == b.size();
    std::size_t n = std::min(a.size(), b.size());
    unsigned char diff = 0;
    for (std::size_t i = 0; i < n; ++i) diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    equal = equal && (diff == 0);
    return equal ? AuthResult::success : AuthResult::denied;
}

SSHPP_INLINE AuthResult SimpleAuthHandler::on_auth_public_key(Session&, std::string_view user, const Key& key,
                                                              PublicKeyState state) {
    if (state == PublicKeyState::wrong) return AuthResult::denied;
    auto* e = find(user);
    if (e == nullptr || e->public_key_fingerprints.empty()) return AuthResult::denied;
    auto fp = key.fingerprint();
    if (!fp) return AuthResult::denied;
    for (const auto& allowed : e->public_key_fingerprints) {
        if (allowed == *fp) {
            if (state == PublicKeyState::valid && !record_attempt_and_check(user)) return AuthResult::denied;
            return AuthResult::success;
        }
    }
    return AuthResult::denied;
}

// ------------------------------------------------------- CommandHandler ----

SSHPP_INLINE bool CommandHandler::on_exec_request(Channel&, std::string_view command) {
    command_ = std::string(command);
    input_buffer_.clear();
    eof_ = false;
    ran_ = false;
    // The Runner only sees `command_` once stdin (if any) is fully buffered; see on_eof below.
    return static_cast<bool>(runner_);
}

SSHPP_INLINE std::size_t CommandHandler::on_data(Channel&, ByteView data, Stream) {
    input_buffer_.append(reinterpret_cast<const char*>(data.data()), data.size());
    return data.size();
}

SSHPP_INLINE void CommandHandler::on_eof(Channel& channel) {
    if (ran_) return;
    ran_ = true;
    eof_ = true;
    std::istringstream in(input_buffer_);
    std::ostringstream out;
    std::ostringstream err;
    int code = runner_ ? runner_(command_, in, out, err) : 1;
    if (!out.str().empty()) (void)channel.try_write_all(out.str());
    if (!err.str().empty()) (void)channel.try_write_all(err.str(), Stream::stderr_);
    (void)channel.try_send_exit_status(code);
    (void)channel.try_send_eof();
    // Deliberately does NOT call channel.try_close() here: this runs from
    // inside the channel_eof_function trampoline, itself invoked mid-iteration
    // by ssh_event_dopoll(); actively closing/freeing the channel at that
    // point corrupted libssh's internal channel list and crashed on the next
    // dopoll() call. Sending EOF is enough - the client closes its end, which
    // reaches us as the normal channel_close_function callback instead.
}

// -------------------------------------------------- Session (callback style) ----

SSHPP_INLINE Result<void> Session::try_set_handler(std::shared_ptr<SessionHandler> handler) {
    if (!core_) return ErrorInfo{make_error_code(errc::invalid_handle), "", "server::Session::try_set_handler"};
    if (used_message_style_ || bridge_) {
        return ErrorInfo{make_error_code(errc::invalid_argument),
                        "session already uses the message style or already has a handler",
                        "server::Session::try_set_handler"};
    }
    if (!handler) {
        return ErrorInfo{make_error_code(errc::invalid_argument), "handler is null", "server::Session::try_set_handler"};
    }
    auto bridge = std::make_shared<detail::HandlerBridge>(*this, std::move(handler));
    auto installed = bridge->install(core_->raw());
    if (!installed) return installed.error();
    bridge_ = std::move(bridge);
    return {};
}

SSHPP_INLINE Result<void> Session::try_attach(Event& event) {
    if (!core_) return ErrorInfo{make_error_code(errc::invalid_handle), "", "server::Session::try_attach"};
    if (ssh_event_add_session(event.native_handle(), core_->raw()) != SSH_OK) {
        return ErrorInfo{make_error_code(errc::unknown), "", "ssh_event_add_session"};
    }
    return {};
}

SSHPP_INLINE Result<void> Session::try_poll(std::chrono::milliseconds timeout) {
    if (!private_event_) {
        private_event_ = std::make_unique<Event>();
        auto attached = try_attach(*private_event_);
        if (!attached) {
            private_event_.reset();
            return attached;
        }
    }
    Result<void> result;
    {
        // Serializes against any dedicated subsystem thread (e.g.
        // SftpSubsystemHandler::try_serve()) doing raw, synchronous reads on
        // the same underlying ssh_session - see Channel::session_mutex().
        std::lock_guard<std::recursive_mutex> lock(core_->mutex());
        result = private_event_->try_poll(timeout);
    }
    // std::recursive_mutex gives no fairness guarantee: when dopoll() keeps
    // returning quickly (active traffic), this loop could otherwise
    // reacquire the lock repeatedly and starve a subsystem thread blocked
    // waiting for it. Yield once per iteration so the scheduler gets a
    // chance to hand the lock to a waiter instead.
    std::this_thread::yield();
    if (bridge_) bridge_->reap_closed_channels();
    return result;
}

SSHPP_INLINE void Session::notify_disconnect() {
    if (bridge_) bridge_->notify_disconnect();
}

} // namespace sshpp::server
