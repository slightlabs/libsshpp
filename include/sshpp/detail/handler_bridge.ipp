// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Bridges libssh's ssh_server_callbacks_struct / ssh_channel_callbacks_struct
// C trampolines to SessionHandler/ChannelHandler. See docs/design/08 §8.6.
//
// Every trampoline is wrapped in try/catch: exceptions must never propagate
// into libssh's C frames (they would corrupt its internal state machine).
#pragma once

#include <sshpp/detail/handler_bridge.hpp>
#include <sshpp/detail/invoke.hpp>
#include <sshpp/server/handlers.hpp>

#include <libssh/callbacks.h>
#include <libssh/libssh.h>
#include <libssh/server.h>

#include <unordered_map>
#include <vector>

namespace sshpp::detail {

class HandlerBridge {
public:
    HandlerBridge(server::Session& session, std::shared_ptr<server::SessionHandler> handler)
        : session_(&session), handler_(std::move(handler)) {
        ssh_callbacks_init((&server_cb_));
        server_cb_.userdata = this;
        server_cb_.auth_none_function = &HandlerBridge::auth_none_cb;
        server_cb_.auth_password_function = &HandlerBridge::auth_password_cb;
        server_cb_.auth_pubkey_function = &HandlerBridge::auth_pubkey_cb;
        server_cb_.auth_gssapi_mic_function = &HandlerBridge::auth_gssapi_mic_cb;
        server_cb_.channel_open_request_session_function = &HandlerBridge::channel_open_session_cb;
        server_cb_.service_request_function = &HandlerBridge::service_request_cb;
    }

    ~HandlerBridge() = default;
    HandlerBridge(const HandlerBridge&) = delete;
    HandlerBridge& operator=(const HandlerBridge&) = delete;

    Result<void> install(native_session raw) {
        if (ssh_set_server_callbacks(raw, &server_cb_) != SSH_OK) {
            return ErrorInfo{make_error_code(errc::unknown), "", "ssh_set_server_callbacks"};
        }
        return {};
    }

    void notify_disconnect() {
        if (!handler_) return;
        try {
            handler_->on_disconnect(*session_);
        } catch (...) {
        }
    }

    /// Actually erases (and thus frees) any channel whose close callback fired
    /// since the last call. Must be called from outside ssh_event_dopoll()'s
    /// call stack - see the comment on channel_close_cb.
    void reap_closed_channels() {
        for (auto raw : pending_removals_) channels_.erase(raw);
        pending_removals_.clear();
    }

private:
    struct ChannelState {
        Channel                                 channel;
        std::shared_ptr<server::ChannelHandler> handler;
        ssh_channel_callbacks_struct            cb{};
        HandlerBridge*                           bridge = nullptr;
    };

    void report_error(const ErrorInfo& info) {
        if (!handler_) return;
        try {
            handler_->on_error(*session_, info);
        } catch (...) {
        }
    }

    ChannelState* register_channel(native_channel raw, std::shared_ptr<server::ChannelHandler> handler) {
        auto state = std::make_unique<ChannelState>();
        state->channel = Channel::from_native(raw, session_->core_, Ownership::owning);
        state->handler = std::move(handler);
        state->bridge = this;
        ssh_callbacks_init((&state->cb));
        state->cb.userdata = state.get();
        state->cb.channel_data_function = &HandlerBridge::channel_data_cb;
        state->cb.channel_eof_function = &HandlerBridge::channel_eof_cb;
        state->cb.channel_close_function = &HandlerBridge::channel_close_cb;
        state->cb.channel_signal_function = &HandlerBridge::channel_signal_cb;
        state->cb.channel_pty_request_function = &HandlerBridge::channel_pty_request_cb;
        state->cb.channel_shell_request_function = &HandlerBridge::channel_shell_request_cb;
        state->cb.channel_x11_req_function = &HandlerBridge::channel_x11_req_cb;
        state->cb.channel_pty_window_change_function = &HandlerBridge::channel_pty_window_change_cb;
        state->cb.channel_exec_request_function = &HandlerBridge::channel_exec_request_cb;
        state->cb.channel_env_request_function = &HandlerBridge::channel_env_request_cb;
        state->cb.channel_subsystem_request_function = &HandlerBridge::channel_subsystem_request_cb;
        ssh_set_channel_callbacks(raw, &state->cb);
        ChannelState* ptr = state.get();
        channels_[raw] = std::move(state);
        return ptr;
    }

    // ---- auth trampolines --------------------------------------------------------
    static int auth_none_cb(ssh_session, const char* user, void* userdata) {
        auto* self = static_cast<HandlerBridge*>(userdata);
        try {
            auto r = self->handler_->on_auth_none(*self->session_, user != nullptr ? user : "");
            return self->apply_auth_result(r, user);
        } catch (const std::exception& e) {
            self->report_error(ErrorInfo{make_error_code(errc::unknown), e.what(), "on_auth_none"});
            return SSH_AUTH_DENIED;
        } catch (...) {
            return SSH_AUTH_DENIED;
        }
    }

    static int auth_password_cb(ssh_session, const char* user, const char* password, void* userdata) {
        auto* self = static_cast<HandlerBridge*>(userdata);
        try {
            auto r = self->handler_->on_auth_password(*self->session_, user != nullptr ? user : "",
                                                       SecureString(password != nullptr ? password : ""));
            return self->apply_auth_result(r, user);
        } catch (const std::exception& e) {
            self->report_error(ErrorInfo{make_error_code(errc::unknown), e.what(), "on_auth_password"});
            return SSH_AUTH_DENIED;
        } catch (...) {
            return SSH_AUTH_DENIED;
        }
    }

    static int auth_pubkey_cb(ssh_session, const char* user, ssh_key pubkey, char signature_state, void* userdata) {
        auto* self = static_cast<HandlerBridge*>(userdata);
        try {
            server::PublicKeyState state = server::PublicKeyState::none;
            if (signature_state == SSH_PUBLICKEY_STATE_VALID) state = server::PublicKeyState::valid;
            else if (signature_state == SSH_PUBLICKEY_STATE_WRONG) state = server::PublicKeyState::wrong;
            Key key = Key::from_native(pubkey, Ownership::borrowed);
            auto r = self->handler_->on_auth_public_key(*self->session_, user != nullptr ? user : "", key, state);
            // A `state == none` success is just "this key would be acceptable" (a
            // probe before the client signs anything); only a `state == valid`
            // success is an actually-verified signature that finishes auth.
            return self->apply_auth_result(r, user, /*finalize=*/state == server::PublicKeyState::valid);
        } catch (const std::exception& e) {
            self->report_error(ErrorInfo{make_error_code(errc::unknown), e.what(), "on_auth_public_key"});
            return SSH_AUTH_DENIED;
        } catch (...) {
            return SSH_AUTH_DENIED;
        }
    }

    static int auth_gssapi_mic_cb(ssh_session, const char* user, const char* principal, void* userdata) {
        auto* self = static_cast<HandlerBridge*>(userdata);
        try {
            auto r = self->handler_->on_auth_gssapi_mic(*self->session_, user != nullptr ? user : "",
                                                        principal != nullptr ? principal : "");
            return self->apply_auth_result(r, user);
        } catch (...) {
            return SSH_AUTH_DENIED;
        }
    }

    int apply_auth_result(server::AuthResult r, const char* user, bool finalize = true) {
        if (r == server::AuthResult::success) {
            if (finalize) {
                session_->authenticated_ = true;
                session_->user_ = user != nullptr ? user : "";
            }
            return SSH_AUTH_SUCCESS;
        }
        if (r == server::AuthResult::partial) return SSH_AUTH_PARTIAL;
        return SSH_AUTH_DENIED;
    }

    // ---- channel-open / service ---------------------------------------------------
    static ssh_channel channel_open_session_cb(ssh_session sess, void* userdata) {
        auto* self = static_cast<HandlerBridge*>(userdata);
        try {
            auto ch_handler = self->handler_->on_channel_open_session(*self->session_);
            if (!ch_handler) return nullptr;
            ssh_channel raw = ssh_channel_new(sess);
            if (raw == nullptr) return nullptr;
            self->register_channel(raw, std::move(ch_handler));
            return raw;
        } catch (const std::exception& e) {
            self->report_error(ErrorInfo{make_error_code(errc::unknown), e.what(), "on_channel_open_session"});
            return nullptr;
        } catch (...) {
            return nullptr;
        }
    }

    static int service_request_cb(ssh_session, const char* service, void* userdata) {
        auto* self = static_cast<HandlerBridge*>(userdata);
        try {
            self->handler_->on_service_request(*self->session_, service != nullptr ? service : "");
        } catch (...) {
        }
        return 0;
    }

    // ---- channel-level trampolines -------------------------------------------------
    static int channel_data_cb(ssh_session, ssh_channel, void* data, uint32_t len, int is_stderr, void* userdata) {
        auto* state = static_cast<ChannelState*>(userdata);
        try {
            auto consumed = state->handler->on_data(state->channel,
                                                    ByteView(static_cast<const std::byte*>(data), len),
                                                    is_stderr != 0 ? Stream::stderr_ : Stream::stdout_);
            return static_cast<int>(consumed);
        } catch (...) {
            return 0;
        }
    }

    static void channel_eof_cb(ssh_session, ssh_channel, void* userdata) {
        auto* state = static_cast<ChannelState*>(userdata);
        try {
            state->handler->on_eof(state->channel);
        } catch (...) {
        }
    }

    static void channel_close_cb(ssh_session, ssh_channel raw, void* userdata) {
        auto* state = static_cast<ChannelState*>(userdata);
        try {
            state->handler->on_close(state->channel);
        } catch (...) {
        }
        // Deferred: freeing the Channel (via erase, destroying the owning
        // ChannelState) here would call ssh_channel_free() while
        // ssh_event_dopoll() is still mid-iteration over its channel list for
        // this very session, which corrupted libssh's internal state and
        // crashed the *next* dopoll() call. Collect it and let
        // reap_closed_channels() (called from Session::try_poll(), after
        // dopoll() has returned) do the actual erase/free instead.
        state->bridge->pending_removals_.push_back(raw);
    }

    static void channel_signal_cb(ssh_session, ssh_channel, const char* signal, void* userdata) {
        auto* state = static_cast<ChannelState*>(userdata);
        try {
            state->handler->on_signal(state->channel, signal != nullptr ? signal : "");
        } catch (...) {
        }
    }

    static int channel_pty_request_cb(ssh_session, ssh_channel, const char* term, int width, int height,
                                      int, int, void* userdata) {
        auto* state = static_cast<ChannelState*>(userdata);
        try {
            PtySize size{width, height};
            return state->handler->on_pty_request(state->channel, term != nullptr ? term : "", size) ? 0 : -1;
        } catch (...) {
            return -1;
        }
    }

    static int channel_pty_window_change_cb(ssh_session, ssh_channel, int width, int height, int, int,
                                            void* userdata) {
        auto* state = static_cast<ChannelState*>(userdata);
        try {
            PtySize size{width, height};
            return state->handler->on_pty_resize(state->channel, size) ? 0 : -1;
        } catch (...) {
            return -1;
        }
    }

    static int channel_shell_request_cb(ssh_session, ssh_channel, void* userdata) {
        auto* state = static_cast<ChannelState*>(userdata);
        try {
            return state->handler->on_shell_request(state->channel) ? 0 : 1;
        } catch (...) {
            return 1;
        }
    }

    static int channel_exec_request_cb(ssh_session, ssh_channel, const char* command, void* userdata) {
        auto* state = static_cast<ChannelState*>(userdata);
        try {
            return state->handler->on_exec_request(state->channel, command != nullptr ? command : "") ? 0 : 1;
        } catch (...) {
            return 1;
        }
    }

    static int channel_env_request_cb(ssh_session, ssh_channel, const char* name, const char* value,
                                      void* userdata) {
        auto* state = static_cast<ChannelState*>(userdata);
        try {
            return state->handler->on_env_request(state->channel, name != nullptr ? name : "",
                                                  value != nullptr ? value : "")
                       ? 0
                       : 1;
        } catch (...) {
            return 1;
        }
    }

    static int channel_subsystem_request_cb(ssh_session, ssh_channel raw, const char* name, void* userdata) {
        auto* state = static_cast<ChannelState*>(userdata);
        try {
            bool accepted = state->handler->on_subsystem_request(state->channel, name != nullptr ? name : "");
            if (accepted) {
                // Subsystems (sftp and friends) hand the channel off to a
                // dedicated protocol handler that does its own raw,
                // synchronous ssh_channel_read()s (see SftpSubsystemHandler).
                // Stop also dispatching this channel's data through
                // channel_data_function, or the two readers race for bytes.
                ssh_remove_channel_callbacks(raw, &state->cb);
            }
            return accepted ? 0 : 1;
        } catch (...) {
            return 1;
        }
    }

    static void channel_x11_req_cb(ssh_session, ssh_channel, int single_connection, const char* auth_protocol,
                                   const char* auth_cookie, uint32_t screen_number, void* userdata) {
        auto* state = static_cast<ChannelState*>(userdata);
        try {
            state->handler->on_x11_request(state->channel, single_connection != 0,
                                           auth_protocol != nullptr ? auth_protocol : "",
                                           auth_cookie != nullptr ? auth_cookie : "", screen_number);
        } catch (...) {
        }
    }

    server::Session*                        session_;
    std::shared_ptr<server::SessionHandler>  handler_;
    ssh_server_callbacks_struct              server_cb_{};
    std::unordered_map<ssh_channel, std::unique_ptr<ChannelState>> channels_;
    std::vector<ssh_channel>                 pending_removals_;
};

} // namespace sshpp::detail
