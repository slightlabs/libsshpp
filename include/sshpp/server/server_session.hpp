// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include <sshpp/config.hpp>

#include <sshpp/detail/handler_bridge.hpp>
#include <sshpp/detail/native_fwd.hpp>
#include <sshpp/detail/session_core.hpp>
#include <sshpp/event.hpp>
#include <sshpp/export.hpp>
#include <sshpp/result.hpp>
#include <sshpp/server/message.hpp>

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace sshpp::server {

struct SSHPP_API AuthMethodSet {
    bool none = false, password = false, public_key = false,
         host_based = false, interactive = false, gssapi_mic = false;
    int to_bits() const noexcept;
};

class Bind;
class SessionHandler;

/// One accepted server-side connection. See docs/design/08 §8.4.
class SSHPP_API Session {
public:
    Session() = default;
    ~Session();
    Session(Session&&) noexcept;
    Session& operator=(Session&&) noexcept;
    Session(const Session&) = delete;

    explicit operator bool() const noexcept { return core_ && core_->valid(); }
    native_session native_handle() const noexcept { return core_ ? core_->raw() : nullptr; }

    /// Performs the SSH transport handshake. Must be called before anything else.
    Result<void> try_handle_key_exchange();

    void         set_auth_methods(AuthMethodSet);
    Result<void> try_disconnect(std::string_view reason = {});

    Result<std::string> try_client_banner() const;

    bool                authenticated() const noexcept { return authenticated_; }
    const std::string& user() const noexcept { return user_; }

    /// nullopt on timeout. Negative timeout blocks indefinitely.
    Result<std::optional<Message>> try_next_message(std::chrono::milliseconds timeout =
                                                     std::chrono::milliseconds(-1));

    // ---- callback style (see docs/design/08 §8.6) --------------------------------
    /// Installs the server/channel callback trampolines and drives them via `event`
    /// on subsequent try_poll()/Event::try_poll() calls. Mixing this with
    /// try_next_message() on the same session returns errc::invalid_argument.
    Result<void> try_set_handler(std::shared_ptr<SessionHandler>);
    Result<void> try_attach(Event& event);
    /// Convenience: try_attach()s a private Event on first use, then polls it.
    Result<void> try_poll(std::chrono::milliseconds timeout);

private:
    friend class Bind;
    friend class Message;
    friend class detail::HandlerBridge;
    explicit Session(detail::SessionCorePtr core) : core_(std::move(core)) {}
    void notify_disconnect();

    detail::SessionCorePtr core_;
    bool                    authenticated_ = false;
    std::string             user_;
    bool                    used_message_style_ = false;
    std::shared_ptr<detail::HandlerBridge> bridge_;
    std::unique_ptr<Event>                  private_event_;
};

} // namespace sshpp::server

#if SSHPP_HEADER_ONLY
#include <sshpp/detail/server_session.ipp>
#endif
