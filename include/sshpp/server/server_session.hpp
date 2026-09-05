// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include <sshpp/detail/native_fwd.hpp>
#include <sshpp/detail/session_core.hpp>
#include <sshpp/export.hpp>
#include <sshpp/result.hpp>
#include <sshpp/server/message.hpp>

#include <chrono>
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

private:
    friend class Bind;
    friend class Message;
    explicit Session(detail::SessionCorePtr core) : core_(std::move(core)) {}

    detail::SessionCorePtr core_;
    bool                    authenticated_ = false;
    std::string             user_;
};

} // namespace sshpp::server
