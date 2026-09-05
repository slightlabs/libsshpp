// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include <sshpp/auth.hpp>
#include <sshpp/auth_types.hpp>
#include <sshpp/channel.hpp>
#include <sshpp/detail/native_fwd.hpp>
#include <sshpp/detail/session_core.hpp>
#include <sshpp/export.hpp>
#include <sshpp/host_key_verifier.hpp>
#include <sshpp/key.hpp>
#include <sshpp/known_hosts.hpp>
#include <sshpp/library.hpp>
#include <sshpp/result.hpp>
#include <sshpp/session_options.hpp>

#include <initializer_list>
#include <string>

namespace sshpp {

struct NegotiatedAlgorithms {
    std::string kex, host_key, cipher_in, cipher_out, hmac_in, hmac_out;
};

/// The SSH client session. Owns a shared SessionCore so derived objects (Channel, ...)
/// can never dangle. See docs/design/04 §4.3 and docs/design/02 §2.2.
class SSHPP_API Session {
public:
    Session();
    explicit Session(const SessionOptions&);
    ~Session();
    Session(Session&&) noexcept;
    Session& operator=(Session&&) noexcept;
    Session(const Session&)            = delete;
    Session& operator=(const Session&) = delete;

    explicit operator bool() const noexcept { return core_ && core_->valid(); }
    native_session native_handle() const noexcept { return core_ ? core_->raw() : nullptr; }

    // ---- options ---------------------------------------------------------
    Result<void> try_set_options(const SessionOptions&);
    void         set_options(const SessionOptions&);
    const SessionOptions& configured_options() const noexcept { return options_; }

    // ---- connection ------------------------------------------------------
    Result<void> try_connect();
    void         connect();
    void         disconnect() noexcept;
    [[nodiscard]] bool is_connected() const noexcept;

    int socket_fd() const noexcept;

    void request_cancel() noexcept { if (core_) core_->request_cancel(); }
    void clear_cancel() noexcept { if (core_) core_->clear_cancel(); }
    bool cancel_requested() const noexcept { return core_ && core_->cancel_requested(); }

    // ---- peer information -------------------------------------------------
    Result<std::string> try_server_banner() const;
    Result<std::string> try_client_banner() const;
    NegotiatedAlgorithms negotiated() const;

    // ---- host key ----------------------------------------------------------
    Result<PublicKey>        try_server_public_key() const;
    Result<KnownHostsStatus> try_check_known_host() const;
    Result<void>             try_update_known_hosts();
    Result<void>             try_verify_host_key(const HostKeyVerifier&);
    void                     verify_host_key(const HostKeyVerifier&);

    // ---- authentication -------------------------------------------------------
    Result<AuthMethods> try_auth_methods();
    Result<AuthStatus>  try_authenticate(const Authenticator&);
    void                authenticate(const Authenticator&);
    Result<AuthStatus>  try_authenticate(std::initializer_list<const Authenticator*>);
    bool                authenticated() const noexcept { return authenticated_; }

    // ---- subsystem factories ---------------------------------------------------
    Result<Channel> try_open_channel();
    Channel         open_channel();

    // ---- diagnostics ------------------------------------------------------------
    void set_log_level(LogLevel);

private:
    friend class HostKeyVerifier;

    detail::SessionCorePtr core_;
    SessionOptions          options_;
    bool                    authenticated_ = false;
};

} // namespace sshpp
