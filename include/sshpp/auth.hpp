// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include <sshpp/config.hpp>

#include <sshpp/auth_types.hpp>
#include <sshpp/detail/session_core.hpp>
#include <sshpp/export.hpp>
#include <sshpp/key.hpp>
#include <sshpp/result.hpp>
#include <sshpp/types.hpp>

#include <memory>
#include <string_view>
#include <vector>
#include <filesystem>

namespace sshpp {

/// Authentication strategy interface. See docs/design/04 §4.4.
class SSHPP_API Authenticator {
public:
    virtual ~Authenticator() = default;
    virtual std::string_view name() const noexcept = 0;
    /// Performs one full attempt. Must not throw.
    virtual Result<AuthStatus> attempt(detail::SessionCore&) const noexcept = 0;
};

namespace auth {

/// "none" — probes the server; sometimes succeeds outright (passwordless accounts).
class SSHPP_API None final : public Authenticator {
public:
    std::string_view name() const noexcept override { return "none"; }
    Result<AuthStatus> attempt(detail::SessionCore&) const noexcept override;
};

class SSHPP_API Password final : public Authenticator {
public:
    explicit Password(SecureString password) : password_(std::move(password)) {}

    std::string_view name() const noexcept override { return "password"; }
    Result<AuthStatus> attempt(detail::SessionCore&) const noexcept override;

private:
    SecureString password_;
};

/// ssh_userauth_publickey_auto: agent, then default identities, then configured identities.
class SSHPP_API PublicKeyAuto final : public Authenticator {
public:
    PublicKeyAuto() = default;
    explicit PublicKeyAuto(SecureString passphrase) : passphrase_(std::move(passphrase)) {}

    std::string_view name() const noexcept override { return "publickey_auto"; }
    Result<AuthStatus> attempt(detail::SessionCore&) const noexcept override;

private:
    SecureString passphrase_;
};

/// Explicit key: try_publickey (offer) then publickey (sign).
class SSHPP_API PublicKey final : public Authenticator {
public:
    explicit PublicKey(Key private_key) : key_(std::move(private_key)) {}

    static Result<PublicKey> from_file(const std::filesystem::path& p, PassphraseCallback cb = {});

    std::string_view name() const noexcept override { return "publickey"; }
    Result<AuthStatus> attempt(detail::SessionCore&) const noexcept override;

private:
    Key key_;
};

/// ssh_userauth_agent.
class SSHPP_API Agent final : public Authenticator {
public:
    std::string_view name() const noexcept override { return "agent"; }
    Result<AuthStatus> attempt(detail::SessionCore&) const noexcept override;
};

/// Full keyboard-interactive loop.
class SSHPP_API KeyboardInteractive final : public Authenticator {
public:
    struct Prompt { std::string text; bool echo; };
    struct Challenge {
        std::string name, instruction;
        std::vector<Prompt> prompts;
    };
    using Handler = std::function<Result<std::vector<SecureString>>(const Challenge&)>;

    explicit KeyboardInteractive(Handler h) : handler_(std::move(h)) {}

    /// Answers the first non-echo prompt with the password; the common "PAM password" case.
    static KeyboardInteractive with_password(SecureString password);
#if SSHPP_WITH_CONSOLE
    /// A Handler that prompts on /dev/tty, echoing prompts marked echo=true and
    /// disabling terminal echo for the rest (passwords/PINs).
    static Handler console_handler();
#endif

    std::string_view name() const noexcept override { return "keyboard-interactive"; }
    Result<AuthStatus> attempt(detail::SessionCore&) const noexcept override;

private:
    Handler handler_;
};

/// Tries each authenticator in order until one succeeds.
class SSHPP_API Chain final : public Authenticator {
public:
    Chain& add(std::shared_ptr<Authenticator> a) { chain_.push_back(std::move(a)); return *this; }

    template <class A, class... Args>
    Chain& emplace(Args&&... args) {
        return add(std::make_shared<A>(std::forward<Args>(args)...));
    }

#if SSHPP_WITH_CONSOLE
    /// Default chain: Agent -> PublicKeyAuto -> KeyboardInteractive(console) -> Password(console).
    /// Note: `passphrase_cb` is consulted once, eagerly, to seed PublicKeyAuto's
    /// single shared passphrase (PublicKeyAuto has no per-key callback of its
    /// own) - it does not defer until Agent/no-passphrase-needed keys have
    /// already been tried.
    static Chain interactive_default(PassphraseCallback passphrase_cb, PasswordCallback password_cb);
#endif

    std::string_view name() const noexcept override { return "chain"; }
    Result<AuthStatus> attempt(detail::SessionCore&) const noexcept override;

private:
    std::vector<std::shared_ptr<Authenticator>> chain_;
};

#if SSHPP_WITH_CONSOLE
/// Reads a password from /dev/tty with echo disabled.
SSHPP_API Result<SecureString> console_password_prompt(std::string_view prompt = "Password: ");
/// A PassphraseCallback that prompts on /dev/tty (echo disabled), showing the key path and attempt number.
SSHPP_API PassphraseCallback console_passphrase_prompt();
/// A PasswordCallback that prompts on /dev/tty (echo disabled).
SSHPP_API PasswordCallback console_password_callback();
#endif

} // namespace auth
} // namespace sshpp

#if SSHPP_HEADER_ONLY
#include <sshpp/detail/auth.ipp>
#endif
