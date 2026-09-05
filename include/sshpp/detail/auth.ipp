// SPDX-License-Identifier: LGPL-2.1-or-later
// Generated from src/auth.cpp; see docs/design/09 §9.3.
#include <sshpp/config.hpp>
// SPDX-License-Identifier: LGPL-2.1-or-later
#include <sshpp/auth.hpp>
#include <sshpp/detail/invoke.hpp>

#include <libssh/libssh.h>

#include <cstring>

#if SSHPP_WITH_CONSOLE
#include <cstdio>
#include <iostream>
#include <termios.h>
#include <unistd.h>
#endif

namespace sshpp {

SSHPP_INLINE AuthMethods AuthMethods::from_bits(int bits) noexcept {
    AuthMethods m;
    m.password    = (bits & SSH_AUTH_METHOD_PASSWORD) != 0;
    m.public_key  = (bits & SSH_AUTH_METHOD_PUBLICKEY) != 0;
    m.host_based  = (bits & SSH_AUTH_METHOD_HOSTBASED) != 0;
    m.interactive = (bits & SSH_AUTH_METHOD_INTERACTIVE) != 0;
    m.gssapi_mic  = (bits & SSH_AUTH_METHOD_GSSAPI_MIC) != 0;
    m.none        = (bits & SSH_AUTH_METHOD_NONE) != 0;
    return m;
}

SSHPP_INLINE int AuthMethods::to_bits() const noexcept {
    int bits = 0;
    if (none) bits |= SSH_AUTH_METHOD_NONE;
    if (password) bits |= SSH_AUTH_METHOD_PASSWORD;
    if (public_key) bits |= SSH_AUTH_METHOD_PUBLICKEY;
    if (host_based) bits |= SSH_AUTH_METHOD_HOSTBASED;
    if (interactive) bits |= SSH_AUTH_METHOD_INTERACTIVE;
    if (gssapi_mic) bits |= SSH_AUTH_METHOD_GSSAPI_MIC;
    return bits;
}

namespace {

Result<AuthStatus> map_auth_result(int rc, native_session raw, const char* op) {
    switch (rc) {
        case SSH_AUTH_SUCCESS: return AuthStatus::success;
        case SSH_AUTH_DENIED: return AuthStatus::denied;
        case SSH_AUTH_PARTIAL: return AuthStatus::partial;
        case SSH_AUTH_AGAIN: return AuthStatus::again;
        case SSH_AUTH_ERROR:
        default:
            return detail::make_error_info(raw, op, SSHPP_HERE, errc::fatal);
    }
}

} // namespace

namespace auth {

SSHPP_INLINE Result<AuthStatus> None::attempt(detail::SessionCore& core) const noexcept {
    int rc = ssh_userauth_none(core.raw(), nullptr);
    return map_auth_result(rc, core.raw(), "ssh_userauth_none");
}

SSHPP_INLINE Result<AuthStatus> Password::attempt(detail::SessionCore& core) const noexcept {
    int rc = ssh_userauth_password(core.raw(), nullptr, password_.c_str());
    return map_auth_result(rc, core.raw(), "ssh_userauth_password");
}

SSHPP_INLINE Result<AuthStatus> PublicKeyAuto::attempt(detail::SessionCore& core) const noexcept {
    const char* pass = passphrase_.empty() ? nullptr : passphrase_.c_str();
    int rc = ssh_userauth_publickey_auto(core.raw(), nullptr, pass);
    return map_auth_result(rc, core.raw(), "ssh_userauth_publickey_auto");
}

SSHPP_INLINE Result<PublicKey> PublicKey::from_file(const std::filesystem::path& p, PassphraseCallback cb) {
    auto key = Key::from_private_file(p, std::move(cb));
    if (!key) return key.error();
    return auth::PublicKey(std::move(*key));
}

SSHPP_INLINE Result<AuthStatus> PublicKey::attempt(detail::SessionCore& core) const noexcept {
    int rc = ssh_userauth_try_publickey(core.raw(), nullptr, key_.native_handle());
    if (rc != SSH_AUTH_SUCCESS) return map_auth_result(rc, core.raw(), "ssh_userauth_try_publickey");
    rc = ssh_userauth_publickey(core.raw(), nullptr, key_.native_handle());
    return map_auth_result(rc, core.raw(), "ssh_userauth_publickey");
}

SSHPP_INLINE Result<AuthStatus> Agent::attempt(detail::SessionCore& core) const noexcept {
    int rc = ssh_userauth_agent(core.raw(), nullptr);
    return map_auth_result(rc, core.raw(), "ssh_userauth_agent");
}

SSHPP_INLINE KeyboardInteractive KeyboardInteractive::with_password(SecureString password) {
    auto pw = std::make_shared<SecureString>(std::move(password));
    return KeyboardInteractive([pw](const Challenge& challenge) -> Result<std::vector<SecureString>> {
        std::vector<SecureString> answers;
        answers.reserve(challenge.prompts.size());
        bool used = false;
        for (const auto& prompt : challenge.prompts) {
            if (!prompt.echo && !used) {
                answers.emplace_back(pw->view());
                used = true;
            } else {
                answers.emplace_back(SecureString{});
            }
        }
        return answers;
    });
}

SSHPP_INLINE Result<AuthStatus> KeyboardInteractive::attempt(detail::SessionCore& core) const noexcept {
    native_session raw = core.raw();
    int rc = ssh_userauth_kbdint(raw, nullptr, nullptr);
    while (rc == SSH_AUTH_INFO) {
        Challenge challenge;
        const char* name = ssh_userauth_kbdint_getname(raw);
        const char* instruction = ssh_userauth_kbdint_getinstruction(raw);
        challenge.name = name ? name : "";
        challenge.instruction = instruction ? instruction : "";

        int n = ssh_userauth_kbdint_getnprompts(raw);
        for (int i = 0; i < n; ++i) {
            char echo = 0;
            const char* text = ssh_userauth_kbdint_getprompt(raw, static_cast<unsigned int>(i), &echo);
            challenge.prompts.push_back({text ? text : "", echo != 0});
        }

        if (!handler_) {
            return detail::make_error_info(raw, "ssh_userauth_kbdint", SSHPP_HERE, errc::auth_denied);
        }
        auto answers = handler_(challenge);
        if (!answers) return answers.error();
        for (std::size_t i = 0; i < answers->size(); ++i) {
            ssh_userauth_kbdint_setanswer(raw, static_cast<unsigned int>(i), (*answers)[i].c_str());
        }
        rc = ssh_userauth_kbdint(raw, nullptr, nullptr);
    }
    return map_auth_result(rc, raw, "ssh_userauth_kbdint");
}

SSHPP_INLINE Result<AuthStatus> Chain::attempt(detail::SessionCore& core) const noexcept {
    AuthStatus last = AuthStatus::denied;
    for (const auto& a : chain_) {
        auto r = a->attempt(core);
        if (!r) return r;
        last = *r;
        if (last == AuthStatus::success) return last;
    }
    return last;
}

#if SSHPP_WITH_CONSOLE
SSHPP_INLINE KeyboardInteractive::Handler KeyboardInteractive::console_handler() {
    return [](const Challenge& challenge) -> Result<std::vector<SecureString>> {
        if (!challenge.instruction.empty()) std::fputs(challenge.instruction.c_str(), stderr);
        std::vector<SecureString> answers;
        answers.reserve(challenge.prompts.size());
        for (const auto& prompt : challenge.prompts) {
            std::fputs(prompt.text.c_str(), stderr);
            if (prompt.echo) {
                std::string line;
                std::getline(std::cin, line);
                answers.emplace_back(std::move(line));
            } else {
                auto pw = console_password_prompt("");
                if (!pw) return pw.error();
                answers.emplace_back(std::move(*pw));
            }
        }
        return answers;
    };
}

SSHPP_INLINE Chain Chain::interactive_default(PassphraseCallback passphrase_cb, PasswordCallback password_cb) {
    Chain chain;
    chain.add(std::make_shared<Agent>());

    SecureString passphrase;
    if (passphrase_cb) {
        auto r = passphrase_cb(PassphraseRequest{});
        if (r) passphrase = *r;
    }
    chain.add(std::make_shared<PublicKeyAuto>(passphrase));
    chain.add(std::make_shared<KeyboardInteractive>(KeyboardInteractive::console_handler()));

    struct LazyPassword final : Authenticator {
        explicit LazyPassword(PasswordCallback cb) : cb_(std::move(cb)) {}
        std::string_view name() const noexcept override { return "password"; }
        Result<AuthStatus> attempt(detail::SessionCore& core) const noexcept override {
            auto pw = cb_ ? cb_() : Result<SecureString>(SecureString{});
            if (!pw) return pw.error();
            return Password(*pw).attempt(core);
        }
        PasswordCallback cb_;
    };
    chain.add(std::make_shared<LazyPassword>(std::move(password_cb)));
    return chain;
}

namespace {
SecureString read_line_no_echo() {
    termios saved{};
    bool have_tty = ::tcgetattr(STDIN_FILENO, &saved) == 0;
    if (have_tty) {
        termios raw = saved;
        raw.c_lflag &= static_cast<tcflag_t>(~ECHO);
        ::tcsetattr(STDIN_FILENO, TCSANOW, &raw);
    }
    std::string line;
    std::getline(std::cin, line);
    if (have_tty) {
        ::tcsetattr(STDIN_FILENO, TCSANOW, &saved);
        std::fputc('\n', stderr);
    }
    return SecureString(std::move(line));
}
} // namespace

SSHPP_INLINE Result<SecureString> console_password_prompt(std::string_view prompt) {
    if (!prompt.empty()) {
        std::fwrite(prompt.data(), 1, prompt.size(), stderr);
        std::fflush(stderr);
    }
    return read_line_no_echo();
}

SSHPP_INLINE PassphraseCallback console_passphrase_prompt() {
    return [](const PassphraseRequest& req) -> Result<SecureString> {
        std::string prompt = "Passphrase for " + req.key_path + ": ";
        return console_password_prompt(prompt);
    };
}

SSHPP_INLINE PasswordCallback console_password_callback() {
    return []() -> Result<SecureString> { return console_password_prompt("Password: "); };
}

#endif // SSHPP_WITH_CONSOLE

} // namespace auth
} // namespace sshpp
