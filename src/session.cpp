// SPDX-License-Identifier: LGPL-2.1-or-later
#include <sshpp/session.hpp>
#include <sshpp/detail/invoke.hpp>

#include <libssh/libssh.h>

#include <type_traits>

namespace sshpp {

namespace {

static_assert(std::is_same_v<native_session, ssh_session>, "libssh changed ssh_session's definition");

KnownHostsStatus known_hosts_status_from_native(ssh_known_hosts_e s) {
    switch (s) {
        case SSH_KNOWN_HOSTS_OK: return KnownHostsStatus::ok;
        case SSH_KNOWN_HOSTS_CHANGED: return KnownHostsStatus::changed;
        case SSH_KNOWN_HOSTS_OTHER: return KnownHostsStatus::other_type;
        case SSH_KNOWN_HOSTS_NOT_FOUND: return KnownHostsStatus::not_found;
        case SSH_KNOWN_HOSTS_UNKNOWN: return KnownHostsStatus::unknown;
        case SSH_KNOWN_HOSTS_ERROR:
        default: return KnownHostsStatus::error;
    }
}

Result<void> set_string_opt(native_session sess, ssh_options_e opt, const std::string& value,
                            const char* name) {
    if (ssh_options_set(sess, opt, value.c_str()) != SSH_OK) {
        return detail::make_error_info(sess, name, SSHPP_HERE, errc::invalid_argument);
    }
    return {};
}

/// Applies SessionOptions in the fixed order documented in docs/design/04 §4.2.
Result<void> apply_options(native_session sess, const SessionOptions& opts) {
    if (opts.ssh_dir) {
        if (auto r = set_string_opt(sess, SSH_OPTIONS_SSH_DIR, opts.ssh_dir->string(), "SSH_OPTIONS_SSH_DIR"); !r) return r;
    }
    if (opts.known_hosts) {
        if (auto r = set_string_opt(sess, SSH_OPTIONS_KNOWNHOSTS, opts.known_hosts->string(), "SSH_OPTIONS_KNOWNHOSTS"); !r) return r;
    }
    if (opts.global_known_hosts) {
        if (auto r = set_string_opt(sess, SSH_OPTIONS_GLOBAL_KNOWNHOSTS, opts.global_known_hosts->string(), "SSH_OPTIONS_GLOBAL_KNOWNHOSTS"); !r) return r;
    }

    if (auto r = set_string_opt(sess, SSH_OPTIONS_HOST, opts.host, "SSH_OPTIONS_HOST"); !r) return r;

    if (opts.port) {
        unsigned int port = *opts.port;
        if (ssh_options_set(sess, SSH_OPTIONS_PORT, &port) != SSH_OK) {
            return detail::make_error_info(sess, "SSH_OPTIONS_PORT", SSHPP_HERE, errc::invalid_argument);
        }
    }
    if (opts.user) {
        if (auto r = set_string_opt(sess, SSH_OPTIONS_USER, *opts.user, "SSH_OPTIONS_USER"); !r) return r;
    }

    if (opts.bind_address) {
        if (auto r = set_string_opt(sess, SSH_OPTIONS_BINDADDR, *opts.bind_address, "SSH_OPTIONS_BINDADDR"); !r) return r;
    }
    if (opts.fd) {
        socket_t fd = *opts.fd;
        ssh_options_set(sess, SSH_OPTIONS_FD, &fd);
    }
    if (opts.proxy_command) {
        if (auto r = set_string_opt(sess, SSH_OPTIONS_PROXYCOMMAND, *opts.proxy_command, "SSH_OPTIONS_PROXYCOMMAND"); !r) return r;
    }
    if (opts.timeout) {
        long sec  = static_cast<long>(opts.timeout->count() / 1000000);
        long usec = static_cast<long>(opts.timeout->count() % 1000000);
        ssh_options_set(sess, SSH_OPTIONS_TIMEOUT, &sec);
        ssh_options_set(sess, SSH_OPTIONS_TIMEOUT_USEC, &usec);
    }
    if (opts.tcp_nodelay) {
        int v = *opts.tcp_nodelay ? 1 : 0;
        ssh_options_set(sess, SSH_OPTIONS_NODELAY, &v);
    }
    for (const auto& id : opts.identities) {
        if (auto r = set_string_opt(sess, SSH_OPTIONS_ADD_IDENTITY, id.string(), "SSH_OPTIONS_ADD_IDENTITY"); !r) return r;
    }
    if (opts.ciphers_client_to_server) {
        if (auto r = set_string_opt(sess, SSH_OPTIONS_CIPHERS_C_S, *opts.ciphers_client_to_server, "SSH_OPTIONS_CIPHERS_C_S"); !r) return r;
    }
    if (opts.ciphers_server_to_client) {
        if (auto r = set_string_opt(sess, SSH_OPTIONS_CIPHERS_S_C, *opts.ciphers_server_to_client, "SSH_OPTIONS_CIPHERS_S_C"); !r) return r;
    }
    if (opts.key_exchange) {
        if (auto r = set_string_opt(sess, SSH_OPTIONS_KEY_EXCHANGE, *opts.key_exchange, "SSH_OPTIONS_KEY_EXCHANGE"); !r) return r;
    }
    if (opts.hmac_client_to_server) {
        if (auto r = set_string_opt(sess, SSH_OPTIONS_HMAC_C_S, *opts.hmac_client_to_server, "SSH_OPTIONS_HMAC_C_S"); !r) return r;
    }
    if (opts.hmac_server_to_client) {
        if (auto r = set_string_opt(sess, SSH_OPTIONS_HMAC_S_C, *opts.hmac_server_to_client, "SSH_OPTIONS_HMAC_S_C"); !r) return r;
    }
    if (opts.host_key_algorithms) {
        if (auto r = set_string_opt(sess, SSH_OPTIONS_HOSTKEYS, *opts.host_key_algorithms, "SSH_OPTIONS_HOSTKEYS"); !r) return r;
    }
    if (opts.public_key_accepted_types) {
        if (auto r = set_string_opt(sess, SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES, *opts.public_key_accepted_types, "SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES"); !r) return r;
    }
    if (opts.compression) {
        const char* v = "no";
        switch (*opts.compression) {
            case Compression::on: v = "yes"; break;
            case Compression::zlib: v = "zlib"; break;
            case Compression::zlib_openssh: v = "zlib@openssh.com"; break;
            case Compression::off:
            default: v = "no"; break;
        }
        ssh_options_set(sess, SSH_OPTIONS_COMPRESSION, v);
    }
    if (opts.compression_level) {
        int v = *opts.compression_level;
        ssh_options_set(sess, SSH_OPTIONS_COMPRESSION_LEVEL, &v);
    }
    if (opts.rekey_data_bytes) {
        std::uint64_t v = *opts.rekey_data_bytes;
        ssh_options_set(sess, SSH_OPTIONS_REKEY_DATA, &v);
    }
    if (opts.rekey_time) {
        std::uint32_t v = static_cast<std::uint32_t>(opts.rekey_time->count());
        ssh_options_set(sess, SSH_OPTIONS_REKEY_TIME, &v);
    }
    if (opts.strict_host_key_checking) {
        int v = *opts.strict_host_key_checking == StrictHostKeyChecking::on ? 1 : 0;
        ssh_options_set(sess, SSH_OPTIONS_STRICTHOSTKEYCHECK, &v);
    }
    if (opts.gssapi_server_identity) {
        if (auto r = set_string_opt(sess, SSH_OPTIONS_GSSAPI_SERVER_IDENTITY, *opts.gssapi_server_identity, "SSH_OPTIONS_GSSAPI_SERVER_IDENTITY"); !r) return r;
    }
    if (opts.gssapi_client_identity) {
        if (auto r = set_string_opt(sess, SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY, *opts.gssapi_client_identity, "SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY"); !r) return r;
    }
    if (opts.gssapi_delegate_credentials) {
        int v = *opts.gssapi_delegate_credentials ? 1 : 0;
        ssh_options_set(sess, SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS, &v);
    }

    if (opts.config_file) {
        ssh_options_parse_config(sess, opts.config_file->string().c_str());
    } else if (opts.process_config) {
        ssh_options_parse_config(sess, nullptr);
    }
    int process_config = opts.process_config ? 1 : 0;
    ssh_options_set(sess, SSH_OPTIONS_PROCESS_CONFIG, &process_config);

    return {};
}

} // namespace

Session::Session() = default;

Session::Session(const SessionOptions& opts) : options_(opts) {
    native_session raw = ssh_new();
    if (raw != nullptr) {
        core_ = std::make_shared<detail::SessionCore>(raw);
        (void)apply_options(raw, opts); // errors surfaced by try_connect()/try_set_options()
    }
}

Session::~Session() = default;
Session::Session(Session&&) noexcept = default;
Session& Session::operator=(Session&&) noexcept = default;

Result<void> Session::try_set_options(const SessionOptions& opts) {
    if (!core_) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Session::try_set_options"};
    options_ = opts;
    return apply_options(core_->raw(), opts);
}

void Session::set_options(const SessionOptions& opts) { try_set_options(opts).throw_if_error(); }

Result<void> Session::try_connect() {
    if (!core_) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Session::try_connect"};
    int rc = ssh_connect(core_->raw());
    if (rc != SSH_OK) {
        return detail::make_error_info(core_->raw(), "ssh_connect", SSHPP_HERE, errc::connection_lost);
    }
    return {};
}

void Session::connect() { try_connect().throw_if_error(); }

void Session::disconnect() noexcept {
    if (core_ && core_->valid()) {
        ssh_disconnect(core_->raw());
    }
}

bool Session::is_connected() const noexcept {
    return core_ && core_->valid() && ssh_is_connected(core_->raw()) != 0;
}

int Session::socket_fd() const noexcept {
    return core_ && core_->valid() ? static_cast<int>(ssh_get_fd(core_->raw())) : -1;
}

Result<std::string> Session::try_server_banner() const {
    if (!core_) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Session::try_server_banner"};
    const char* banner = ssh_get_serverbanner(core_->raw());
    return std::string(banner ? banner : "");
}

Result<std::string> Session::try_client_banner() const {
    if (!core_) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Session::try_client_banner"};
    const char* banner = ssh_get_clientbanner(core_->raw());
    return std::string(banner ? banner : "");
}

NegotiatedAlgorithms Session::negotiated() const {
    NegotiatedAlgorithms n;
    if (!core_) return n;
    native_session raw = core_->raw();
    const char* v;
    v = ssh_get_kex_algo(raw); if (v) n.kex = v;
    v = ssh_get_cipher_in(raw); if (v) n.cipher_in = v;
    v = ssh_get_cipher_out(raw); if (v) n.cipher_out = v;
    v = ssh_get_hmac_in(raw); if (v) n.hmac_in = v;
    v = ssh_get_hmac_out(raw); if (v) n.hmac_out = v;
    return n;
}

Result<PublicKey> Session::try_server_public_key() const {
    if (!core_) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Session::try_server_public_key"};
    ssh_key key = nullptr;
    int rc = ssh_get_server_publickey(core_->raw(), &key);
    if (rc != SSH_OK || key == nullptr) {
        return detail::make_error_info(core_->raw(), "ssh_get_server_publickey", SSHPP_HERE, errc::host_key_unknown);
    }
    return Key::from_native(key, Ownership::owning);
}

Result<KnownHostsStatus> Session::try_check_known_host() const {
    if (!core_) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Session::try_check_known_host"};
    ssh_known_hosts_e s = ssh_session_is_known_server(core_->raw());
    return known_hosts_status_from_native(s);
}

Result<void> Session::try_update_known_hosts() {
    if (!core_) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Session::try_update_known_hosts"};
    int rc = ssh_session_update_known_hosts(core_->raw());
    if (rc != SSH_OK) {
        return detail::make_error_info(core_->raw(), "ssh_session_update_known_hosts", SSHPP_HERE, errc::known_hosts_io_error);
    }
    return {};
}

Result<void> Session::try_verify_host_key(const HostKeyVerifier& verifier) {
    if (!core_) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Session::try_verify_host_key"};

    auto status = try_check_known_host();
    if (!status) return status.error();

    auto key = try_server_public_key();
    if (!key) return key.error();

    auto fp = key->fingerprint(HashType::sha256);
    if (!fp) return fp.error();

    HostKeyVerifier::Context ctx{options_.host, options_.port.value_or(22), *status, *key, *fp, *this};
    auto decision = verifier.verify(ctx);

    switch (decision) {
        case HostKeyVerifier::Decision::reject: {
            ErrorInfo info;
            info.operation = "Session::verify_host_key";
            info.code = make_error_code(errc::host_key_rejected);
            info.message = "host key rejected by policy (status=" +
                           std::to_string(static_cast<int>(*status)) + ")";
            return info;
        }
        case HostKeyVerifier::Decision::accept_and_remember:
            return try_update_known_hosts();
        case HostKeyVerifier::Decision::accept:
        default:
            return {};
    }
}

void Session::verify_host_key(const HostKeyVerifier& verifier) {
    try_verify_host_key(verifier).throw_if_error();
}

Result<AuthMethods> Session::try_auth_methods() {
    if (!core_) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Session::try_auth_methods"};
    native_session raw = core_->raw();
    int rc = ssh_userauth_none(raw, nullptr);
    if (rc == SSH_AUTH_SUCCESS) {
        authenticated_ = true;
        AuthMethods m;
        m.none = true;
        return m;
    }
    int bits = ssh_userauth_list(raw, nullptr);
    return AuthMethods::from_bits(bits);
}

Result<AuthStatus> Session::try_authenticate(const Authenticator& authenticator) {
    if (!core_) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Session::try_authenticate"};
    auto r = authenticator.attempt(*core_);
    if (r && *r == AuthStatus::success) authenticated_ = true;
    return r;
}

void Session::authenticate(const Authenticator& authenticator) {
    auto status = try_authenticate(authenticator).value();
    if (status != AuthStatus::success) {
        ErrorInfo info;
        info.operation = "Session::authenticate";
        info.code = make_error_code(status == AuthStatus::partial ? errc::auth_partial : errc::auth_denied);
        info.message = "authentication did not succeed";
        throw_error(info);
    }
}

Result<AuthStatus> Session::try_authenticate(std::initializer_list<const Authenticator*> chain) {
    AuthStatus last = AuthStatus::denied;
    for (const auto* a : chain) {
        auto r = try_authenticate(*a);
        if (!r) return r;
        last = *r;
        if (last == AuthStatus::success) return last;
    }
    return last;
}

Result<Channel> Session::try_open_channel() {
    if (!core_) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Session::try_open_channel"};
    ssh_channel raw = ssh_channel_new(core_->raw());
    if (raw == nullptr) {
        return detail::make_error_info(core_->raw(), "ssh_channel_new", SSHPP_HERE, errc::channel_open_failed);
    }
    Channel ch(raw, core_, true);
    auto r = ch.try_open_session();
    if (!r) return r.error();
    return ch;
}

Channel Session::open_channel() { return try_open_channel().value(); }

void Session::set_log_level(LogLevel level) {
    if (!core_) return;
    (void)level;
}

} // namespace sshpp
