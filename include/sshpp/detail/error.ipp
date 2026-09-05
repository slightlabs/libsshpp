// SPDX-License-Identifier: LGPL-2.1-or-later
// Generated from src/error.cpp; see docs/design/09 §9.3.
#include <sshpp/config.hpp>
// SPDX-License-Identifier: LGPL-2.1-or-later
#include <sshpp/error.hpp>

#include <sstream>

namespace sshpp {

namespace {

class SshCategory final : public std::error_category {
public:
    const char* name() const noexcept override { return "sshpp::ssh"; }

    std::string message(int ev) const override {
        switch (static_cast<errc>(ev)) {
            case errc::ok: return "ok";
            case errc::fatal: return "fatal transport error";
            case errc::request_denied: return "request denied";
            case errc::interrupted: return "interrupted";
            case errc::would_block: return "would block";
            case errc::timed_out: return "timed out";
            case errc::cancelled: return "cancelled";
            case errc::not_connected: return "not connected";
            case errc::already_connected: return "already connected";
            case errc::connection_lost: return "connection lost";
            case errc::protocol_error: return "protocol error";
            case errc::banner_exchange_failed: return "banner exchange failed";
            case errc::key_exchange_failed: return "key exchange failed";
            case errc::rekey_failed: return "rekey failed";
            case errc::host_key_unknown: return "host key unknown";
            case errc::host_key_changed: return "host key changed";
            case errc::host_key_type_mismatch: return "host key type mismatch";
            case errc::host_key_rejected: return "host key rejected";
            case errc::known_hosts_io_error: return "known_hosts I/O error";
            case errc::auth_denied: return "authentication denied";
            case errc::auth_partial: return "authentication partial";
            case errc::auth_method_unavailable: return "authentication method unavailable";
            case errc::auth_no_more_methods: return "no more authentication methods";
            case errc::passphrase_required: return "passphrase required";
            case errc::passphrase_incorrect: return "passphrase incorrect";
            case errc::agent_unavailable: return "ssh-agent unavailable";
            case errc::gssapi_error: return "GSSAPI error";
            case errc::key_import_failed: return "key import failed";
            case errc::key_export_failed: return "key export failed";
            case errc::key_generation_failed: return "key generation failed";
            case errc::unsupported_key_type: return "unsupported key type";
            case errc::channel_open_failed: return "channel open failed";
            case errc::channel_closed: return "channel closed";
            case errc::channel_eof: return "channel EOF";
            case errc::channel_request_failed: return "channel request failed";
            case errc::pty_request_failed: return "PTY request failed";
            case errc::sftp_unavailable: return "SFTP unavailable";
            case errc::scp_error: return "SCP error";
            case errc::forwarding_failed: return "forwarding failed";
            case errc::x11_failed: return "X11 forwarding failed";
            case errc::invalid_handle: return "invalid (moved-from/released) handle";
            case errc::invalid_argument: return "invalid argument";
            case errc::unsupported_operation: return "unsupported by linked libssh";
            case errc::out_of_memory: return "out of memory";
            case errc::unknown: return "unknown error";
        }
        return "unrecognized sshpp::errc";
    }

    std::error_condition default_error_condition(int ev) const noexcept override {
        switch (static_cast<errc>(ev)) {
            case errc::timed_out: return std::errc::timed_out;
            case errc::would_block: return std::errc::operation_would_block;
            case errc::interrupted: return std::errc::interrupted;
            case errc::cancelled: return std::errc::operation_canceled;
            case errc::connection_lost: return std::errc::connection_aborted;
            case errc::not_connected: return std::errc::not_connected;
            case errc::invalid_argument: return std::errc::invalid_argument;
            case errc::out_of_memory: return std::errc::not_enough_memory;
            case errc::unsupported_operation: return std::errc::function_not_supported;
            case errc::auth_denied: return std::errc::permission_denied;
            default: return std::error_condition(ev, *this);
        }
    }
};

class SftpCategory final : public std::error_category {
public:
    const char* name() const noexcept override { return "sshpp::sftp"; }

    std::string message(int ev) const override {
        switch (static_cast<sftp_errc>(ev)) {
            case sftp_errc::ok: return "ok";
            case sftp_errc::eof: return "EOF";
            case sftp_errc::no_such_file: return "no such file";
            case sftp_errc::permission_denied: return "permission denied";
            case sftp_errc::failure: return "failure";
            case sftp_errc::bad_message: return "bad message";
            case sftp_errc::no_connection: return "no connection";
            case sftp_errc::connection_lost: return "connection lost";
            case sftp_errc::op_unsupported: return "operation unsupported";
            case sftp_errc::invalid_handle: return "invalid handle";
            case sftp_errc::no_such_path: return "no such path";
            case sftp_errc::file_already_exists: return "file already exists";
            case sftp_errc::write_protect: return "write protected";
            case sftp_errc::no_media: return "no media";
            case sftp_errc::invalid_parameter: return "invalid parameter";
        }
        return "unrecognized sshpp::sftp_errc";
    }

    std::error_condition default_error_condition(int ev) const noexcept override {
        switch (static_cast<sftp_errc>(ev)) {
            case sftp_errc::permission_denied: return std::errc::permission_denied;
            case sftp_errc::no_such_file:
            case sftp_errc::no_such_path: return std::errc::no_such_file_or_directory;
            case sftp_errc::file_already_exists: return std::errc::file_exists;
            default: return std::error_condition(ev, *this);
        }
    }
};

} // namespace

SSHPP_INLINE const std::error_category& ssh_category() noexcept {
    static const SshCategory instance;
    return instance;
}

SSHPP_INLINE const std::error_category& sftp_category() noexcept {
    static const SftpCategory instance;
    return instance;
}

SSHPP_INLINE std::error_code make_error_code(errc e) noexcept { return {static_cast<int>(e), ssh_category()}; }
SSHPP_INLINE std::error_code make_error_code(sftp_errc e) noexcept { return {static_cast<int>(e), sftp_category()}; }

SSHPP_INLINE std::string ErrorInfo::to_string() const {
    std::ostringstream os;
    if (operation && *operation) os << operation << ": ";
    if (!message.empty()) {
        os << message;
    } else {
        os << code.message();
    }
    os << " [" << code.category().name() << ':' << code.message() << ']';
    return os.str();
}

SSHPP_INLINE Error::Error(ErrorInfo info)
    : std::system_error(info.code, info.message.empty() ? info.code.message() : info.message),
      info_(std::move(info)) {}

SSHPP_INLINE void throw_error(ErrorInfo info) {
    if (info.code.category() == ssh_category()) {
        switch (static_cast<errc>(info.code.value())) {
            case errc::timed_out:
                throw TimeoutError(std::move(info));
            case errc::cancelled:
                throw CancelledError(std::move(info));
            case errc::fatal:
            case errc::request_denied:
            case errc::interrupted:
            case errc::not_connected:
            case errc::already_connected:
            case errc::connection_lost:
            case errc::protocol_error:
            case errc::banner_exchange_failed:
            case errc::key_exchange_failed:
            case errc::rekey_failed:
                throw ConnectionError(std::move(info));
            case errc::host_key_unknown:
            case errc::host_key_changed:
            case errc::host_key_type_mismatch:
            case errc::host_key_rejected:
            case errc::known_hosts_io_error:
                throw HostKeyError(std::move(info));
            case errc::auth_denied:
            case errc::auth_partial:
            case errc::auth_method_unavailable:
            case errc::auth_no_more_methods:
            case errc::passphrase_required:
            case errc::passphrase_incorrect:
            case errc::agent_unavailable:
            case errc::gssapi_error:
                throw AuthError(std::move(info));
            case errc::key_import_failed:
            case errc::key_export_failed:
            case errc::key_generation_failed:
            case errc::unsupported_key_type:
                throw KeyError(std::move(info));
            case errc::channel_open_failed:
            case errc::channel_closed:
            case errc::channel_eof:
            case errc::channel_request_failed:
            case errc::pty_request_failed:
                throw ChannelError(std::move(info));
            case errc::sftp_unavailable:
                throw SftpError(std::move(info));
            case errc::scp_error:
                throw ScpError(std::move(info));
            case errc::forwarding_failed:
            case errc::x11_failed:
                throw ForwardingError(std::move(info));
            case errc::invalid_handle:
            case errc::invalid_argument:
            case errc::unsupported_operation:
                throw UsageError(std::move(info));
            case errc::ok:
            case errc::would_block:
            case errc::out_of_memory:
            case errc::unknown:
            default:
                throw Error(std::move(info));
        }
    }
    if (info.code.category() == sftp_category()) {
        throw SftpError(std::move(info));
    }
    throw Error(std::move(info));
}

} // namespace sshpp
