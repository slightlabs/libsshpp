// SPDX-License-Identifier: LGPL-2.1-or-later
// Generated from src/invoke.cpp; see docs/design/09 §9.3.
#include <sshpp/config.hpp>
// SPDX-License-Identifier: LGPL-2.1-or-later
#include <sshpp/detail/invoke.hpp>

#include <libssh/libssh.h>
#include <libssh/sftp.h>

namespace sshpp::detail {

namespace {
static_assert(std::is_same_v<native_session, ssh_session>, "libssh changed ssh_session's definition");
static_assert(std::is_same_v<native_sftp, sftp_session>, "libssh changed sftp_session's definition");
} // namespace

SSHPP_INLINE ErrorInfo make_error_info(native_session session, const char* operation, SourceLocation where,
                          errc fallback) {
    ErrorInfo info;
    info.operation = operation;
    info.where = where;

    errc mapped = fallback;
    if (session != nullptr) {
        info.message = ssh_get_error(session);
        int code = ssh_get_error_code(session);
        switch (code) {
            case SSH_NO_ERROR: mapped = fallback; break;
            case SSH_REQUEST_DENIED: mapped = errc::request_denied; break;
            case SSH_FATAL: mapped = errc::fatal; break;
            case SSH_EINTR: mapped = errc::interrupted; break;
            default: mapped = fallback; break;
        }
    }
    info.code = make_error_code(mapped);
    return info;
}

SSHPP_INLINE errc errc_from_auth_result(int auth_result) noexcept {
    switch (auth_result) {
        case SSH_AUTH_DENIED: return errc::auth_denied;
        case SSH_AUTH_PARTIAL: return errc::auth_partial;
        case SSH_AUTH_AGAIN: return errc::would_block;
        case SSH_AUTH_ERROR: return errc::fatal;
        default: return errc::auth_denied;
    }
}

SSHPP_INLINE ErrorInfo make_sftp_error_info(native_sftp sftp, native_session session, const char* operation,
                               SourceLocation where) {
    ErrorInfo info;
    info.operation = operation;
    info.where = where;
    int status = sftp != nullptr ? sftp_get_error(sftp) : SSH_FX_FAILURE;
    info.code = make_error_code(static_cast<sftp_errc>(status));
    if (session != nullptr) {
        info.message = ssh_get_error(session);
    }
    return info;
}

} // namespace sshpp::detail
