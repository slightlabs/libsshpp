// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Internal helpers shared by the .cpp files that talk to libssh directly.
// Not part of the public API.
#pragma once

#include <sshpp/config.hpp>

#include <sshpp/detail/native_fwd.hpp>
#include <sshpp/error.hpp>

namespace sshpp::detail {

/// Snapshots ssh_get_error()/ssh_get_error_code() for `session` into an ErrorInfo,
/// mapping the libssh error code to the closest sshpp::errc.
ErrorInfo make_error_info(native_session session, const char* operation, SourceLocation where,
                          errc fallback = errc::unknown);

/// Maps a raw SSH_AUTH_* result to sshpp::errc for error paths (success/partial are not errors).
errc errc_from_auth_result(int auth_result) noexcept;

/// Snapshots sftp_get_error()/ssh_get_error() for an SFTP failure into an ErrorInfo.
ErrorInfo make_sftp_error_info(native_sftp sftp, native_session session, const char* operation,
                               SourceLocation where);

} // namespace sshpp::detail

#if SSHPP_HEADER_ONLY
#include <sshpp/detail/invoke.ipp>
#endif
