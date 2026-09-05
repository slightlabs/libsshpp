// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include <sshpp/config.hpp>

#include <sshpp/export.hpp>

#include <string>
#include <system_error>

namespace sshpp {

/// Minimal std::source_location-like shim (this library targets C++17).
struct SourceLocation {
    const char* file     = "";
    int         line     = 0;
    const char* function = "";
};

#define SSHPP_HERE ::sshpp::SourceLocation{__FILE__, __LINE__, __func__}

enum class errc : int {
    ok = 0,

    // --- transport / session -------------------------------------------
    fatal,
    request_denied,
    interrupted,
    would_block,
    timed_out,
    cancelled,
    not_connected,
    already_connected,
    connection_lost,
    protocol_error,
    banner_exchange_failed,
    key_exchange_failed,
    rekey_failed,

    // --- host key ------------------------------------------------------
    host_key_unknown,
    host_key_changed,
    host_key_type_mismatch,
    host_key_rejected,
    known_hosts_io_error,

    // --- authentication ---------------------------------------------------
    auth_denied,
    auth_partial,
    auth_method_unavailable,
    auth_no_more_methods,
    passphrase_required,
    passphrase_incorrect,
    agent_unavailable,
    gssapi_error,

    // --- keys ---------------------------------------------------------------
    key_import_failed,
    key_export_failed,
    key_generation_failed,
    unsupported_key_type,

    // --- channels ---------------------------------------------------------------
    channel_open_failed,
    channel_closed,
    channel_eof,
    channel_request_failed,
    pty_request_failed,

    // --- subsystems -----------------------------------------------------------------
    sftp_unavailable,
    scp_error,
    forwarding_failed,
    x11_failed,

    // --- wrapper-level -------------------------------------------------------------------
    invalid_handle,
    invalid_argument,
    unsupported_operation,
    out_of_memory,
    unknown,
};

enum class sftp_errc : int {
    ok = 0,
    eof = 1,
    no_such_file = 2,
    permission_denied = 3,
    failure = 4,
    bad_message = 5,
    no_connection = 6,
    connection_lost = 7,
    op_unsupported = 8,
    invalid_handle = 9,
    no_such_path = 10,
    file_already_exists = 11,
    write_protect = 12,
    no_media = 13,
    invalid_parameter = 14,
};

SSHPP_API const std::error_category& ssh_category() noexcept;
SSHPP_API const std::error_category& sftp_category() noexcept;

SSHPP_API std::error_code make_error_code(errc e) noexcept;
SSHPP_API std::error_code make_error_code(sftp_errc e) noexcept;

} // namespace sshpp

namespace std {
template <> struct is_error_code_enum<sshpp::errc>      : true_type {};
template <> struct is_error_code_enum<sshpp::sftp_errc> : true_type {};
} // namespace std

namespace sshpp {

/// Captures the libssh textual reason at the point of failure, before any other
/// call can overwrite ssh_get_error(). See docs/design/03 §3.3.
struct SSHPP_API ErrorInfo {
    std::error_code code{};
    std::string     message;
    const char*     operation = "";
    SourceLocation  where{};

    [[nodiscard]] std::string to_string() const;
    explicit operator bool() const noexcept { return static_cast<bool>(code); }
};

class SSHPP_API Error : public std::system_error {
public:
    explicit Error(ErrorInfo info);

    const ErrorInfo&      info() const noexcept { return info_; }
    const char*           operation() const noexcept { return info_.operation; }
    const SourceLocation& where() const noexcept { return info_.where; }

private:
    ErrorInfo info_;
};

class SSHPP_API ConnectionError : public Error { using Error::Error; };
class SSHPP_API TimeoutError    : public ConnectionError { using ConnectionError::ConnectionError; };
class SSHPP_API CancelledError  : public ConnectionError { using ConnectionError::ConnectionError; };

class SSHPP_API HostKeyError : public Error { using Error::Error; };
class SSHPP_API AuthError    : public Error { using Error::Error; };
class SSHPP_API KeyError     : public Error { using Error::Error; };
class SSHPP_API ChannelError : public Error { using Error::Error; };
class SSHPP_API SftpError    : public Error { using Error::Error; };
class SSHPP_API ScpError     : public Error { using Error::Error; };
class SSHPP_API ForwardingError : public ChannelError { using ChannelError::ChannelError; };
class SSHPP_API ServerError  : public Error { using Error::Error; };
class SSHPP_API UsageError   : public Error { using Error::Error; };

/// Throws the exception subclass matching info.code's category/value.
/// The single place that translates an ErrorInfo into a thrown exception.
[[noreturn]] SSHPP_API void throw_error(ErrorInfo info);

} // namespace sshpp

#if SSHPP_HEADER_ONLY
#include <sshpp/detail/error.ipp>
#endif
