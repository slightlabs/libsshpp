// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include <sshpp/config.hpp>

#include <sshpp/export.hpp>
#include <sshpp/error.hpp>

#include <functional>
#include <string>
#include <vector>

namespace sshpp {

enum class LogLevel { none = 0, warning, info, debug, trace };

struct LogRecord {
    LogLevel    level;
    const char* function;
    std::string message;
};

using LogCallback = std::function<void(const LogRecord&)>;

struct Features {
    std::string libssh_version;
    int  libssh_version_int = 0;
    bool zlib = false;
    bool gssapi = false;
    bool sftp = false;
    bool server = false;
    bool sftp_aio = false;
    bool control_master = false;
    bool channel_exit_state = false;
    std::vector<std::string> ciphers, kex, macs, public_key_algorithms;
};

/// RAII guard around ssh_init()/ssh_finalize(). Reference-counted and thread-safe.
/// At least one instance must be alive for the whole time any other sshpp object exists.
/// See docs/design/04 §4.1.
class SSHPP_API Library {
public:
    struct Config {
        bool        install_threading_callbacks = true;
        LogLevel    log_level = LogLevel::none;
        LogCallback log_callback{};
    };

    Library();
    explicit Library(const Config&);
    ~Library();
    Library(const Library&);
    Library& operator=(const Library&);
    Library(Library&&) noexcept;
    Library& operator=(Library&&) noexcept;

    static bool initialized() noexcept;
    static Features features();
    static std::string version_string();

    static void set_log_level(LogLevel);
    static LogLevel log_level() noexcept;
    static void set_log_callback(LogCallback);

    using DestructorErrorHandler = std::function<void(const ErrorInfo&)>;
    static void set_destructor_error_handler(DestructorErrorHandler);

    /// Invokes the installed destructor-error handler (or does nothing by default).
    /// Used internally by other wrapper destructors that cannot throw.
    static void report_destructor_error(ErrorInfo) noexcept;

private:
    bool owns_ = false;
};

} // namespace sshpp

#if SSHPP_HEADER_ONLY
#include <sshpp/detail/library.ipp>
#endif
