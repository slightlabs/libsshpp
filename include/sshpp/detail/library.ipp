// SPDX-License-Identifier: LGPL-2.1-or-later
// Generated from src/library.cpp; see docs/design/09 §9.3.
#include <sshpp/config.hpp>
// SPDX-License-Identifier: LGPL-2.1-or-later
#include <sshpp/config.hpp>
#include <sshpp/library.hpp>

#include <libssh/callbacks.h>
#include <libssh/libssh.h>

#include <atomic>
#include <mutex>

namespace sshpp {

namespace detail {

// C++17 inline variables: these MUST have true external linkage merged by the
// linker across every translation unit, not per-TU internal linkage. In
// SSHPP_HEADER_ONLY mode, library.ipp is #included by every .cpp that pulls in
// <sshpp/library.hpp> (potentially many translation units linked into one
// binary); an anonymous namespace here would silently give each TU its own
// separate copy of the ssh_init()/ssh_finalize() refcount, so one TU's last
// Library could call ssh_finalize() while another TU's Session is still
// relying on libssh being initialized - previously observed as an
// unreproducible-looking hang specific to header-only builds with several
// integration test translation units in one executable.
inline std::mutex           g_library_mutex;
inline int                   g_library_refcount = 0;
inline LogLevel              g_library_log_level = LogLevel::none;
inline LogCallback           g_library_log_callback;
inline Library::DestructorErrorHandler g_library_destructor_handler;

} // namespace detail

namespace {

LogLevel level_from_native(int level) {
    switch (level) {
        case SSH_LOG_WARNING: return LogLevel::warning;
        case SSH_LOG_INFO:    return LogLevel::info;
        case SSH_LOG_DEBUG:   return LogLevel::debug;
        case SSH_LOG_TRACE:   return LogLevel::trace;
        default:              return LogLevel::none;
    }
}

int level_to_native(LogLevel level) {
    switch (level) {
        case LogLevel::warning: return SSH_LOG_WARNING;
        case LogLevel::info:    return SSH_LOG_INFO;
        case LogLevel::debug:   return SSH_LOG_DEBUG;
        case LogLevel::trace:   return SSH_LOG_TRACE;
        case LogLevel::none:
        default:                return SSH_LOG_NONE;
    }
}

void log_trampoline(int priority, const char* function, const char* buffer, void* /*userdata*/) {
    LogCallback cb;
    {
        std::lock_guard<std::mutex> lock(detail::g_library_mutex);
        cb = detail::g_library_log_callback;
    }
    if (!cb) return;
    try {
        cb(LogRecord{level_from_native(priority), function, buffer ? buffer : ""});
    } catch (...) {
        // Exceptions must not propagate into libssh's C frames.
    }
}

} // namespace

SSHPP_INLINE Library::Library() : Library(Config{}) {}

SSHPP_INLINE Library::Library(const Config& cfg) {
    std::lock_guard<std::mutex> lock(detail::g_library_mutex);
    if (detail::g_library_refcount == 0) {
        ssh_init();
        if (cfg.install_threading_callbacks) {
            ssh_threads_set_callbacks(ssh_threads_get_pthread());
        }
    }
    ++detail::g_library_refcount;
    owns_ = true;

    if (cfg.log_level != LogLevel::none) {
        detail::g_library_log_level = cfg.log_level;
        ssh_set_log_level(level_to_native(cfg.log_level));
    }
    if (cfg.log_callback) {
        detail::g_library_log_callback = cfg.log_callback;
        ssh_set_log_callback(log_trampoline);
    }
}

SSHPP_INLINE Library::~Library() {
    if (!owns_) return;
    std::lock_guard<std::mutex> lock(detail::g_library_mutex);
    --detail::g_library_refcount;
    if (detail::g_library_refcount == 0) {
        ssh_finalize();
    }
}

SSHPP_INLINE Library::Library(const Library&) {
    std::lock_guard<std::mutex> lock(detail::g_library_mutex);
    ++detail::g_library_refcount;
    owns_ = true;
}

SSHPP_INLINE Library& Library::operator=(const Library& other) {
    if (this == &other) return *this;
    Library tmp(other);
    std::swap(owns_, tmp.owns_);
    return *this;
}

SSHPP_INLINE Library::Library(Library&& other) noexcept : owns_(other.owns_) { other.owns_ = false; }

SSHPP_INLINE Library& Library::operator=(Library&& other) noexcept {
    if (this == &other) return *this;
    if (owns_) {
        std::lock_guard<std::mutex> lock(detail::g_library_mutex);
        --detail::g_library_refcount;
        if (detail::g_library_refcount == 0) ssh_finalize();
    }
    owns_ = other.owns_;
    other.owns_ = false;
    return *this;
}

SSHPP_INLINE bool Library::initialized() noexcept {
    std::lock_guard<std::mutex> lock(detail::g_library_mutex);
    return detail::g_library_refcount > 0;
}

SSHPP_INLINE Features Library::features() {
    Features f;
    f.libssh_version = ssh_version(0) ? ssh_version(0) : "";
    f.libssh_version_int = LIBSSH_VERSION_INT;
    f.sftp = true;
    f.server = true;
#if SSHPP_HAS_SFTP_AIO
    f.sftp_aio = true;
#endif
#if SSHPP_HAS_CHANNEL_EXIT_STATE
    f.channel_exit_state = true;
#endif
#if SSHPP_HAS_GSSAPI
    f.gssapi = true;
#endif
    return f;
}

SSHPP_INLINE std::string Library::version_string() {
    std::string v = "libsshpp ";
    v += SSHPP_VERSION_STRING;
    v += " (libssh ";
    v += ssh_version(0) ? ssh_version(0) : "unknown";
    v += ")";
    return v;
}

SSHPP_INLINE void Library::set_log_level(LogLevel level) {
    std::lock_guard<std::mutex> lock(detail::g_library_mutex);
    detail::g_library_log_level = level;
    ssh_set_log_level(level_to_native(level));
}

SSHPP_INLINE LogLevel Library::log_level() noexcept {
    std::lock_guard<std::mutex> lock(detail::g_library_mutex);
    return detail::g_library_log_level;
}

SSHPP_INLINE void Library::set_log_callback(LogCallback cb) {
    std::lock_guard<std::mutex> lock(detail::g_library_mutex);
    detail::g_library_log_callback = std::move(cb);
    ssh_set_log_callback(detail::g_library_log_callback ? log_trampoline : nullptr);
}

SSHPP_INLINE void Library::set_destructor_error_handler(DestructorErrorHandler handler) {
    std::lock_guard<std::mutex> lock(detail::g_library_mutex);
    detail::g_library_destructor_handler = std::move(handler);
}

SSHPP_INLINE void Library::report_destructor_error(ErrorInfo info) noexcept {
    DestructorErrorHandler handler;
    {
        std::lock_guard<std::mutex> lock(detail::g_library_mutex);
        handler = detail::g_library_destructor_handler;
    }
    if (!handler) return;
    try {
        handler(info);
    } catch (...) {
    }
}

} // namespace sshpp
