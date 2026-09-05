// SPDX-License-Identifier: LGPL-2.1-or-later
#include <sshpp/config.hpp>
#include <sshpp/library.hpp>

#include <libssh/callbacks.h>
#include <libssh/libssh.h>

#include <atomic>
#include <mutex>

namespace sshpp {

namespace {

std::mutex           g_mutex;
int                   g_refcount = 0;
LogLevel              g_log_level = LogLevel::none;
LogCallback           g_log_callback;
Library::DestructorErrorHandler g_destructor_handler;

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
        std::lock_guard<std::mutex> lock(g_mutex);
        cb = g_log_callback;
    }
    if (!cb) return;
    try {
        cb(LogRecord{level_from_native(priority), function, buffer ? buffer : ""});
    } catch (...) {
        // Exceptions must not propagate into libssh's C frames.
    }
}

} // namespace

Library::Library() : Library(Config{}) {}

Library::Library(const Config& cfg) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_refcount == 0) {
        ssh_init();
        if (cfg.install_threading_callbacks) {
            ssh_threads_set_callbacks(ssh_threads_get_pthread());
        }
    }
    ++g_refcount;
    owns_ = true;

    if (cfg.log_level != LogLevel::none) {
        g_log_level = cfg.log_level;
        ssh_set_log_level(level_to_native(cfg.log_level));
    }
    if (cfg.log_callback) {
        g_log_callback = cfg.log_callback;
        ssh_set_log_callback(log_trampoline);
    }
}

Library::~Library() {
    if (!owns_) return;
    std::lock_guard<std::mutex> lock(g_mutex);
    --g_refcount;
    if (g_refcount == 0) {
        ssh_finalize();
    }
}

Library::Library(const Library&) {
    std::lock_guard<std::mutex> lock(g_mutex);
    ++g_refcount;
    owns_ = true;
}

Library& Library::operator=(const Library& other) {
    if (this == &other) return *this;
    Library tmp(other);
    std::swap(owns_, tmp.owns_);
    return *this;
}

Library::Library(Library&& other) noexcept : owns_(other.owns_) { other.owns_ = false; }

Library& Library::operator=(Library&& other) noexcept {
    if (this == &other) return *this;
    if (owns_) {
        std::lock_guard<std::mutex> lock(g_mutex);
        --g_refcount;
        if (g_refcount == 0) ssh_finalize();
    }
    owns_ = other.owns_;
    other.owns_ = false;
    return *this;
}

bool Library::initialized() noexcept {
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_refcount > 0;
}

Features Library::features() {
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

std::string Library::version_string() {
    std::string v = "libsshpp ";
    v += SSHPP_VERSION_STRING;
    v += " (libssh ";
    v += ssh_version(0) ? ssh_version(0) : "unknown";
    v += ")";
    return v;
}

void Library::set_log_level(LogLevel level) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_log_level = level;
    ssh_set_log_level(level_to_native(level));
}

LogLevel Library::log_level() noexcept {
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_log_level;
}

void Library::set_log_callback(LogCallback cb) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_log_callback = std::move(cb);
    ssh_set_log_callback(g_log_callback ? log_trampoline : nullptr);
}

void Library::set_destructor_error_handler(DestructorErrorHandler handler) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_destructor_handler = std::move(handler);
}

void Library::report_destructor_error(ErrorInfo info) noexcept {
    DestructorErrorHandler handler;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        handler = g_destructor_handler;
    }
    if (!handler) return;
    try {
        handler(info);
    } catch (...) {
    }
}

} // namespace sshpp
