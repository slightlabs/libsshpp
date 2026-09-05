// SPDX-License-Identifier: LGPL-2.1-or-later
// Generated from src/channel.cpp; see docs/design/09 §9.3.
#include <sshpp/config.hpp>
// SPDX-License-Identifier: LGPL-2.1-or-later
#include <sshpp/channel.hpp>
#include <sshpp/detail/invoke.hpp>

#include <libssh/libssh.h>
#if SSHPP_WITH_SERVER
#include <libssh/server.h>
#endif

#include <algorithm>
#include <type_traits>

namespace sshpp {

namespace {
static_assert(std::is_same_v<native_channel, ssh_channel>, "libssh changed ssh_channel's definition");

const char* signal_name(Signal s) {
    switch (s) {
        case Signal::abrt: return "ABRT";
        case Signal::alrm: return "ALRM";
        case Signal::fpe: return "FPE";
        case Signal::hup: return "HUP";
        case Signal::ill: return "ILL";
        case Signal::int_: return "INT";
        case Signal::kill: return "KILL";
        case Signal::pipe: return "PIPE";
        case Signal::quit: return "QUIT";
        case Signal::segv: return "SEGV";
        case Signal::term: return "TERM";
        case Signal::usr1: return "USR1";
        case Signal::usr2: return "USR2";
    }
    return "TERM";
}

} // namespace

SSHPP_INLINE Channel::~Channel() {
    if (native_ != nullptr && owning_) {
        if (open_ && !ssh_channel_is_closed(native_)) {
            ssh_channel_close(native_);
        }
        ssh_channel_free(native_);
    }
    native_ = nullptr;
}

SSHPP_INLINE Channel::Channel(Channel&& other) noexcept
    : native_(std::exchange(other.native_, nullptr)),
      core_(std::move(other.core_)),
      owning_(other.owning_),
      open_(std::exchange(other.open_, false)) {}

SSHPP_INLINE Channel& Channel::operator=(Channel&& other) noexcept {
    if (this != &other) {
        if (native_ != nullptr && owning_) {
            if (open_ && !ssh_channel_is_closed(native_)) ssh_channel_close(native_);
            ssh_channel_free(native_);
        }
        native_ = std::exchange(other.native_, nullptr);
        core_ = std::move(other.core_);
        owning_ = other.owning_;
        open_ = std::exchange(other.open_, false);
    }
    return *this;
}

SSHPP_INLINE Channel Channel::from_native(native_channel n, detail::SessionCorePtr core, Ownership o) {
    Channel ch(n, std::move(core), o == Ownership::owning);
    ch.open_ = n != nullptr && ssh_channel_is_open(n) != 0;
    return ch;
}

SSHPP_INLINE Result<void> Channel::try_open_session() {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Channel::try_open_session"};
    int rc = ssh_channel_open_session(native_);
    if (rc != SSH_OK) {
        return detail::make_error_info(core_->raw(), "ssh_channel_open_session", SSHPP_HERE, errc::channel_open_failed);
    }
    open_ = true;
    return {};
}

SSHPP_INLINE Result<void> Channel::try_request_pty(std::string_view term, PtySize size) {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Channel::try_request_pty"};
    std::string term_str(term);
    int rc = ssh_channel_request_pty_size(native_, term_str.c_str(), size.columns, size.rows);
    if (rc != SSH_OK) {
        return detail::make_error_info(core_->raw(), "ssh_channel_request_pty_size", SSHPP_HERE, errc::pty_request_failed);
    }
    return {};
}

SSHPP_INLINE Result<void> Channel::try_change_pty_size(PtySize size) {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Channel::try_change_pty_size"};
    int rc = ssh_channel_change_pty_size(native_, size.columns, size.rows);
    if (rc != SSH_OK) {
        return detail::make_error_info(core_->raw(), "ssh_channel_change_pty_size", SSHPP_HERE, errc::pty_request_failed);
    }
    return {};
}

SSHPP_INLINE Result<void> Channel::try_request_shell() {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Channel::try_request_shell"};
    int rc = ssh_channel_request_shell(native_);
    if (rc != SSH_OK) {
        return detail::make_error_info(core_->raw(), "ssh_channel_request_shell", SSHPP_HERE, errc::channel_request_failed);
    }
    return {};
}

SSHPP_INLINE Result<void> Channel::try_request_exec(std::string_view command) {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Channel::try_request_exec"};
    std::string cmd(command);
    int rc = ssh_channel_request_exec(native_, cmd.c_str());
    if (rc != SSH_OK) {
        return detail::make_error_info(core_->raw(), "ssh_channel_request_exec", SSHPP_HERE, errc::channel_request_failed);
    }
    return {};
}

SSHPP_INLINE Result<void> Channel::try_request_subsystem(std::string_view name) {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Channel::try_request_subsystem"};
    std::string n(name);
    int rc = ssh_channel_request_subsystem(native_, n.c_str());
    if (rc != SSH_OK) {
        return detail::make_error_info(core_->raw(), "ssh_channel_request_subsystem", SSHPP_HERE, errc::channel_request_failed);
    }
    return {};
}

SSHPP_INLINE Result<void> Channel::try_request_env(std::string_view name, std::string_view value) {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Channel::try_request_env"};
    std::string n(name), v(value);
    int rc = ssh_channel_request_env(native_, n.c_str(), v.c_str());
    if (rc != SSH_OK) {
        return detail::make_error_info(core_->raw(), "ssh_channel_request_env", SSHPP_HERE, errc::channel_request_failed);
    }
    return {};
}

SSHPP_INLINE Result<void> Channel::try_send_signal(Signal s) {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Channel::try_send_signal"};
    int rc = ssh_channel_request_send_signal(native_, signal_name(s));
    if (rc != SSH_OK) {
        return detail::make_error_info(core_->raw(), "ssh_channel_request_send_signal", SSHPP_HERE, errc::channel_request_failed);
    }
    return {};
}

SSHPP_INLINE Result<std::size_t> Channel::try_read_some(MutableByteView buf, Stream stream) {
    return try_read_some(buf, stream, std::chrono::milliseconds(-1));
}

SSHPP_INLINE Result<std::size_t> Channel::try_read_some(MutableByteView buf, Stream stream,
                                           std::chrono::milliseconds timeout) {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Channel::try_read_some"};
    int is_stderr = stream == Stream::stderr_ ? 1 : 0;
    int timeout_ms = timeout.count() < 0 ? -1 : static_cast<int>(timeout.count());
    int rc = ssh_channel_read_timeout(native_, buf.data(), static_cast<uint32_t>(buf.size()), is_stderr, timeout_ms);
    if (rc < 0) {
        return detail::make_error_info(core_->raw(), "ssh_channel_read_timeout", SSHPP_HERE, errc::channel_closed);
    }
    return static_cast<std::size_t>(rc);
}

SSHPP_INLINE Result<std::string> Channel::try_read_all(Stream stream, std::size_t limit) {
    std::string result;
    std::vector<std::byte> chunk(16384);
    for (;;) {
        auto r = try_read_some(MutableByteView(chunk.data(), chunk.size()), stream);
        if (!r) return r.error();
        if (*r == 0) break;
        result.append(reinterpret_cast<const char*>(chunk.data()), *r);
        if (result.size() >= limit) break;
    }
    return result;
}

SSHPP_INLINE Result<std::size_t> Channel::try_write_some(ByteView data) {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Channel::try_write_some"};
    int rc = ssh_channel_write(native_, data.data(), static_cast<uint32_t>(data.size()));
    if (rc < 0) {
        return detail::make_error_info(core_->raw(), "ssh_channel_write", SSHPP_HERE, errc::channel_closed);
    }
    return static_cast<std::size_t>(rc);
}

SSHPP_INLINE Result<std::size_t> Channel::try_write_some(ByteView data, Stream stream) {
    if (stream == Stream::stdout_) return try_write_some(data);
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Channel::try_write_some"};
    int rc = ssh_channel_write_stderr(native_, data.data(), static_cast<uint32_t>(data.size()));
    if (rc < 0) {
        return detail::make_error_info(core_->raw(), "ssh_channel_write_stderr", SSHPP_HERE, errc::channel_closed);
    }
    return static_cast<std::size_t>(rc);
}

SSHPP_INLINE Result<void> Channel::try_write_all(ByteView data) {
    std::size_t written = 0;
    while (written < data.size()) {
        ByteView remaining(data.data() + written, data.size() - written);
        auto r = try_write_some(remaining);
        if (!r) return r.error();
        if (*r == 0) {
            return ErrorInfo{make_error_code(errc::channel_closed), "short write", "Channel::try_write_all"};
        }
        written += *r;
    }
    return {};
}

SSHPP_INLINE Result<void> Channel::try_write_all(ByteView data, Stream stream) {
    std::size_t written = 0;
    while (written < data.size()) {
        ByteView remaining(data.data() + written, data.size() - written);
        auto r = try_write_some(remaining, stream);
        if (!r) return r.error();
        if (*r == 0) {
            return ErrorInfo{make_error_code(errc::channel_closed), "short write", "Channel::try_write_all"};
        }
        written += *r;
    }
    return {};
}

SSHPP_INLINE Result<void> Channel::try_write_all(std::string_view data) {
    return try_write_all(ByteView(data));
}

SSHPP_INLINE Result<void> Channel::try_write_all(std::string_view data, Stream stream) {
    return try_write_all(ByteView(data), stream);
}

SSHPP_INLINE Result<std::size_t> Channel::try_bytes_available(Stream stream) const {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Channel::try_bytes_available"};
    int is_stderr = stream == Stream::stderr_ ? 1 : 0;
    int rc = ssh_channel_poll_timeout(native_, 0, is_stderr);
    if (rc < 0) {
        return detail::make_error_info(core_->raw(), "ssh_channel_poll_timeout", SSHPP_HERE, errc::channel_closed);
    }
    return static_cast<std::size_t>(rc);
}

SSHPP_INLINE Result<bool> Channel::try_wait_readable(std::chrono::milliseconds timeout, Stream stream) {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Channel::try_wait_readable"};
    int is_stderr = stream == Stream::stderr_ ? 1 : 0;
    int rc = ssh_channel_poll_timeout(native_, static_cast<int>(timeout.count()), is_stderr);
    if (rc < 0) {
        return detail::make_error_info(core_->raw(), "ssh_channel_poll_timeout", SSHPP_HERE, errc::channel_closed);
    }
    return rc > 0;
}

SSHPP_INLINE Result<void> Channel::try_send_eof() {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Channel::try_send_eof"};
    int rc = ssh_channel_send_eof(native_);
    if (rc != SSH_OK) {
        return detail::make_error_info(core_->raw(), "ssh_channel_send_eof", SSHPP_HERE, errc::channel_request_failed);
    }
    return {};
}

SSHPP_INLINE bool Channel::is_eof() const noexcept { return native_ != nullptr && ssh_channel_is_eof(native_) != 0; }

SSHPP_INLINE Result<void> Channel::try_close() {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Channel::try_close"};
    int rc = ssh_channel_close(native_);
    open_ = false;
    if (rc != SSH_OK) {
        return detail::make_error_info(core_->raw(), "ssh_channel_close", SSHPP_HERE, errc::channel_request_failed);
    }
    return {};
}

SSHPP_INLINE Result<ExitState> Channel::try_wait_exit(std::chrono::milliseconds timeout) {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Channel::try_wait_exit"};

    // Drain both streams to EOF; libssh only reports the exit status once the peer's
    // output has been fully read. See docs/design/05 §5.1 notes.
    std::vector<std::byte> sink(16384);
    auto deadline_ms = timeout.count();
    for (int guard = 0; guard < 1'000'000 && !ssh_channel_is_eof(native_) && !ssh_channel_is_closed(native_); ++guard) {
        int timeout_ms = deadline_ms < 0 ? 1000 : static_cast<int>(std::min<long long>(deadline_ms, 1000));
        ssh_channel_read_timeout(native_, sink.data(), static_cast<uint32_t>(sink.size()), 0, timeout_ms);
        ssh_channel_read_timeout(native_, sink.data(), static_cast<uint32_t>(sink.size()), 1, timeout_ms);
    }
    return exit_state();
}

SSHPP_INLINE ExitState Channel::exit_state() const noexcept {
    ExitState st;
    if (native_ == nullptr) return st;
#if SSHPP_HAS_CHANNEL_EXIT_STATE
    uint32_t exit_code = 0;
    char* exit_signal = nullptr;
    int core_dumped = 0;
    int rc = ssh_channel_get_exit_state(native_, &exit_code, &exit_signal, &core_dumped);
    if (rc == SSH_OK) {
        if (exit_signal != nullptr) {
            st.signal = exit_signal;
            st.core_dumped = core_dumped != 0;
            ssh_string_free_char(exit_signal);
        } else {
            st.status = static_cast<int>(exit_code);
        }
    }
#else
    int status = ssh_channel_get_exit_status(native_);
    if (status >= 0) {
        st.status = status;
    }
#endif
    return st;
}

#if SSHPP_WITH_SERVER
SSHPP_INLINE Result<void> Channel::try_send_exit_status(int code) {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Channel::try_send_exit_status"};
    if (ssh_channel_request_send_exit_status(native_, code) != SSH_OK) {
        return detail::make_error_info(ssh_channel_get_session(native_), "ssh_channel_request_send_exit_status",
                                       SSHPP_HERE, errc::channel_request_failed);
    }
    return {};
}
#endif

} // namespace sshpp
