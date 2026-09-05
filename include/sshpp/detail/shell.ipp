// SPDX-License-Identifier: LGPL-2.1-or-later
// Generated from src/shell.cpp; see docs/design/09 §9.3.
#include <sshpp/config.hpp>
#include <sshpp/shell.hpp>
#include <sshpp/session.hpp>

#include <array>

#if SSHPP_WITH_CONSOLE
#include <algorithm>
#include <array>
#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <poll.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>
#endif

namespace sshpp {

SSHPP_INLINE Shell::Shell(Session& session, Options options) : session_(&session), options_(std::move(options)) {}

SSHPP_INLINE Result<void> Shell::try_start() {
    auto ch = session_->try_open_channel();
    if (!ch) return ch.error();
    channel_ = std::move(*ch);

    if (options_.request_pty) {
        auto pty = channel_.try_request_pty(options_.term, options_.size);
        if (!pty) return pty;
    }
    for (const auto& [name, value] : options_.env) {
        (void)channel_.try_request_env(name, value); // servers may reject individual vars; not fatal
    }
    return channel_.try_request_shell();
}

SSHPP_INLINE Result<std::size_t> Shell::try_write(std::string_view data) {
    auto r = channel_.try_write_all(data);
    if (!r) return r.error();
    return data.size();
}

SSHPP_INLINE Result<std::string> Shell::try_read(std::chrono::milliseconds timeout, Stream stream) {
    std::array<std::byte, 16384> buf{};
    auto n = channel_.try_read_some(MutableByteView(buf.data(), buf.size()), stream, timeout);
    if (!n) return n.error();
    return std::string(reinterpret_cast<const char*>(buf.data()), *n);
}

SSHPP_INLINE Result<void> Shell::try_resize(PtySize size) {
    options_.size = size;
    return channel_.try_change_pty_size(size);
}

SSHPP_INLINE Result<void> Shell::try_send_signal(Signal s) { return channel_.try_send_signal(s); }

#if SSHPP_WITH_CONSOLE

namespace {

std::atomic<bool> g_sigwinch_received{false};
void on_sigwinch(int) { g_sigwinch_received.store(true); }

/// RAII terminal raw-mode toggle for fd 0 (stdin). Restores the original
/// mode on destruction so a thrown exception or early return never leaves
/// the user's terminal broken.
class RawMode {
public:
    RawMode() {
        if (::tcgetattr(STDIN_FILENO, &saved_) != 0) return;
        valid_ = true;
        termios raw = saved_;
        ::cfmakeraw(&raw);
        ::tcsetattr(STDIN_FILENO, TCSANOW, &raw);
    }
    ~RawMode() {
        if (valid_) ::tcsetattr(STDIN_FILENO, TCSANOW, &saved_);
    }
    RawMode(const RawMode&) = delete;

private:
    termios saved_{};
    bool     valid_ = false;
};

PtySize current_terminal_size() {
    winsize ws{};
    if (::ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0 && ws.ws_row > 0) {
        return PtySize{ws.ws_col, ws.ws_row};
    }
    return PtySize{};
}

} // namespace

SSHPP_INLINE Result<ExitState> Shell::try_interact(InteractOptions options) {
    RawMode raw_mode;

    struct sigaction sa{};
    sa.sa_handler = &on_sigwinch;
    struct sigaction old_sa{};
    ::sigaction(SIGWINCH, &sa, &old_sa);
    g_sigwinch_received.store(false);

    bool at_line_start = true;
    bool escape_seen = false;
    bool detach = false;

    while (!detach && channel_.is_open() && !channel_.is_eof()) {
        if (g_sigwinch_received.exchange(false)) {
            (void)try_resize(current_terminal_size());
        }

        auto avail = channel_.try_bytes_available(Stream::stdout_);
        if (avail && *avail > 0) {
            std::array<std::byte, 16384> buf{};
            auto n = channel_.try_read_some(MutableByteView(buf.data(), std::min(buf.size(), *avail)));
            if (n && *n > 0) {
                ::write(STDOUT_FILENO, buf.data(), *n);
            }
        }
        auto avail_err = channel_.try_bytes_available(Stream::stderr_);
        if (avail_err && *avail_err > 0) {
            std::array<std::byte, 16384> buf{};
            auto n = channel_.try_read_some(MutableByteView(buf.data(), std::min(buf.size(), *avail_err)),
                                           Stream::stderr_);
            if (n && *n > 0) {
                ::write(STDERR_FILENO, buf.data(), *n);
            }
        }

        auto readable = channel_.try_wait_readable(std::chrono::milliseconds(20));
        (void)readable;

        // Poll local stdin without blocking the remote-output pump above.
        pollfd pfd{STDIN_FILENO, POLLIN, 0};
        if (::poll(&pfd, 1, 0) > 0 && (pfd.revents & POLLIN) != 0) {
            char c = 0;
            ssize_t n = ::read(STDIN_FILENO, &c, 1);
            if (n <= 0) break;
            if (options.enable_escape) {
                if (at_line_start && c == options.escape_char) {
                    escape_seen = true;
                    at_line_start = false;
                    continue;
                }
                if (escape_seen) {
                    escape_seen = false;
                    if (c == '.') {
                        detach = true;
                        continue;
                    }
                    // Not a recognised escape sequence: forward both bytes.
                    (void)channel_.try_write_all(std::string_view(&options.escape_char, 1));
                }
            }
            at_line_start = (c == '\n' || c == '\r');
            (void)channel_.try_write_all(std::string_view(&c, 1));
        }
    }

    ::sigaction(SIGWINCH, &old_sa, nullptr);

    if (detach) return ExitState{};
    auto exit_state = channel_.try_wait_exit(std::chrono::milliseconds(2000));
    return exit_state ? Result<ExitState>(*exit_state) : Result<ExitState>(channel_.exit_state());
}

#endif // SSHPP_WITH_CONSOLE

} // namespace sshpp
