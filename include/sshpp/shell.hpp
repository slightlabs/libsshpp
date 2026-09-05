// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Interactive shell sessions. See docs/design/05 §5.4. try_interact() (the
// terminal raw-mode relay loop) is only declared/compiled when
// LIBSSHPP_WITH_CONSOLE=ON, since it needs termios and installs a SIGWINCH
// handler - a library embedded in a server has no business doing either.
#pragma once

#include <sshpp/config.hpp>

#include <sshpp/channel.hpp>
#include <sshpp/error.hpp>
#include <sshpp/export.hpp>
#include <sshpp/fwd.hpp>
#include <sshpp/result.hpp>
#include <sshpp/types.hpp>

#include <chrono>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace sshpp {

#if SSHPP_WITH_CONSOLE
/// Options for Shell::try_interact(). "~." (at the start of a line) detaches
/// without closing the remote shell's exit status collection, matching the
/// familiar OpenSSH escape.
struct InteractOptions {
    bool        enable_escape = true;
    char        escape_char = '~';
};
#endif

/// An interactive channel: pty + shell requests, then either manual
/// try_write()/try_read() or (with LIBSSHPP_WITH_CONSOLE) a full terminal relay.
class SSHPP_API Shell {
public:
    struct Options {
        std::string term = "xterm-256color";
        PtySize     size{};
        std::vector<std::pair<std::string, std::string>> env;
        bool        request_pty = true;
    };

    Shell(Session&, Options options);

    Result<void> try_start();
    Channel&     channel() noexcept { return channel_; }

    Result<std::size_t> try_write(std::string_view data);
    Result<std::string> try_read(std::chrono::milliseconds timeout, Stream stream = Stream::stdout_);
    Result<void>        try_resize(PtySize);
    Result<void>        try_send_signal(Signal);

#if SSHPP_WITH_CONSOLE
    /// Blocking bidirectional relay between the shell and local stdin/stdout.
    /// Puts the local terminal in raw mode for the duration of the call and
    /// restores it (even on error/exception) before returning. Resizes the
    /// remote pty on SIGWINCH. Only available when LIBSSHPP_WITH_CONSOLE=ON.
    Result<ExitState> try_interact(InteractOptions options = {});
#endif

private:
    Session* session_;
    Options   options_;
    Channel    channel_;
};

} // namespace sshpp

#if SSHPP_HEADER_ONLY
#include <sshpp/detail/shell.ipp>
#endif
