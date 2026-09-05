// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include <sshpp/config.hpp>

#include <sshpp/channel.hpp>
#include <sshpp/export.hpp>
#include <sshpp/fwd.hpp>
#include <sshpp/result.hpp>
#include <sshpp/session.hpp>
#include <sshpp/types.hpp>

#include <chrono>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace sshpp {

struct ExecResult {
    int                         exit_code = -1;
    std::optional<std::string> exit_signal;
    std::string                stdout_text;
    std::string                stderr_text;
    bool                        stdout_truncated = false;
    bool                        stderr_truncated = false;

    explicit operator bool() const noexcept { return exit_code == 0; }
    /// Throws ChannelError with the captured stderr if exit_code != 0.
    const ExecResult& check() const;
};

using OutputSink = std::function<void(Stream, ByteView)>;

/// One-shot remote command execution: opens a channel, requests exec, pumps
/// stdout/stderr without stalling on the interleaving hazard, waits for exit.
/// See docs/design/05 §5.3.
class SSHPP_API Exec {
public:
    explicit Exec(Session& session) : session_(session) {}

    Exec& env(std::string_view name, std::string_view value);
    Exec& pty(bool enable = true, std::string_view term = "xterm-256color", PtySize size = {});
    Exec& stdin_data(std::string data);
    Exec& timeout(std::chrono::milliseconds t) { timeout_ = t; return *this; }
    Exec& max_output(std::size_t bytes) { max_output_ = bytes; return *this; }
    Exec& merge_stderr(bool v = true) { merge_stderr_ = v; return *this; }
    Exec& sink(OutputSink s) { sink_ = std::move(s); return *this; }

    Result<ExecResult> try_run(std::string_view command);
    ExecResult         run(std::string_view command);

    /// Builds an argv-style command with correct POSIX shell quoting.
    Result<ExecResult> try_run(const std::vector<std::string>& argv);

private:
    Session&                                       session_;
    std::vector<std::pair<std::string, std::string>> env_;
    bool                                            pty_ = false;
    std::string                                     pty_term_ = "xterm-256color";
    PtySize                                         pty_size_{};
    std::optional<std::string>                      stdin_data_;
    std::optional<std::chrono::milliseconds>        timeout_;
    std::size_t                                     max_output_ = 16u << 20;
    bool                                             merge_stderr_ = false;
    OutputSink                                       sink_;
};

/// Escapes a single argument for a POSIX shell.
SSHPP_API std::string shell_quote(std::string_view arg);

} // namespace sshpp

#if SSHPP_HEADER_ONLY
#include <sshpp/detail/exec.ipp>
#endif
