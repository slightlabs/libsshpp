// SPDX-License-Identifier: LGPL-2.1-or-later
// Generated from src/exec.cpp; see docs/design/09 §9.3.
#include <sshpp/config.hpp>
// SPDX-License-Identifier: LGPL-2.1-or-later
#include <sshpp/exec.hpp>

#include <algorithm>
#include <chrono>

namespace sshpp {

SSHPP_INLINE const ExecResult& ExecResult::check() const {
    if (exit_code != 0) {
        ErrorInfo info;
        info.operation = "ExecResult::check";
        info.code = make_error_code(errc::channel_request_failed);
        info.message = "command exited with status " + std::to_string(exit_code) +
                       (stderr_text.empty() ? "" : (": " + stderr_text));
        throw_error(info);
    }
    return *this;
}

SSHPP_INLINE Exec& Exec::env(std::string_view name, std::string_view value) {
    env_.emplace_back(std::string(name), std::string(value));
    return *this;
}

SSHPP_INLINE Exec& Exec::pty(bool enable, std::string_view term, PtySize size) {
    pty_ = enable;
    pty_term_ = std::string(term);
    pty_size_ = size;
    return *this;
}

SSHPP_INLINE Exec& Exec::stdin_data(std::string data) {
    stdin_data_ = std::move(data);
    return *this;
}

SSHPP_INLINE Result<ExecResult> Exec::try_run(std::string_view command) {
    auto channel_result = session_.try_open_channel();
    if (!channel_result) return channel_result.error();
    Channel ch = std::move(*channel_result);

    for (const auto& [name, value] : env_) {
        auto r = ch.try_request_env(name, value);
        (void)r; // servers commonly reject env requests outside AcceptEnv; not fatal
    }

    if (pty_) {
        auto r = ch.try_request_pty(pty_term_, pty_size_);
        if (!r) return r.error();
    }

    auto exec_result = ch.try_request_exec(command);
    if (!exec_result) return exec_result.error();

    if (stdin_data_) {
        auto r = ch.try_write_all(std::string_view(*stdin_data_));
        if (!r) return r.error();
    }
    (void)ch.try_send_eof();

    ExecResult result;
    std::vector<std::byte> chunk(16384);
    auto deadline = timeout_ ? std::chrono::steady_clock::now() + *timeout_
                             : std::chrono::steady_clock::time_point::max();

    while (true) {
        bool progressed = false;

        auto avail_out = ch.try_bytes_available(Stream::stdout_);
        if (avail_out && *avail_out > 0) {
            auto r = ch.try_read_some(MutableByteView(chunk.data(), chunk.size()), Stream::stdout_);
            if (!r) return r.error();
            if (*r > 0) {
                progressed = true;
                if (sink_) {
                    sink_(Stream::stdout_, ByteView(chunk.data(), *r));
                } else if (result.stdout_text.size() < max_output_) {
                    result.stdout_text.append(reinterpret_cast<const char*>(chunk.data()), *r);
                } else {
                    result.stdout_truncated = true;
                }
            }
        }

        auto avail_err = ch.try_bytes_available(Stream::stderr_);
        if (avail_err && *avail_err > 0) {
            auto r = ch.try_read_some(MutableByteView(chunk.data(), chunk.size()), Stream::stderr_);
            if (!r) return r.error();
            if (*r > 0) {
                progressed = true;
                std::string& dst = merge_stderr_ ? result.stdout_text : result.stderr_text;
                bool& truncated = merge_stderr_ ? result.stdout_truncated : result.stderr_truncated;
                if (sink_) {
                    sink_(Stream::stderr_, ByteView(chunk.data(), *r));
                } else if (dst.size() < max_output_) {
                    dst.append(reinterpret_cast<const char*>(chunk.data()), *r);
                } else {
                    truncated = true;
                }
            }
        }

        if (ch.is_eof() && (!avail_out || *avail_out == 0) && (!avail_err || *avail_err == 0)) {
            break;
        }
        if (!progressed) {
            (void)ch.try_wait_readable(std::chrono::milliseconds(50), Stream::stdout_);
        }
        if (timeout_ && std::chrono::steady_clock::now() > deadline) {
            ErrorInfo info;
            info.operation = "Exec::try_run";
            info.code = make_error_code(errc::timed_out);
            return info;
        }
    }

    auto exit_st = ch.try_wait_exit(std::chrono::milliseconds(5000));
    (void)ch.try_close();

    if (exit_st) {
        result.exit_code = exit_st->status.value_or(-1);
        result.exit_signal = exit_st->signal;
    }
    return result;
}

SSHPP_INLINE ExecResult Exec::run(std::string_view command) { return try_run(command).value(); }

SSHPP_INLINE Result<ExecResult> Exec::try_run(const std::vector<std::string>& argv) {
    std::string command;
    for (const auto& arg : argv) {
        if (!command.empty()) command += ' ';
        command += shell_quote(arg);
    }
    return try_run(command);
}

SSHPP_INLINE std::string shell_quote(std::string_view arg) {
    if (!arg.empty() && arg.find_first_not_of(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-./,:@%^+=") ==
            std::string_view::npos) {
        return std::string(arg);
    }
    std::string quoted = "'";
    for (char c : arg) {
        if (c == '\'') {
            quoted += "'\\''";
        } else {
            quoted += c;
        }
    }
    quoted += '\'';
    return quoted;
}

} // namespace sshpp
