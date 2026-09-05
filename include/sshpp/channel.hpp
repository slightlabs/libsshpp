// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include <sshpp/config.hpp>
#include <sshpp/detail/native_fwd.hpp>
#include <sshpp/detail/session_core.hpp>
#include <sshpp/export.hpp>
#include <sshpp/fwd.hpp>
#include <sshpp/result.hpp>
#include <sshpp/types.hpp>

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace sshpp {

enum class Stream { stdout_, stderr_ };

enum class Signal { abrt, alrm, fpe, hup, ill, int_, kill, pipe, quit, segv, term, usr1, usr2 };

struct ExitState {
    std::optional<int>         status;
    std::optional<std::string> signal;
    bool                       core_dumped = false;
    std::string                error_message;
};

struct PtySize { int columns = 80; int rows = 24; };

/// A single SSH channel: exec/shell/pty/subsystem I/O multiplexed over a Session.
/// See docs/design/05 §5.1.
class SSHPP_API Channel {
public:
    Channel() = default;
    ~Channel();
    Channel(Channel&&) noexcept;
    Channel& operator=(Channel&&) noexcept;
    Channel(const Channel&) = delete;
    Channel& operator=(const Channel&) = delete;

    explicit operator bool() const noexcept { return native_ != nullptr; }
    native_channel native_handle() const noexcept { return native_; }
    static Channel from_native(native_channel, detail::SessionCorePtr, Ownership);

    // ---- opening --------------------------------------------------------
    Result<void> try_open_session();
    bool is_open() const noexcept { return open_; }

    // ---- requests --------------------------------------------------------
    Result<void> try_request_pty(std::string_view term = "xterm-256color", PtySize = {});
    Result<void> try_change_pty_size(PtySize);
    Result<void> try_request_shell();
    Result<void> try_request_exec(std::string_view command);
    Result<void> try_request_subsystem(std::string_view name);
    Result<void> try_request_env(std::string_view name, std::string_view value);
    Result<void> try_send_signal(Signal);

    // ---- I/O ---------------------------------------------------------------
    Result<std::size_t> try_read_some(MutableByteView buf, Stream = Stream::stdout_);
    Result<std::size_t> try_read_some(MutableByteView buf, Stream, std::chrono::milliseconds timeout);
    Result<std::string> try_read_all(Stream = Stream::stdout_, std::size_t limit = 64u << 20);

    Result<std::size_t> try_write_some(ByteView data);
    Result<void>        try_write_all(ByteView data);
    Result<void>        try_write_all(std::string_view data);

    Result<std::size_t> try_bytes_available(Stream = Stream::stdout_) const;
    Result<bool>        try_wait_readable(std::chrono::milliseconds, Stream = Stream::stdout_);

    // ---- closing --------------------------------------------------------------
    Result<void> try_send_eof();
    bool         is_eof() const noexcept;
    Result<void> try_close();
    bool         is_closed() const noexcept { return !open_; }

    // ---- exit status -----------------------------------------------------------
    Result<ExitState> try_wait_exit(std::chrono::milliseconds timeout = std::chrono::milliseconds::max());
    ExitState         exit_state() const noexcept;

#if SSHPP_WITH_FORWARDING
    // ---- forwarding factories (see docs/design/07) ---------------------------------
    static Result<Channel> open_forward(Session&, std::string_view remote_host, std::uint16_t remote_port,
                                        std::string_view origin_host, std::uint16_t origin_port);
    static Result<Channel> open_forward_unix(Session&, std::string_view remote_socket,
                                             std::string_view origin_host, std::uint16_t origin_port);
#endif

private:
    Channel(native_channel n, detail::SessionCorePtr core, bool owning)
        : native_(n), core_(std::move(core)), owning_(owning) {}

    friend class Session;

    native_channel        native_ = nullptr;
    detail::SessionCorePtr core_;
    bool                  owning_ = true;
    bool                  open_ = false;
};

} // namespace sshpp
