# 05 — Channels API

Header: `<sshpp/channel.hpp>`, `<sshpp/channel_stream.hpp>`, `<sshpp/exec.hpp>`,
`<sshpp/shell.hpp>`, `<sshpp/event.hpp>`.

## 5.1 `Channel` — the Layer-3 primitive

```cpp
namespace sshpp {

enum class Stream { stdout_, stderr_ };

/// Signals accepted by ssh_channel_request_send_signal (RFC 4254 §6.10, no "SIG" prefix).
enum class Signal { abrt, alrm, fpe, hup, ill, int_, kill, pipe, quit, segv, term, usr1, usr2 };

struct ExitState {
    std::optional<int>         status;        // exit-status
    std::optional<std::string> signal;        // exit-signal, e.g. "TERM"
    bool                       core_dumped = false;
    std::string                error_message;
};

struct PtySize { int columns = 80; int rows = 24; };

class SSHPP_API Channel {
public:
    Channel() = default;                       // empty
    ~Channel();                                // close + ssh_channel_free
    Channel(Channel&&) noexcept;
    Channel& operator=(Channel&&) noexcept;
    Channel(const Channel&) = delete;

    explicit operator bool() const noexcept;
    native_channel native_handle() const noexcept;
    static Channel from_native(native_channel, const Session&, Ownership);
    Session session() const;                   // strong ref to the owning session

    // ---- opening --------------------------------------------------------
    Result<void> try_open_session();           // ssh_channel_open_session
    bool is_open() const noexcept;

    // ---- requests --------------------------------------------------------
    Result<void> try_request_pty(std::string_view term = "xterm-256color",
                                 PtySize = {});
    Result<void> try_change_pty_size(PtySize);
    Result<void> try_request_shell();
    Result<void> try_request_exec(std::string_view command);
    Result<void> try_request_subsystem(std::string_view name);   // e.g. "sftp", "netconf"
    Result<void> try_request_env(std::string_view name, std::string_view value);
    Result<void> try_request_x11(const X11Request&);             // see doc 07
    Result<void> try_send_signal(Signal);
    Result<void> try_send_break(std::chrono::milliseconds);      // ssh_channel_request_send_break

    // ---- I/O ---------------------------------------------------------------
    /// Blocking read of up to buf.size() bytes. Returns 0 on EOF.
    Result<std::size_t> try_read_some(MutableByteView buf, Stream = Stream::stdout_);
    Result<std::size_t> try_read_some(MutableByteView buf, Stream,
                                      std::chrono::milliseconds timeout);
    /// Never blocks; returns 0 if nothing buffered.
    Result<std::size_t> try_read_available(MutableByteView buf, Stream = Stream::stdout_);
    /// Reads exactly buf.size() bytes or fails with channel_eof / timed_out.
    Result<void>        try_read_exact(MutableByteView buf, Stream = Stream::stdout_);
    /// Reads until EOF. `limit` guards against unbounded memory use.
    Result<std::string> try_read_all(Stream = Stream::stdout_,
                                     std::size_t limit = 64u << 20);

    Result<std::size_t> try_write_some(ByteView data);            // may write less
    Result<void>        try_write_all(ByteView data);             // loops
    Result<void>        try_write_all(std::string_view data);
    Result<std::size_t> try_write_stderr(ByteView data);          // server side only

    /// Bytes immediately readable; errc::channel_eof when the peer closed the stream.
    Result<std::size_t> try_bytes_available(Stream = Stream::stdout_) const;
    Result<bool>        try_wait_readable(std::chrono::milliseconds,
                                          Stream = Stream::stdout_);

    // ---- closing --------------------------------------------------------------
    Result<void> try_send_eof();
    bool         is_eof() const noexcept;                         // peer sent EOF
    Result<void> try_close();
    bool         is_closed() const noexcept;

    // ---- exit status -----------------------------------------------------------
    /// Blocks until the remote command exits (or the channel closes).
    Result<ExitState> try_wait_exit(std::chrono::milliseconds timeout =
                                    std::chrono::milliseconds::max());
    /// Non-blocking snapshot; `status` is nullopt if not yet received.
    ExitState exit_state() const noexcept;

    // ---- forwarding factories (see doc 07) ---------------------------------------
    static Result<Channel> open_forward(Session&, std::string_view remote_host,
                                        std::uint16_t remote_port,
                                        std::string_view origin_host, std::uint16_t origin_port);
    static Result<Channel> open_forward_unix(Session&, std::string_view remote_socket,
                                             std::string_view origin_host, std::uint16_t origin_port);
};

} // namespace sshpp
```

### Design notes

* `exit_state()` uses `ssh_channel_get_exit_state()` when the linked libssh is ≥ 0.11
  (`SSHPP_HAS_CHANNEL_EXIT_STATE`), falling back to `ssh_channel_get_exit_status()` otherwise —
  in the fallback, `ExitState::signal` is always `nullopt` and this is documented.
* `try_wait_exit()` implements the required drain: libssh only surfaces the exit status once the
  channel has been read to EOF, so `try_wait_exit` loops on `ssh_channel_read_timeout` for both
  streams, discarding data, until EOF or close. A `[[nodiscard]]` warning plus a runtime
  diagnostic fires if unread data is discarded, because that is usually a bug — use
  `Exec` (§5.3) instead.
* `try_read_some` with `Stream::stderr_` maps to `ssh_channel_read_timeout(..., is_stderr=1)`.
* **Interleaving hazard.** libssh multiplexes stdout/stderr over one channel; reading only
  stdout can stall if the peer fills the stderr window. `Exec` and `ChannelPump` (§5.5) read
  both via `ssh_channel_select`/`ssh_event`, and the `Channel` docs warn about the single-stream
  loop.
* `try_write_all` handles short writes and `SSH_AGAIN`.
* Destructor order: `try_close()` then `ssh_channel_free()`. Failures go to the destructor error
  handler.

## 5.2 `<sshpp/channel_stream.hpp>` — iostream adapters

Thin, opt-in, Layer-4:

```cpp
namespace sshpp {

class SSHPP_API ChannelStreambuf final : public std::streambuf {
public:
    ChannelStreambuf(Channel&, Stream read_from = Stream::stdout_,
                     std::size_t buffer_size = 16 * 1024);
    // underflow/overflow/sync implemented over Channel::try_read_some / try_write_some.
    // Errors set the associated stream's badbit AND are retrievable via last_error().
    const ErrorInfo& last_error() const noexcept;
};

class SSHPP_API ChannelIStream final : public std::istream { /* owns a streambuf */ };
class SSHPP_API ChannelOStream final : public std::ostream { /* flush() -> write + sync */ };
class SSHPP_API ChannelIOStream final : public std::iostream {};

} // namespace sshpp
```

Rationale: iostreams cannot report `ErrorInfo`, so they are explicitly a convenience for
line-oriented protocols (`std::getline` over a subsystem channel). `last_error()` preserves the
detail. They are not used internally by any other part of the library.

## 5.3 `<sshpp/exec.hpp>` — one-shot remote commands

The single most common use case gets a dedicated, hard-to-misuse type.

```cpp
namespace sshpp {

struct ExecResult {
    int          exit_code = -1;
    std::optional<std::string> exit_signal;
    std::string  stdout_text;
    std::string  stderr_text;
    bool         stdout_truncated = false;
    bool         stderr_truncated = false;

    explicit operator bool() const noexcept { return exit_code == 0; }
    /// Throws ChannelError with the captured stderr if exit_code != 0.
    const ExecResult& check() const;
};

/// Sink callbacks for streaming instead of buffering.
using OutputSink = std::function<void(Stream, ByteView)>;

class SSHPP_API Exec {
public:
    explicit Exec(Session&);

    Exec& env(std::string_view name, std::string_view value);   // channel "env" requests
    Exec& pty(bool enable = true, std::string_view term = "xterm-256color", PtySize = {});
    Exec& stdin_data(std::string data);                          // written then EOF
    Exec& stdin_stream(std::istream&);
    Exec& timeout(std::chrono::milliseconds);
    Exec& max_output(std::size_t bytes);                         // default 16 MiB per stream
    Exec& merge_stderr(bool = true);                             // stderr appended to stdout_text
    Exec& sink(OutputSink);                                      // disables buffering

    Result<ExecResult> try_run(std::string_view command);
    ExecResult         run(std::string_view command);

    /// Builds an argv-style command with correct POSIX shell quoting.
    Result<ExecResult> try_run(std::vector<std::string> argv);
};

/// Escapes a single argument for a POSIX shell. Exposed because callers need it.
SSHPP_API std::string shell_quote(std::string_view);

} // namespace sshpp
```

Security note (OWASP A03 — Injection): `Exec::run(std::string_view)` passes the string to the
remote shell verbatim. The `std::vector<std::string> argv` overload applies `shell_quote` to
every element and is the documented default recommendation for any command built from
untrusted input. Documentation and the header both carry this warning; examples use the argv
form.

`Exec` internally:

1. opens a channel, applies `env`/`pty` requests,
2. `request_exec`,
3. runs a select-driven pump over stdout, stderr and (if provided) stdin,
4. sends EOF on stdin, waits for EOF on both output streams,
5. closes and collects `ExitState`.

This is the loop most users get wrong; it exists once, here.

## 5.4 `<sshpp/shell.hpp>` — interactive sessions

```cpp
namespace sshpp {

class SSHPP_API Shell {
public:
    struct Options {
        std::string term = "xterm-256color";
        PtySize     size{};
        std::vector<std::pair<std::string, std::string>> env;
        bool        request_pty = true;
    };

    Shell(Session&, Options = {});

    Result<void> try_start();                       // pty + shell requests
    Channel&     channel() noexcept;                // full access for advanced use

    Result<std::size_t> try_write(std::string_view);
    Result<std::string> try_read(std::chrono::milliseconds timeout, Stream = Stream::stdout_);
    Result<void>        try_resize(PtySize);
    Result<void>        try_send_signal(Signal);

    /// Blocking bidirectional relay between the shell and local stdin/stdout.
    /// Handles terminal raw-mode, SIGWINCH-driven resize, and ~. escape.
    /// Only available when LIBSSHPP_WITH_CONSOLE=ON.
    Result<ExitState> try_interact(InteractOptions = {});
};

} // namespace sshpp
```

`try_interact()` is what makes a usable `ssh` clone; it is deliberately isolated behind a build
option because it needs `termios`/`SetConsoleMode` and signal handling that a library embedded
in a server has no business installing.

## 5.5 `<sshpp/event.hpp>` — poll integration

`ssh_event` is the seam for integrating with an external event loop (and the basis of the
future async layer).

```cpp
namespace sshpp {

enum class PollFlags : unsigned { none = 0, in = 1, pri = 2, out = 4, err = 8, hup = 16 };
SSHPP_API PollFlags operator|(PollFlags, PollFlags) noexcept;   // + &, ~, etc.

class SSHPP_API Event {
public:
    Event();                                        // ssh_event_new
    ~Event();

    Result<void> try_add_session(Session&);
    Result<void> try_remove_session(Session&);
    Result<void> try_add_fd(int fd, PollFlags, std::function<PollFlags(int, PollFlags)> cb);
    Result<void> try_remove_fd(int fd);
    Result<void> try_add_connector(/* ssh_connector, see doc 07 */);

    /// SSH_OK / SSH_AGAIN(timeout) / SSH_ERROR.
    Result<void> try_poll(std::chrono::milliseconds timeout);
};

/// Copies bytes in both directions between two things (channel<->fd, channel<->channel)
/// using ssh_connector under the hood. The building block of port forwarding.
class SSHPP_API Connector { /* see doc 07 §7.5 */ };

/// Convenience: waits until any of the given channels has data, using ssh_channel_select.
SSHPP_API Result<std::vector<Channel*>> select_channels(
    std::vector<Channel*> read_set, std::chrono::milliseconds timeout);

} // namespace sshpp
```

For users on Asio/libuv/Qt: `Session::socket_fd()` plus `Session::try_set_blocking(false)` and
the `errc::would_block` contract is enough to drive libssh from a foreign loop; a worked example
is shipped in `examples/` but no dependency on those libraries is taken.

## 5.6 Examples

Run a command safely:

```cpp
auto r = sshpp::Exec{session}
             .timeout(std::chrono::seconds{30})
             .try_run(std::vector<std::string>{"grep", "-r", user_supplied, "/var/log"});
if (!r) return fail(r.error());
if (r->exit_code != 0) std::cerr << r->stderr_text;
```

Stream a large output without buffering:

```cpp
std::ofstream out{"dump.bin", std::ios::binary};
sshpp::Exec{session}
    .sink([&](sshpp::Stream s, sshpp::ByteView b) {
        if (s == sshpp::Stream::stdout_)
            out.write(reinterpret_cast<const char*>(b.data()),
                      static_cast<std::streamsize>(b.size()));
    })
    .run("cat /var/lib/backup.tar");
```

Raw channel, subsystem:

```cpp
auto ch = session.open_channel();
ch.try_request_subsystem("netconf").value();
sshpp::ChannelIOStream io{ch};
io << hello_message << std::flush;
std::string line;
std::getline(io, line);
```
