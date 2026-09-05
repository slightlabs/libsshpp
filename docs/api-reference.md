# API Reference

The full, generated API reference (every public class, function, and enum in
[include/sshpp/](https://github.com/slightlabs/libsshpp/tree/main/include/sshpp)) is built with
Doxygen and published alongside this site — see the [Doxygen API reference](api/index.html).

## Quick orientation

| Header | Contents |
|---|---|
| `<sshpp/sshpp.hpp>` | Umbrella header pulling in the whole public API |
| `<sshpp/library.hpp>` | `Library` — process-wide libssh init/teardown guard |
| `<sshpp/error.hpp>` | `errc`, `sftp_errc`, `ErrorInfo`, `Result<T>`, exception hierarchy |
| `<sshpp/session.hpp>`, `<sshpp/session_options.hpp>` | `Session`, `SessionOptions` |
| `<sshpp/auth.hpp>` | Authenticators: `Password`, `PublicKeyAuto`, `KeyboardInteractive`, ... |
| `<sshpp/key.hpp>`, `<sshpp/known_hosts.hpp>` | `Key`, PKI helpers, `KnownHosts`, `HostKeyVerifier` policies |
| `<sshpp/channel.hpp>`, `<sshpp/exec.hpp>`, `<sshpp/shell.hpp>` | `Channel`, `Exec`, `Shell`, PTY |
| `<sshpp/event.hpp>` | `Event` — poll-loop integration |
| `<sshpp/sftp/*.hpp>` | `sftp::Sftp`, `sftp::File`, `sftp::DirectoryIterator`, attributes |
| `<sshpp/scp/*.hpp>` | `scp::Reader`, `scp::Writer` |
| `<sshpp/forwarding/*.hpp>` | `LocalForward`, `RemoteForward`, `X11Forwarder`, `SocksProxy` |
| `<sshpp/server/*.hpp>` | `server::Bind`, `server::Session`, `server::Message`, callback handlers, `server::TestServer` |

For per-module design rationale (why the API looks the way it does), see the matching
[Design](design/README.md) document — each header above maps to one of `docs/design/04` through
`docs/design/08`.
