# libsshpp — Design Documentation

`libsshpp` is a modern C++17 wrapper around [libssh](https://www.libssh.org/) (the LGPL 2.1
SSHv2 client/server library), packaged with CMake and Conan 2.

This directory contains the complete design of the library. It is written **before**
implementation and is the normative reference for the public API, the build system and the
packaging story. Anything not described here is out of scope for `v1.0`.

## Reading order

| # | Document | Contents |
|---|----------|----------|
| 01 | [Goals and scope](01-goals-and-scope.md) | Motivation, non-goals, requirements, supported platforms and libssh versions |
| 02 | [Architecture](02-architecture.md) | Layering, ownership/lifetime model, threading, directory layout, naming conventions |
| 03 | [Error handling](03-error-handling.md) | `error_code`, `error_category`, `Error` hierarchy, `Result<T>`, dual throwing/non-throwing API |
| 04 | [Core API — library, session, auth, keys, host keys](04-api-core.md) | `Library`, `Session`, `SessionOptions`, authenticators, `Key`, `KnownHosts`, `HostKeyVerifier` |
| 05 | [Channels API](05-api-channels.md) | `Channel`, `Exec`, `Shell`, PTY, streams, `Event` polling |
| 06 | [SFTP and SCP API](06-api-sftp-scp.md) | `sftp::Sftp`, `sftp::File`, `sftp::DirectoryIterator`, attributes, `scp::Reader`/`scp::Writer` |
| 07 | [Port forwarding and X11](07-api-forwarding.md) | Local (direct-tcpip), remote (tcpip-forward), UNIX sockets, X11, ready-made pumps |
| 08 | [Server API](08-api-server.md) | `server::Bind`, `server::Session`, message loop, callback handlers, in-process test server |
| 09 | [Build and packaging](09-build-and-packaging.md) | CMake targets/options, install & export, header-only mode, Conan 2 recipe, presets, FetchContent/CPM |
| 10 | [Testing and CI](10-testing-and-ci.md) | Unit/integration/fuzz strategy, Docker sshd fixtures, sanitizers, CI matrix |
| 11 | [Versioning and roadmap](11-versioning-and-roadmap.md) | SemVer + ABI policy, deprecation process, milestones, post-1.0 async plans |

## Decisions at a glance

| Topic | Decision |
|---|---|
| Language standard | **C++17** (forward-compatible with C++20/23; `Result<T>` aliases `std::expected` when available) |
| Namespace | `sshpp`, with inline ABI namespace `sshpp::v1` |
| Header prefix | `#include <sshpp/…>` |
| Underlying library | libssh **0.10.4 – 0.11.x** |
| Error model | Exceptions by default; every fallible operation also has a non-throwing `try_*` sibling returning `Result<T>` |
| Concurrency | Blocking/synchronous only in v1; `Event` gives poll-loop integration; async is post-1.0 |
| Ownership | Strict RAII, move-only handles, `shared_ptr` session core so derived objects can never dangle |
| Packaging | Conan 2 recipe + CMake config package `find_package(libsshpp)`; static, shared, or header-only |
| License | LGPL-2.1-or-later (inherited from libssh — see [Goals and scope](01-goals-and-scope.md#licensing)) |
