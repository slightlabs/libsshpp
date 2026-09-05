// SPDX-License-Identifier: LGPL-2.1-or-later
//
// A complete in-process SSH server for tests. See docs/design/08 §8.8.
//
// Scope note relative to the design doc: no Options::faults fault-injection
// (truncated banners, mid-transfer disconnects, slow handshakes) and no
// Stats/allow_interactive/allow_none/allow_port_forwarding - this covers the
// common case (password/public-key auth, exec, optional SFTP root) that
// makes the rest of the test suite hermetic; the rest can be added later
// without changing this shape.
#pragma once

#include <sshpp/config.hpp>

#include <sshpp/key.hpp>
#include <sshpp/result.hpp>
#include <sshpp/server/bind.hpp>
#include <sshpp/session_options.hpp>
#include <sshpp/types.hpp>

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <istream>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace sshpp::server {

/// A complete SSH server on 127.0.0.1:<ephemeral>, running on its own
/// thread(s). Generates a throwaway ed25519 host key in memory. See
/// docs/design/08 §8.8.
class SSHPP_API TestServer {
public:
    struct Options {
        std::string       user = "testuser";
        SecureString       password{"testpass"};
        std::vector<Key>  authorized_keys;
        bool                allow_password = true;
        bool                allow_public_key = true;
        std::optional<std::filesystem::path> sftp_root;   // enables the SFTP subsystem
        std::function<int(std::string_view, std::istream&, std::ostream&, std::ostream&)> exec;
    };

    // No `= Options{}` default here: GCC rejects a default argument whose
    // type is a nested class of the same enclosing class when that nested
    // class has a default member initializer. Callers wanting defaults pass
    // `Options{}` explicitly.
    explicit TestServer(Options options);
    ~TestServer();
    TestServer(const TestServer&) = delete;
    TestServer& operator=(const TestServer&) = delete;

    std::uint16_t port() const noexcept { return port_; }
    const Key&    host_key() const noexcept { return host_key_; }
    Fingerprint   host_key_fingerprint(HashType type = HashType::sha256) const;
    /// Ready-made client options pointing at this server (password/pubkey auth
    /// is still the caller's job to configure and perform).
    SessionOptions client_options() const;
    std::filesystem::path known_hosts_file() const { return known_hosts_path_; }

private:
    void accept_loop();
    void serve_connection(Session session);

    Options                     options_;
    Key                          host_key_;
    Bind                          bind_;
    std::uint16_t                port_ = 0;
    std::filesystem::path       known_hosts_path_;
    std::atomic<bool>           stop_requested_{false};
    std::thread                  accept_thread_;
    std::vector<std::thread>    connection_threads_;
};

} // namespace sshpp::server

#if SSHPP_HEADER_ONLY
#include <sshpp/detail/server_test_server.ipp>
#endif
