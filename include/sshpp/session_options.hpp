// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include <sshpp/config.hpp>

#include <sshpp/export.hpp>
#include <sshpp/library.hpp>
#include <sshpp/result.hpp>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace sshpp {

enum class StrictHostKeyChecking { off, on };
enum class Locking { none, internal };
enum class Compression { off, on, zlib, zlib_openssh };

/// Type-safe, checked replacement for ssh_options_set's void* interface.
/// See docs/design/04 §4.2.
struct SSHPP_API SessionOptions {
    // --- connection ------------------------------------------------------
    std::string                  host;
    std::optional<std::uint16_t> port;
    std::optional<std::string>   user;
    std::optional<std::string>   bind_address;
    std::optional<int>           fd;
    std::optional<std::string>   proxy_command;
    std::optional<std::string>   proxy_jump;

    // --- timing -----------------------------------------------------------
    std::optional<std::chrono::microseconds> timeout;
    std::optional<bool>          tcp_nodelay;

    // --- files / config ----------------------------------------------------
    std::optional<std::filesystem::path> ssh_dir;
    std::optional<std::filesystem::path> known_hosts;
    std::optional<std::filesystem::path> global_known_hosts;
    std::vector<std::filesystem::path>   identities;
    std::optional<std::filesystem::path> config_file;
    bool                                 process_config = true;

    // --- crypto negotiation -------------------------------------------------
    std::optional<std::string> ciphers_client_to_server;
    std::optional<std::string> ciphers_server_to_client;
    std::optional<std::string> key_exchange;
    std::optional<std::string> hmac_client_to_server;
    std::optional<std::string> hmac_server_to_client;
    std::optional<std::string> host_key_algorithms;
    std::optional<std::string> public_key_accepted_types;
    std::optional<Compression> compression;
    std::optional<int>         compression_level;

    // --- rekeying ------------------------------------------------------------
    std::optional<std::uint64_t>        rekey_data_bytes;
    std::optional<std::chrono::seconds> rekey_time;

    // --- host key policy ------------------------------------------------------
    std::optional<StrictHostKeyChecking> strict_host_key_checking;

    // --- GSSAPI -----------------------------------------------------------------
    std::optional<std::string> gssapi_server_identity;
    std::optional<std::string> gssapi_client_identity;
    std::optional<bool>        gssapi_delegate_credentials;

    // --- wrapper behaviour --------------------------------------------------------
    Locking  locking   = Locking::none;
    LogLevel log_level = LogLevel::none;

    /// Parse "user@host:port" / "host" / "[v6::addr]:port".
    static Result<SessionOptions> parse_target(std::string_view target);

    Result<void> validate() const;

    class Builder;
    static Builder builder();
};

/// Fluent builder over SessionOptions for call-site brevity. Declared after the
/// aggregate itself because it holds one by value (see docs/design/04 §4.2).
class SessionOptions::Builder {
public:
    Builder& host(std::string v) { opts_.host = std::move(v); return *this; }
    Builder& port(std::uint16_t v) { opts_.port = v; return *this; }
    Builder& user(std::string v) { opts_.user = std::move(v); return *this; }
    Builder& timeout(std::chrono::microseconds v) { opts_.timeout = v; return *this; }
    Builder& identity(std::filesystem::path v) { opts_.identities.push_back(std::move(v)); return *this; }
    Result<SessionOptions> build() {
        auto r = opts_.validate();
        if (!r) return r.error();
        return opts_;
    }
private:
    SessionOptions opts_;
};

inline SessionOptions::Builder SessionOptions::builder() { return Builder{}; }

} // namespace sshpp

#if SSHPP_HEADER_ONLY
#include <sshpp/detail/session_options.ipp>
#endif
