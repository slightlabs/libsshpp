// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include <sshpp/config.hpp>

#include <sshpp/detail/native_fwd.hpp>
#include <sshpp/export.hpp>
#include <sshpp/key.hpp>
#include <sshpp/library.hpp>
#include <sshpp/result.hpp>
#include <sshpp/server/server_session.hpp>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace sshpp::server {

struct SSHPP_API BindOptions {
    std::string   bind_address = "0.0.0.0";
    std::uint16_t port = 22;

    /// At least one host key (via either field) is required.
    std::vector<std::filesystem::path> host_key_files;
    std::vector<Key>                    host_keys;

    std::optional<std::string> banner;
    LogLevel                    log_level = LogLevel::none;

    Result<void> validate() const;
};

/// The listening server socket. See docs/design/08 §8.3.
class SSHPP_API Bind {
public:
    Bind() = default;
    explicit Bind(const BindOptions&);
    ~Bind();
    Bind(Bind&&) noexcept;
    Bind& operator=(Bind&&) noexcept;
    Bind(const Bind&) = delete;

    explicit operator bool() const noexcept { return native_ != nullptr; }
    native_bind native_handle() const noexcept { return native_; }

    Result<void>  try_listen();
    std::uint16_t local_port() const noexcept { return configured_port_; }
    int           fd() const noexcept;

    /// Blocking accept. The returned session has NOT completed key exchange yet.
    Result<Session> try_accept();
    /// Blocks up to `timeout`; nullopt on timeout.
    Result<std::optional<Session>> try_accept(std::chrono::milliseconds timeout);

private:
    native_bind   native_ = nullptr;
    std::uint16_t configured_port_ = 0;
};

} // namespace sshpp::server

#if SSHPP_HEADER_ONLY
#include <sshpp/detail/server_bind.ipp>
#endif
