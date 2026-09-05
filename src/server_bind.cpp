// SPDX-License-Identifier: LGPL-2.1-or-later
#include <sshpp/server/bind.hpp>
#include <sshpp/detail/invoke.hpp>

#include <libssh/libssh.h>
#include <libssh/server.h>

#include <poll.h>

#include <type_traits>

namespace sshpp::server {

namespace {
static_assert(std::is_same_v<native_bind, ssh_bind>, "libssh changed ssh_bind's definition");

ErrorInfo bind_error(ssh_bind b, const char* operation, errc fallback) {
    ErrorInfo info;
    info.operation = operation;
    info.where = SSHPP_HERE;
    info.message = b != nullptr ? ssh_get_error(b) : "";
    info.code = make_error_code(fallback);
    return info;
}
} // namespace

Result<void> BindOptions::validate() const {
    if (host_key_files.empty() && host_keys.empty()) {
        ErrorInfo info;
        info.operation = "BindOptions::validate";
        info.code = make_error_code(errc::invalid_argument);
        info.message = "at least one host key is required";
        return info;
    }
    return {};
}

Bind::Bind(const BindOptions& opts) : configured_port_(opts.port) {
    native_ = ssh_bind_new();
    if (native_ == nullptr) return;

    ssh_bind_options_set(native_, SSH_BIND_OPTIONS_BINDADDR, opts.bind_address.c_str());
    std::string port_str = std::to_string(opts.port);
    ssh_bind_options_set(native_, SSH_BIND_OPTIONS_BINDPORT_STR, port_str.c_str());
    if (opts.banner) {
        ssh_bind_options_set(native_, SSH_BIND_OPTIONS_BANNER, opts.banner->c_str());
    }
    for (const auto& path : opts.host_key_files) {
        ssh_bind_options_set(native_, SSH_BIND_OPTIONS_HOSTKEY, path.string().c_str());
    }
    for (const auto& key : opts.host_keys) {
        // ssh_bind_free() frees keys set via IMPORT_KEY, so hand libssh an
        // exclusively-owned duplicate rather than our caller-owned handle
        // (passing the original would double-free it).
        ssh_key dup = ssh_key_dup(key.native_handle());
        if (dup != nullptr) ssh_bind_options_set(native_, SSH_BIND_OPTIONS_IMPORT_KEY, dup);
    }
}

Bind::~Bind() {
    if (native_ != nullptr) ssh_bind_free(native_);
    native_ = nullptr;
}

Bind::Bind(Bind&& other) noexcept
    : native_(std::exchange(other.native_, nullptr)), configured_port_(other.configured_port_) {}

Bind& Bind::operator=(Bind&& other) noexcept {
    if (this != &other) {
        if (native_ != nullptr) ssh_bind_free(native_);
        native_ = std::exchange(other.native_, nullptr);
        configured_port_ = other.configured_port_;
    }
    return *this;
}

Result<void> Bind::try_listen() {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Bind::try_listen"};
    if (ssh_bind_listen(native_) != SSH_OK) {
        return bind_error(native_, "ssh_bind_listen", errc::fatal);
    }
    return {};
}

int Bind::fd() const noexcept { return native_ != nullptr ? static_cast<int>(ssh_bind_get_fd(native_)) : -1; }

Result<Session> Bind::try_accept() {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Bind::try_accept"};
    native_session raw = ssh_new();
    if (raw == nullptr) {
        return ErrorInfo{make_error_code(errc::out_of_memory), "", "ssh_new"};
    }
    if (ssh_bind_accept(native_, raw) != SSH_OK) {
        auto info = detail::make_error_info(raw, "ssh_bind_accept", SSHPP_HERE, errc::fatal);
        ssh_free(raw);
        return info;
    }
    return Session(std::make_shared<detail::SessionCore>(raw));
}

Result<std::optional<Session>> Bind::try_accept(std::chrono::milliseconds timeout) {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Bind::try_accept"};
    pollfd pfd{fd(), POLLIN, 0};
    int rv = ::poll(&pfd, 1, static_cast<int>(timeout.count()));
    if (rv <= 0) return std::optional<Session>{};
    auto r = try_accept();
    if (!r) return r.error();
    return std::optional<Session>{std::move(*r)};
}

} // namespace sshpp::server
