// SPDX-License-Identifier: LGPL-2.1-or-later
#include <sshpp/known_hosts.hpp>

#include <libssh/libssh.h>

#include <cstdlib>
#include <fstream>

namespace sshpp {

namespace {

std::filesystem::path default_user_known_hosts() {
    const char* home = std::getenv("HOME");
    std::filesystem::path base = home ? std::filesystem::path(home) : std::filesystem::path("~");
    return base / ".ssh" / "known_hosts";
}

} // namespace

KnownHosts::KnownHosts(std::filesystem::path user_file, std::filesystem::path global_file)
    : user_file_(std::move(user_file)), global_file_(std::move(global_file)) {}

KnownHosts KnownHosts::default_files() {
    return KnownHosts(default_user_known_hosts(), "/etc/ssh/ssh_known_hosts");
}

Result<void> KnownHosts::add(std::string_view host, std::uint16_t port, const Key& key,
                             std::string_view comment) {
    auto b64 = key.to_public_base64();
    if (!b64) return b64.error();

    std::string hosts_field(host);
    if (port != 22) {
        hosts_field = "[" + std::string(host) + "]:" + std::to_string(port);
    }

    std::ofstream out(user_file_, std::ios::app);
    if (!out) {
        ErrorInfo info;
        info.operation = "KnownHosts::add";
        info.code = make_error_code(errc::known_hosts_io_error);
        info.message = "failed to open " + user_file_.string();
        return info;
    }
    out << hosts_field << ' ' << key.type_name() << ' ' << *b64;
    if (!comment.empty()) out << ' ' << comment;
    out << '\n';
    return {};
}

Result<KnownHostsEntry> KnownHosts::parse_line(std::string_view host, std::string_view line) {
    std::string host_str(host);
    std::string line_str(line);
    struct ssh_knownhosts_entry* raw = nullptr;
    int rc = ssh_known_hosts_parse_line(host_str.c_str(), line_str.c_str(), &raw);
    if (rc != SSH_OK || raw == nullptr) {
        ErrorInfo info;
        info.operation = "ssh_known_hosts_parse_line";
        info.code = make_error_code(errc::known_hosts_io_error);
        return info;
    }
    KnownHostsEntry entry;
    entry.hosts_field = raw->hostname ? raw->hostname : "";
    entry.comment = raw->comment ? raw->comment : "";
    if (raw->publickey != nullptr) {
        entry.key = Key::from_native(raw->publickey, Ownership::owning);
        raw->publickey = nullptr; // ownership transferred to entry.key
        entry.key_type = entry.key.type();
    }
    ssh_knownhosts_entry_free(raw);
    return entry;
}

} // namespace sshpp
