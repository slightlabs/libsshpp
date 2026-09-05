// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include <sshpp/export.hpp>
#include <sshpp/key.hpp>
#include <sshpp/result.hpp>

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace sshpp {

enum class KnownHostsStatus { ok, changed, other_type, not_found, unknown, error };

struct KnownHostsEntry {
    std::string           hosts_field;
    std::string           marker;
    KeyType                key_type = KeyType::unknown;
    Key                    key;
    std::string            comment;
    std::filesystem::path  file;
    int                    line = 0;
};

/// Direct manipulation of known_hosts files, independent of a live Session.
/// See docs/design/04 §4.6.
class SSHPP_API KnownHosts {
public:
    explicit KnownHosts(std::filesystem::path user_file, std::filesystem::path global_file = {});

    static KnownHosts default_files();

    Result<void> add(std::string_view host, std::uint16_t port, const Key&, std::string_view comment = {});

    /// Parse a single line without touching any file (wraps ssh_known_hosts_parse_line).
    static Result<KnownHostsEntry> parse_line(std::string_view host, std::string_view line);

private:
    std::filesystem::path user_file_;
    std::filesystem::path global_file_;
};

} // namespace sshpp
