// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include <sshpp/export.hpp>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <utility>

namespace sshpp::sftp {

enum class FileType { regular, directory, symlink, special, unknown,
                      socket, char_device, block_device, fifo };

/// Value-type copy of libssh's sftp_attributes. See docs/design/06 §6.1.
struct SSHPP_API Attributes {
    std::string   name;
    std::string   long_name;
    FileType      type = FileType::unknown;
    std::uint64_t size = 0;
    std::uint32_t uid = 0, gid = 0;
    std::optional<std::string> owner, group;
    std::uint32_t permissions = 0;
    std::uint32_t flags = 0;

    std::optional<std::chrono::system_clock::time_point> atime, mtime, createtime;

    bool is_regular()   const noexcept { return type == FileType::regular; }
    bool is_directory() const noexcept { return type == FileType::directory; }
    bool is_symlink()   const noexcept { return type == FileType::symlink; }
    std::filesystem::perms std_perms() const noexcept {
        return static_cast<std::filesystem::perms>(permissions & 07777u);
    }
};

/// Partial attributes for setstat: only engaged fields are transmitted.
struct SSHPP_API AttributeUpdate {
    std::optional<std::uint64_t> size;
    std::optional<std::uint32_t> permissions;
    std::optional<std::pair<std::uint32_t, std::uint32_t>> uid_gid;
    std::optional<std::chrono::system_clock::time_point> atime, mtime;
};

} // namespace sshpp::sftp
