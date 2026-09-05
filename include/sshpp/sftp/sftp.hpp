// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include <sshpp/detail/native_fwd.hpp>
#include <sshpp/detail/session_core.hpp>
#include <sshpp/export.hpp>
#include <sshpp/fwd.hpp>
#include <sshpp/result.hpp>
#include <sshpp/sftp/attributes.hpp>
#include <sshpp/sftp/directory.hpp>
#include <sshpp/sftp/file.hpp>
#include <sshpp/types.hpp>

#include <filesystem>
#include <vector>

namespace sshpp::sftp {

enum class OpenMode : unsigned {
    read       = 1u << 0,
    write      = 1u << 1,
    read_write = read | write,
    create     = 1u << 2,
    truncate   = 1u << 3,
    append     = 1u << 4,
    exclusive  = 1u << 5,
};
SSHPP_API inline OpenMode operator|(OpenMode a, OpenMode b) noexcept {
    return static_cast<OpenMode>(static_cast<unsigned>(a) | static_cast<unsigned>(b));
}
SSHPP_API inline bool has_flag(OpenMode v, OpenMode flag) noexcept {
    return (static_cast<unsigned>(v) & static_cast<unsigned>(flag)) != 0;
}

struct Limits {
    std::uint64_t max_packet_length = 0;
    std::uint64_t max_read_length = 0;
    std::uint64_t max_write_length = 0;
    std::uint64_t max_open_handles = 0;
};

/// The SFTP subsystem session. See docs/design/06 §6.2.
class SSHPP_API Sftp {
public:
    Sftp() = default;
    explicit Sftp(Session& session);
    ~Sftp();
    Sftp(Sftp&&) noexcept;
    Sftp& operator=(Sftp&&) noexcept;
    Sftp(const Sftp&) = delete;

    Result<void> try_init();
    explicit operator bool() const noexcept { return native_ != nullptr; }
    native_sftp native_handle() const noexcept { return native_; }

    int  protocol_version() const noexcept;
    Result<Limits> try_limits() const;

    // ---- files -----------------------------------------------------------
    Result<File> try_open(const RemotePath&, OpenMode,
                          std::filesystem::perms create_perms = std::filesystem::perms::owner_read |
                                                                std::filesystem::perms::owner_write);

    // ---- metadata ---------------------------------------------------------
    Result<Attributes> try_stat(const RemotePath&) const;
    Result<Attributes> try_lstat(const RemotePath&) const;
    Result<bool>       try_exists(const RemotePath&) const;
    Result<void>       try_chmod(const RemotePath&, std::filesystem::perms);
    Result<void>       try_chown(const RemotePath&, std::uint32_t uid, std::uint32_t gid);

    // ---- namespace ----------------------------------------------------------
    Result<void>       try_mkdir(const RemotePath&,
                                 std::filesystem::perms = std::filesystem::perms::owner_all);
    Result<void>       try_mkdir_p(const RemotePath&,
                                   std::filesystem::perms = std::filesystem::perms::owner_all);
    Result<void>       try_rmdir(const RemotePath&);
    Result<void>       try_remove(const RemotePath&);
    Result<void>       try_rename(const RemotePath& from, const RemotePath& to);
    Result<void>       try_symlink(const RemotePath& target, const RemotePath& link);
    Result<RemotePath> try_readlink(const RemotePath&) const;
    Result<RemotePath> try_canonicalize(const RemotePath&) const;

    // ---- directories ----------------------------------------------------------
    Result<Directory>  try_open_directory(const RemotePath&) const;
    Result<std::vector<Attributes>> try_list(const RemotePath&) const;

private:
    native_sftp             native_ = nullptr;
    detail::SessionCorePtr core_;
};

/// Range adapter: `for (const auto& e : sshpp::sftp::entries(s, "/var/log").value())`.
SSHPP_API Result<DirectoryRange> entries(Sftp&, const RemotePath&);

} // namespace sshpp::sftp
