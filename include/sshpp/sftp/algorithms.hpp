// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include <sshpp/export.hpp>
#include <sshpp/result.hpp>
#include <sshpp/sftp/sftp.hpp>
#include <sshpp/types.hpp>

#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>

namespace sshpp::sftp {

struct Progress {
    std::uint64_t bytes_done = 0;
    std::optional<std::uint64_t> bytes_total;
};
/// Return false to abort the transfer (yields errc::cancelled).
using ProgressCallback = std::function<bool(const Progress&)>;

enum class Overwrite { fail, replace };

struct TransferOptions {
    Overwrite         overwrite = Overwrite::replace;
    bool              preserve_permissions = true;
    std::size_t       chunk_size = 256u * 1024u;
    ProgressCallback  progress;
};

SSHPP_API Result<std::uint64_t> try_download(Sftp&, const RemotePath& remote,
                                             const std::filesystem::path& local,
                                             TransferOptions = {});
SSHPP_API Result<std::uint64_t> try_upload(Sftp&, const std::filesystem::path& local,
                                           const RemotePath& remote, TransferOptions = {});
SSHPP_API Result<std::string>   try_read_file(Sftp&, const RemotePath&, std::size_t limit = 16u << 20);
SSHPP_API Result<void>          try_write_file(Sftp&, const RemotePath&, ByteView,
                                               std::filesystem::perms = std::filesystem::perms::owner_read |
                                                                        std::filesystem::perms::owner_write);

struct TreeStats { std::uint64_t files = 0, directories = 0, bytes = 0, skipped = 0; };

/// Downloads a remote directory tree. Every remote entry name is validated to contain
/// no '/', no "..", and no NUL before being joined to `local`; symlinks are skipped
/// (counted in TreeStats::skipped), never followed. See docs/design/06 §6.5.
SSHPP_API Result<TreeStats> try_download_tree(Sftp&, const RemotePath& remote,
                                              const std::filesystem::path& local,
                                              TransferOptions = {});

} // namespace sshpp::sftp
