// SPDX-License-Identifier: LGPL-2.1-or-later
//
// SCP is legacy; prefer sshpp::sftp for new code (SFTP is the OpenSSH default
// since 9.0 and has no equivalent of CVE-2019-6111). This module exists for
// servers/appliances that only speak SCP. See docs/design/06 §6.7.
#pragma once

#include <sshpp/detail/native_fwd.hpp>
#include <sshpp/detail/session_core.hpp>
#include <sshpp/export.hpp>
#include <sshpp/fwd.hpp>
#include <sshpp/result.hpp>
#include <sshpp/types.hpp>

#include <cstdint>
#include <filesystem>
#include <functional>
#include <iosfwd>
#include <optional>
#include <string>

namespace sshpp::scp {

enum class Mode { read, write, read_recursive, write_recursive };
enum class RequestType { new_file, new_directory, end_directory, eof, warning };

struct Request {
    RequestType             type = RequestType::eof;
    std::string             name;
    std::uint64_t           size = 0;
    std::filesystem::perms permissions{};
    std::string             warning;
};

struct Progress {
    std::uint64_t bytes_done = 0;
    std::optional<std::uint64_t> bytes_total;
};
/// Return false to abort the transfer (yields errc::cancelled).
using ProgressCallback = std::function<bool(const Progress&)>;

/// Pull side of an SCP transfer: `scp -f` as seen by the client.
class SSHPP_API Reader {
public:
    Reader() = default;
    Reader(Session& session, const RemotePath& location, bool recursive);
    ~Reader();
    Reader(Reader&&) noexcept;
    Reader& operator=(Reader&&) noexcept;
    Reader(const Reader&) = delete;

    explicit operator bool() const noexcept { return native_ != nullptr; }

    Result<void> try_init();

    /// nullopt when the transfer is complete (SSH_SCP_REQUEST_EOF).
    Result<std::optional<Request>> try_next();
    Result<void>          try_accept();
    Result<void>          try_deny(std::string_view reason);
    Result<std::size_t>   try_read(MutableByteView);
    Result<std::uint64_t> try_read_to(std::ostream&, ProgressCallback = {});

private:
    native_scp              native_ = nullptr;
    detail::SessionCorePtr core_;
};

/// Push side of an SCP transfer: `scp -t` as seen by the client.
class SSHPP_API Writer {
public:
    Writer() = default;
    Writer(Session& session, const RemotePath& destination_dir, bool recursive);
    ~Writer();
    Writer(Writer&&) noexcept;
    Writer& operator=(Writer&&) noexcept;
    Writer(const Writer&) = delete;

    explicit operator bool() const noexcept { return native_ != nullptr; }

    Result<void> try_init();

    Result<void> try_push_file(std::string_view name, std::uint64_t size,
                               std::filesystem::perms = std::filesystem::perms::owner_read |
                                                        std::filesystem::perms::owner_write);
    Result<void> try_push_directory(std::string_view name,
                                    std::filesystem::perms = std::filesystem::perms::owner_all);
    Result<void>          try_leave_directory();
    Result<void>          try_write(ByteView);
    Result<std::uint64_t> try_write_from(std::istream&, std::uint64_t size, ProgressCallback = {});

private:
    native_scp              native_ = nullptr;
    detail::SessionCorePtr core_;
};

/// Layer-4 one-liners with the same name-validation hardening as the SFTP tree
/// helpers (cf. CVE-2019-6111: a malicious server sending unexpected filenames).
SSHPP_API Result<std::uint64_t> try_download(Session&, const RemotePath&,
                                             const std::filesystem::path&, ProgressCallback = {});
SSHPP_API Result<std::uint64_t> try_upload(Session&, const std::filesystem::path&,
                                           const RemotePath&, ProgressCallback = {});

} // namespace sshpp::scp
