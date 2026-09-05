// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include <sshpp/detail/native_fwd.hpp>
#include <sshpp/detail/session_core.hpp>
#include <sshpp/export.hpp>
#include <sshpp/result.hpp>
#include <sshpp/sftp/attributes.hpp>
#include <sshpp/types.hpp>

#include <cstdint>

namespace sshpp::sftp {

class Sftp;

/// A single open SFTP file handle. See docs/design/06 §6.3 (pipelined
/// ReadAhead/WriteBehind I/O from that section is not implemented yet).
class SSHPP_API File {
public:
    File() = default;
    ~File();
    File(File&&) noexcept;
    File& operator=(File&&) noexcept;
    File(const File&) = delete;

    explicit operator bool() const noexcept { return native_ != nullptr; }
    native_sftp_file native_handle() const noexcept { return native_; }
    const RemotePath& path() const noexcept { return path_; }

    Result<std::size_t> try_read(MutableByteView);
    Result<void>        try_read_exact(MutableByteView);
    Result<std::size_t> try_write(ByteView);
    Result<void>        try_write_all(ByteView);

    Result<std::uint64_t> try_tell() const;
    Result<void>          try_seek(std::uint64_t offset);
    Result<void>          try_rewind();
    Result<Attributes>    try_stat() const;
    Result<void>          try_truncate(std::uint64_t size);
    Result<void>          try_close();

private:
    friend class Sftp;
    File(native_sftp_file n, native_sftp sftp, detail::SessionCorePtr core, RemotePath path)
        : native_(n), sftp_(sftp), core_(std::move(core)), path_(std::move(path)) {}

    native_sftp_file        native_ = nullptr;
    native_sftp             sftp_ = nullptr;
    detail::SessionCorePtr core_;
    RemotePath              path_;
};

} // namespace sshpp::sftp
