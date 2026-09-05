// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include <sshpp/config.hpp>
#include <sshpp/detail/native_fwd.hpp>
#include <sshpp/detail/session_core.hpp>
#include <sshpp/export.hpp>
#include <sshpp/result.hpp>
#include <sshpp/sftp/attributes.hpp>
#include <sshpp/types.hpp>

#include <cstdint>
#include <deque>
#include <vector>

namespace sshpp::sftp {

class Sftp;

/// A single open SFTP file handle. See docs/design/06 §6.3.
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

    class ReadAhead;
    class WriteBehind;

private:
    friend class Sftp;
    File(native_sftp_file n, native_sftp sftp, detail::SessionCorePtr core, RemotePath path)
        : native_(n), sftp_(sftp), core_(std::move(core)), path_(std::move(path)) {}

    native_sftp_file        native_ = nullptr;
    native_sftp             sftp_ = nullptr;
    detail::SessionCorePtr core_;
    RemotePath              path_;
};

/// Keeps up to `depth` reads in flight so throughput isn't capped at one round
/// trip per chunk. Falls back to a synchronous loop when the linked libssh
/// predates sftp_aio_* (SSHPP_HAS_SFTP_AIO == 0). See docs/design/06 §6.3.
class SSHPP_API File::ReadAhead {
public:
    explicit ReadAhead(File& file, std::size_t chunk = 0, std::size_t depth = 0);
    ~ReadAhead();
    ReadAhead(const ReadAhead&) = delete;
    ReadAhead(ReadAhead&&) = delete;

    /// Returns the next contiguous chunk in file order; empty span == EOF.
    /// The returned view is invalidated by the next call to try_next().
    Result<ByteView> try_next();

private:
#if SSHPP_HAS_SFTP_AIO
    Result<void> submit_one();
    std::deque<native_sftp_aio> inflight_;
#endif
    File*                   file_;
    std::size_t             chunk_;
    std::size_t             depth_;
    std::vector<std::byte> buffer_;
    bool                    reached_eof_ = false;
};

/// Keeps up to `depth` writes in flight; mirror of ReadAhead for the write side.
class SSHPP_API File::WriteBehind {
public:
    explicit WriteBehind(File& file, std::size_t chunk = 0, std::size_t depth = 0);
    ~WriteBehind();
    WriteBehind(const WriteBehind&) = delete;
    WriteBehind(WriteBehind&&) = delete;

    Result<void> try_write(ByteView data);
    /// Waits for all in-flight writes to complete. Also called by the destructor
    /// (errors from that implicit call go to Library::set_destructor_error_handler()).
    Result<void> try_flush();

private:
#if SSHPP_HAS_SFTP_AIO
    Result<void> drain_one();
    std::deque<native_sftp_aio> inflight_;
#endif
    File*       file_;
    std::size_t chunk_;
    std::size_t depth_;
};

} // namespace sshpp::sftp

#if SSHPP_HEADER_ONLY
#include <sshpp/detail/file.ipp>
#endif
