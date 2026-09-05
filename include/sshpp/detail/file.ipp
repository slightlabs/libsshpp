// SPDX-License-Identifier: LGPL-2.1-or-later
// Generated from src/file.cpp; see docs/design/09 §9.3.
#include <sshpp/config.hpp>
// SPDX-License-Identifier: LGPL-2.1-or-later
#include <sshpp/sftp/file.hpp>
#include <sshpp/detail/invoke.hpp>
#include <sshpp/library.hpp>

#include "sftp_internal.hpp"

#include <libssh/libssh.h>
#include <libssh/sftp.h>

#include <algorithm>
#include <type_traits>

namespace sshpp::sftp {

namespace {
#if SSHPP_HAS_SFTP_AIO
static_assert(std::is_same_v<native_sftp_aio, sftp_aio>, "libssh changed sftp_aio's definition");
#endif
} // namespace

SSHPP_INLINE File::~File() {
    if (native_ != nullptr) sftp_close(native_);
    native_ = nullptr;
}

SSHPP_INLINE File::File(File&& other) noexcept
    : native_(std::exchange(other.native_, nullptr)), sftp_(other.sftp_), core_(std::move(other.core_)),
      path_(std::move(other.path_)) {}

SSHPP_INLINE File& File::operator=(File&& other) noexcept {
    if (this != &other) {
        if (native_ != nullptr) sftp_close(native_);
        native_ = std::exchange(other.native_, nullptr);
        sftp_ = other.sftp_;
        core_ = std::move(other.core_);
        path_ = std::move(other.path_);
    }
    return *this;
}

SSHPP_INLINE Result<std::size_t> File::try_read(MutableByteView buf) {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "File::try_read"};
    ssize_t n = sftp_read(native_, buf.data(), buf.size());
    if (n < 0) {
        return detail::make_sftp_error_info(sftp_, nullptr, "sftp_read", SSHPP_HERE);
    }
    return static_cast<std::size_t>(n);
}

SSHPP_INLINE Result<void> File::try_read_exact(MutableByteView buf) {
    std::size_t got = 0;
    while (got < buf.size()) {
        MutableByteView remaining(buf.data() + got, buf.size() - got);
        auto r = try_read(remaining);
        if (!r) return r.error();
        if (*r == 0) {
            return ErrorInfo{make_error_code(errc::channel_eof), "unexpected EOF", "File::try_read_exact"};
        }
        got += *r;
    }
    return {};
}

SSHPP_INLINE Result<std::size_t> File::try_write(ByteView data) {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "File::try_write"};
    ssize_t n = sftp_write(native_, data.data(), data.size());
    if (n < 0) {
        return detail::make_sftp_error_info(sftp_, nullptr, "sftp_write", SSHPP_HERE);
    }
    return static_cast<std::size_t>(n);
}

SSHPP_INLINE Result<void> File::try_write_all(ByteView data) {
    std::size_t written = 0;
    while (written < data.size()) {
        ByteView remaining(data.data() + written, data.size() - written);
        auto r = try_write(remaining);
        if (!r) return r.error();
        if (*r == 0) return ErrorInfo{make_error_code(errc::channel_closed), "short write", "File::try_write_all"};
        written += *r;
    }
    return {};
}

SSHPP_INLINE Result<std::uint64_t> File::try_tell() const {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "File::try_tell"};
    return static_cast<std::uint64_t>(sftp_tell64(native_));
}

SSHPP_INLINE Result<void> File::try_seek(std::uint64_t offset) {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "File::try_seek"};
    int rc = sftp_seek64(native_, offset);
    if (rc != 0) {
        return detail::make_sftp_error_info(sftp_, nullptr, "sftp_seek64", SSHPP_HERE);
    }
    return {};
}

SSHPP_INLINE Result<void> File::try_rewind() {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "File::try_rewind"};
    sftp_rewind(native_);
    return {};
}

SSHPP_INLINE Result<Attributes> File::try_stat() const {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "File::try_stat"};
    sftp_attributes raw = sftp_fstat(native_);
    if (raw == nullptr) {
        return detail::make_sftp_error_info(sftp_, nullptr, "sftp_fstat", SSHPP_HERE);
    }
    Attributes a = internal::attributes_from_native(raw);
    sftp_attributes_free(raw);
    return a;
}

SSHPP_INLINE Result<void> File::try_truncate(std::uint64_t size) {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "File::try_truncate"};
    sftp_attributes_struct attr{};
    attr.size = size;
    attr.flags = SSH_FILEXFER_ATTR_SIZE;
    int rc = sftp_setstat(sftp_, path_.str().c_str(), &attr);
    if (rc != SSH_OK) {
        return detail::make_sftp_error_info(sftp_, nullptr, "sftp_setstat", SSHPP_HERE);
    }
    return {};
}

SSHPP_INLINE Result<void> File::try_close() {
    if (native_ == nullptr) return {};
    int rc = sftp_close(native_);
    native_ = nullptr;
    if (rc != SSH_OK) {
        return ErrorInfo{make_error_code(errc::sftp_unavailable), "", "sftp_close"};
    }
    return {};
}

namespace {
constexpr std::size_t kDefaultChunk = 256u * 1024u;
constexpr std::size_t kDefaultDepth = 16;
} // namespace

SSHPP_INLINE File::ReadAhead::ReadAhead(File& file, std::size_t chunk, std::size_t depth)
    : file_(&file), chunk_(chunk != 0 ? chunk : kDefaultChunk), depth_(depth != 0 ? depth : kDefaultDepth) {
    buffer_.reserve(chunk_);
}

SSHPP_INLINE File::ReadAhead::~ReadAhead() {
#if SSHPP_HAS_SFTP_AIO
    for (native_sftp_aio aio : inflight_) sftp_aio_free(aio);
#endif
}

#if SSHPP_HAS_SFTP_AIO
SSHPP_INLINE Result<void> File::ReadAhead::submit_one() {
    native_sftp_aio aio = nullptr;
    ssize_t rc = sftp_aio_begin_read(file_->native_handle(), chunk_, &aio);
    if (rc == SSH_ERROR || aio == nullptr) {
        return detail::make_sftp_error_info(file_->sftp_, nullptr, "sftp_aio_begin_read", SSHPP_HERE);
    }
    inflight_.push_back(aio);
    return {};
}
#endif

SSHPP_INLINE Result<ByteView> File::ReadAhead::try_next() {
    if (file_->native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "File::ReadAhead::try_next"};
#if SSHPP_HAS_SFTP_AIO
    while (!reached_eof_ && inflight_.size() < depth_) {
        auto r = submit_one();
        if (!r) return r.error();
    }
    if (inflight_.empty()) return ByteView{};

    native_sftp_aio aio = inflight_.front();
    inflight_.pop_front();
    buffer_.resize(chunk_);
    ssize_t n = sftp_aio_wait_read(&aio, buffer_.data(), buffer_.size());
    if (n < 0) {
        return detail::make_sftp_error_info(file_->sftp_, nullptr, "sftp_aio_wait_read", SSHPP_HERE);
    }
    if (n == 0) {
        // Sequential submission order guarantees this is the true end of file;
        // free (not wait on) whatever is still in flight to avoid leaking it.
        reached_eof_ = true;
        for (native_sftp_aio pending : inflight_) sftp_aio_free(pending);
        inflight_.clear();
        return ByteView{};
    }
    return ByteView(buffer_.data(), static_cast<std::size_t>(n));
#else
    if (reached_eof_) return ByteView{};
    buffer_.resize(chunk_);
    auto r = file_->try_read(MutableByteView(buffer_.data(), buffer_.size()));
    if (!r) return r.error();
    if (*r == 0) reached_eof_ = true;
    return ByteView(buffer_.data(), *r);
#endif
}

SSHPP_INLINE File::WriteBehind::WriteBehind(File& file, std::size_t chunk, std::size_t depth)
    : file_(&file), chunk_(chunk != 0 ? chunk : kDefaultChunk), depth_(depth != 0 ? depth : kDefaultDepth) {}

SSHPP_INLINE File::WriteBehind::~WriteBehind() {
    auto r = try_flush();
    if (!r) Library::report_destructor_error(r.error());
}

#if SSHPP_HAS_SFTP_AIO
SSHPP_INLINE Result<void> File::WriteBehind::drain_one() {
    native_sftp_aio aio = inflight_.front();
    inflight_.pop_front();
    ssize_t n = sftp_aio_wait_write(&aio);
    if (n < 0) {
        return detail::make_sftp_error_info(file_->sftp_, nullptr, "sftp_aio_wait_write", SSHPP_HERE);
    }
    return {};
}
#endif

SSHPP_INLINE Result<void> File::WriteBehind::try_write(ByteView data) {
    if (file_->native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "File::WriteBehind::try_write"};
#if SSHPP_HAS_SFTP_AIO
    std::size_t offset = 0;
    while (offset < data.size()) {
        while (inflight_.size() >= depth_) {
            auto r = drain_one();
            if (!r) return r.error();
        }
        std::size_t n = std::min(chunk_, data.size() - offset);
        native_sftp_aio aio = nullptr;
        ssize_t rc = sftp_aio_begin_write(file_->native_handle(), data.data() + offset, n, &aio);
        if (rc == SSH_ERROR || aio == nullptr) {
            return detail::make_sftp_error_info(file_->sftp_, nullptr, "sftp_aio_begin_write", SSHPP_HERE);
        }
        inflight_.push_back(aio);
        offset += static_cast<std::size_t>(rc);
    }
    return {};
#else
    std::size_t offset = 0;
    while (offset < data.size()) {
        std::size_t n = std::min(chunk_, data.size() - offset);
        auto r = file_->try_write_all(ByteView(data.data() + offset, n));
        if (!r) return r.error();
        offset += n;
    }
    return {};
#endif
}

SSHPP_INLINE Result<void> File::WriteBehind::try_flush() {
#if SSHPP_HAS_SFTP_AIO
    ErrorInfo first_error;
    while (!inflight_.empty()) {
        auto r = drain_one();
        if (!r && !first_error) first_error = r.error();
    }
    if (first_error) return first_error;
    return {};
#else
    return {};
#endif
}

} // namespace sshpp::sftp
