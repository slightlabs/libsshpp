// SPDX-License-Identifier: LGPL-2.1-or-later
#include <sshpp/sftp/file.hpp>
#include <sshpp/detail/invoke.hpp>

#include "sftp_internal.hpp"

#include <libssh/libssh.h>
#include <libssh/sftp.h>

namespace sshpp::sftp {

File::~File() {
    if (native_ != nullptr) sftp_close(native_);
    native_ = nullptr;
}

File::File(File&& other) noexcept
    : native_(std::exchange(other.native_, nullptr)), sftp_(other.sftp_), core_(std::move(other.core_)),
      path_(std::move(other.path_)) {}

File& File::operator=(File&& other) noexcept {
    if (this != &other) {
        if (native_ != nullptr) sftp_close(native_);
        native_ = std::exchange(other.native_, nullptr);
        sftp_ = other.sftp_;
        core_ = std::move(other.core_);
        path_ = std::move(other.path_);
    }
    return *this;
}

Result<std::size_t> File::try_read(MutableByteView buf) {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "File::try_read"};
    ssize_t n = sftp_read(native_, buf.data(), buf.size());
    if (n < 0) {
        return detail::make_sftp_error_info(sftp_, nullptr, "sftp_read", SSHPP_HERE);
    }
    return static_cast<std::size_t>(n);
}

Result<void> File::try_read_exact(MutableByteView buf) {
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

Result<std::size_t> File::try_write(ByteView data) {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "File::try_write"};
    ssize_t n = sftp_write(native_, data.data(), data.size());
    if (n < 0) {
        return detail::make_sftp_error_info(sftp_, nullptr, "sftp_write", SSHPP_HERE);
    }
    return static_cast<std::size_t>(n);
}

Result<void> File::try_write_all(ByteView data) {
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

Result<std::uint64_t> File::try_tell() const {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "File::try_tell"};
    return static_cast<std::uint64_t>(sftp_tell64(native_));
}

Result<void> File::try_seek(std::uint64_t offset) {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "File::try_seek"};
    int rc = sftp_seek64(native_, offset);
    if (rc != 0) {
        return detail::make_sftp_error_info(sftp_, nullptr, "sftp_seek64", SSHPP_HERE);
    }
    return {};
}

Result<void> File::try_rewind() {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "File::try_rewind"};
    sftp_rewind(native_);
    return {};
}

Result<Attributes> File::try_stat() const {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "File::try_stat"};
    sftp_attributes raw = sftp_fstat(native_);
    if (raw == nullptr) {
        return detail::make_sftp_error_info(sftp_, nullptr, "sftp_fstat", SSHPP_HERE);
    }
    Attributes a = internal::attributes_from_native(raw);
    sftp_attributes_free(raw);
    return a;
}

Result<void> File::try_truncate(std::uint64_t size) {
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

Result<void> File::try_close() {
    if (native_ == nullptr) return {};
    int rc = sftp_close(native_);
    native_ = nullptr;
    if (rc != SSH_OK) {
        return ErrorInfo{make_error_code(errc::sftp_unavailable), "", "sftp_close"};
    }
    return {};
}

} // namespace sshpp::sftp
