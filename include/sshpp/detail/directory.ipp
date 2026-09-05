// SPDX-License-Identifier: LGPL-2.1-or-later
// Generated from src/directory.cpp; see docs/design/09 §9.3.
#include <sshpp/config.hpp>
// SPDX-License-Identifier: LGPL-2.1-or-later
#include <sshpp/sftp/directory.hpp>
#include <sshpp/detail/invoke.hpp>

#include "sftp_internal.hpp"

#include <libssh/libssh.h>
#include <libssh/sftp.h>

namespace sshpp::sftp {

SSHPP_INLINE Directory::~Directory() {
    if (native_ != nullptr) sftp_closedir(native_);
    native_ = nullptr;
}

SSHPP_INLINE Directory::Directory(Directory&& other) noexcept
    : native_(std::exchange(other.native_, nullptr)), sftp_(other.sftp_), core_(std::move(other.core_)),
      path_(std::move(other.path_)), last_error_(std::move(other.last_error_)) {}

SSHPP_INLINE Directory& Directory::operator=(Directory&& other) noexcept {
    if (this != &other) {
        if (native_ != nullptr) sftp_closedir(native_);
        native_ = std::exchange(other.native_, nullptr);
        sftp_ = other.sftp_;
        core_ = std::move(other.core_);
        path_ = std::move(other.path_);
        last_error_ = std::move(other.last_error_);
    }
    return *this;
}

SSHPP_INLINE std::optional<Attributes> Directory::next() {
    if (native_ == nullptr) return std::nullopt;
    sftp_attributes raw = sftp_readdir(sftp_, native_);
    if (raw == nullptr) {
        if (!sftp_dir_eof(native_)) {
            last_error_ = detail::make_sftp_error_info(sftp_, nullptr, "sftp_readdir", SSHPP_HERE);
        }
        return std::nullopt;
    }
    Attributes a = internal::attributes_from_native(raw);
    sftp_attributes_free(raw);
    return a;
}

SSHPP_INLINE bool Directory::eof() const noexcept { return native_ == nullptr || sftp_dir_eof(native_) != 0; }

} // namespace sshpp::sftp
