// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include <sshpp/config.hpp>

#include <sshpp/detail/native_fwd.hpp>
#include <sshpp/detail/session_core.hpp>
#include <sshpp/export.hpp>
#include <sshpp/result.hpp>
#include <sshpp/sftp/attributes.hpp>
#include <sshpp/types.hpp>

#include <iterator>
#include <optional>

namespace sshpp::sftp {

class Sftp;

/// An open SFTP directory handle. See docs/design/06 §6.4.
class SSHPP_API Directory {
public:
    Directory() = default;
    ~Directory();
    Directory(Directory&&) noexcept;
    Directory& operator=(Directory&&) noexcept;
    Directory(const Directory&) = delete;

    explicit operator bool() const noexcept { return native_ != nullptr; }
    const RemotePath& path() const noexcept { return path_; }

    /// nullopt when exhausted. Errors are reported through last_error().
    std::optional<Attributes> next();
    bool eof() const noexcept;
    const ErrorInfo& last_error() const noexcept { return last_error_; }

private:
    friend class Sftp;
    Directory(native_sftp_dir n, native_sftp sftp, detail::SessionCorePtr core, RemotePath path)
        : native_(n), sftp_(sftp), core_(std::move(core)), path_(std::move(path)) {}

    native_sftp_dir         native_ = nullptr;
    native_sftp             sftp_ = nullptr;
    detail::SessionCorePtr core_;
    RemotePath              path_;
    ErrorInfo               last_error_;
};

/// InputIterator over a Directory. Skips "." and ".." by default.
class SSHPP_API DirectoryIterator {
public:
    using value_type        = Attributes;
    using difference_type   = std::ptrdiff_t;
    using pointer            = const Attributes*;
    using reference          = const Attributes&;
    using iterator_category = std::input_iterator_tag;

    DirectoryIterator() = default;
    explicit DirectoryIterator(Directory& dir, bool skip_dot_entries = true)
        : dir_(&dir), skip_dot_(skip_dot_entries) {
        advance();
    }

    const Attributes& operator*() const { return *current_; }
    const Attributes* operator->() const { return &*current_; }

    DirectoryIterator& operator++() {
        advance();
        return *this;
    }

    bool operator==(const DirectoryIterator& other) const noexcept {
        bool this_end = !current_.has_value();
        bool other_end = !other.current_.has_value();
        return this_end && other_end;
    }
    bool operator!=(const DirectoryIterator& other) const noexcept { return !(*this == other); }

private:
    void advance() {
        if (dir_ == nullptr) { current_.reset(); return; }
        for (;;) {
            current_ = dir_->next();
            if (!current_) return;
            if (!skip_dot_ || (current_->name != "." && current_->name != "..")) return;
        }
    }

    Directory*                 dir_ = nullptr;
    bool                       skip_dot_ = true;
    std::optional<Attributes> current_;
};

/// Range adapter: `for (const auto& e : sftp::DirectoryRange{std::move(dir)})`.
class SSHPP_API DirectoryRange {
public:
    explicit DirectoryRange(Directory dir) : dir_(std::move(dir)) {}
    DirectoryIterator begin() { return DirectoryIterator(dir_); }
    DirectoryIterator end() { return DirectoryIterator(); }

private:
    Directory dir_;
};

} // namespace sshpp::sftp

#if SSHPP_HEADER_ONLY
#include <sshpp/detail/directory.ipp>
#endif
