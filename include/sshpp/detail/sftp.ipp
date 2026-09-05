// SPDX-License-Identifier: LGPL-2.1-or-later
// Generated from src/sftp.cpp; see docs/design/09 §9.3.
#include <sshpp/config.hpp>
// SPDX-License-Identifier: LGPL-2.1-or-later
#include <sshpp/sftp/sftp.hpp>
#include <sshpp/detail/invoke.hpp>
#include <sshpp/session.hpp>

#include "sftp_internal.hpp"

#include <fcntl.h>
#include <libssh/libssh.h>
#include <libssh/sftp.h>

#include <type_traits>

namespace sshpp::sftp {

namespace {

static_assert(std::is_same_v<native_sftp, sftp_session>, "libssh changed sftp_session's definition");
static_assert(std::is_same_v<native_sftp_file, sftp_file>, "libssh changed sftp_file's definition");
static_assert(std::is_same_v<native_sftp_dir, sftp_dir>, "libssh changed sftp_dir's definition");

FileType file_type_from_native(uint8_t t) {
    switch (t) {
        case SSH_FILEXFER_TYPE_REGULAR: return FileType::regular;
        case SSH_FILEXFER_TYPE_DIRECTORY: return FileType::directory;
        case SSH_FILEXFER_TYPE_SYMLINK: return FileType::symlink;
        case SSH_FILEXFER_TYPE_SPECIAL: return FileType::special;
        case SSH_FILEXFER_TYPE_UNKNOWN:
        default: return FileType::unknown;
    }
}

int open_mode_to_posix(OpenMode mode) {
    int flags = 0;
    bool r = has_flag(mode, OpenMode::read);
    bool w = has_flag(mode, OpenMode::write);
    if (r && w) flags |= O_RDWR;
    else if (w) flags |= O_WRONLY;
    else flags |= O_RDONLY;
    if (has_flag(mode, OpenMode::create)) flags |= O_CREAT;
    if (has_flag(mode, OpenMode::truncate)) flags |= O_TRUNC;
    if (has_flag(mode, OpenMode::append)) flags |= O_APPEND;
    if (has_flag(mode, OpenMode::exclusive)) flags |= O_EXCL;
    return flags;
}

} // namespace

SSHPP_INLINE Attributes internal::attributes_from_native(sftp_attributes raw) {
    Attributes a;
    a.name = raw->name ? raw->name : "";
    a.long_name = raw->longname ? raw->longname : "";
    a.type = file_type_from_native(raw->type);
    a.size = raw->size;
    a.uid = raw->uid;
    a.gid = raw->gid;
    if (raw->owner) a.owner = raw->owner;
    if (raw->group) a.group = raw->group;
    a.permissions = raw->permissions;
    a.flags = raw->flags;
    if (raw->flags & SSH_FILEXFER_ATTR_ACCESSTIME) {
        a.atime = std::chrono::system_clock::from_time_t(static_cast<time_t>(raw->atime64));
    }
    if (raw->flags & SSH_FILEXFER_ATTR_MODIFYTIME) {
        a.mtime = std::chrono::system_clock::from_time_t(static_cast<time_t>(raw->mtime64));
    }
    if (raw->flags & SSH_FILEXFER_ATTR_CREATETIME) {
        a.createtime = std::chrono::system_clock::from_time_t(static_cast<time_t>(raw->createtime));
    }
    return a;
}

SSHPP_INLINE Sftp::Sftp(Session& session) : native_(sftp_new(session.native_handle())), core_(session.core_) {}

SSHPP_INLINE Sftp::~Sftp() {
    if (native_ != nullptr) sftp_free(native_);
    native_ = nullptr;
}

SSHPP_INLINE Sftp::Sftp(Sftp&& other) noexcept
    : native_(std::exchange(other.native_, nullptr)), core_(std::move(other.core_)) {}

SSHPP_INLINE Sftp& Sftp::operator=(Sftp&& other) noexcept {
    if (this != &other) {
        if (native_ != nullptr) sftp_free(native_);
        native_ = std::exchange(other.native_, nullptr);
        core_ = std::move(other.core_);
    }
    return *this;
}

SSHPP_INLINE Result<void> Sftp::try_init() {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::sftp_unavailable), "", "Sftp::try_init"};
    int rc = sftp_init(native_);
    if (rc != SSH_OK) {
        return detail::make_sftp_error_info(native_, core_ ? core_->raw() : nullptr, "sftp_init", SSHPP_HERE);
    }
    return {};
}

SSHPP_INLINE int Sftp::protocol_version() const noexcept {
    return native_ != nullptr ? sftp_server_version(native_) : 0;
}

SSHPP_INLINE Result<Limits> Sftp::try_limits() const {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Sftp::try_limits"};
    sftp_limits_t raw = sftp_limits(native_);
    if (raw == nullptr) {
        return detail::make_sftp_error_info(native_, core_->raw(), "sftp_limits", SSHPP_HERE);
    }
    Limits l;
    l.max_packet_length = raw->max_packet_length;
    l.max_read_length = raw->max_read_length;
    l.max_write_length = raw->max_write_length;
    l.max_open_handles = raw->max_open_handles;
    sftp_limits_free(raw);
    return l;
}

SSHPP_INLINE Result<File> Sftp::try_open(const RemotePath& path, OpenMode mode, std::filesystem::perms create_perms) {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Sftp::try_open"};
    int flags = open_mode_to_posix(mode);
    mode_t posix_mode = static_cast<mode_t>(create_perms);
    sftp_file raw = sftp_open(native_, path.str().c_str(), flags, posix_mode);
    if (raw == nullptr) {
        return detail::make_sftp_error_info(native_, core_->raw(), "sftp_open", SSHPP_HERE);
    }
    return File(raw, native_, core_, path);
}

SSHPP_INLINE Result<Attributes> Sftp::try_stat(const RemotePath& path) const {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Sftp::try_stat"};
    sftp_attributes raw = sftp_stat(native_, path.str().c_str());
    if (raw == nullptr) {
        return detail::make_sftp_error_info(native_, core_->raw(), "sftp_stat", SSHPP_HERE);
    }
    Attributes a = internal::attributes_from_native(raw);
    sftp_attributes_free(raw);
    return a;
}

SSHPP_INLINE Result<Attributes> Sftp::try_lstat(const RemotePath& path) const {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Sftp::try_lstat"};
    sftp_attributes raw = sftp_lstat(native_, path.str().c_str());
    if (raw == nullptr) {
        return detail::make_sftp_error_info(native_, core_->raw(), "sftp_lstat", SSHPP_HERE);
    }
    Attributes a = internal::attributes_from_native(raw);
    sftp_attributes_free(raw);
    return a;
}

SSHPP_INLINE Result<bool> Sftp::try_exists(const RemotePath& path) const {
    auto r = try_stat(path);
    if (r) return true;
    if (r.error().code == make_error_code(sftp_errc::no_such_file) ||
        r.error().code == make_error_code(sftp_errc::no_such_path)) {
        return false;
    }
    return r.error();
}

SSHPP_INLINE Result<void> Sftp::try_chmod(const RemotePath& path, std::filesystem::perms perms) {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Sftp::try_chmod"};
    int rc = sftp_chmod(native_, path.str().c_str(), static_cast<mode_t>(perms));
    if (rc != SSH_OK) return detail::make_sftp_error_info(native_, core_->raw(), "sftp_chmod", SSHPP_HERE);
    return {};
}

SSHPP_INLINE Result<void> Sftp::try_chown(const RemotePath& path, std::uint32_t uid, std::uint32_t gid) {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Sftp::try_chown"};
    int rc = sftp_chown(native_, path.str().c_str(), static_cast<uid_t>(uid), static_cast<gid_t>(gid));
    if (rc != SSH_OK) return detail::make_sftp_error_info(native_, core_->raw(), "sftp_chown", SSHPP_HERE);
    return {};
}

SSHPP_INLINE Result<void> Sftp::try_mkdir(const RemotePath& path, std::filesystem::perms perms) {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Sftp::try_mkdir"};
    int rc = sftp_mkdir(native_, path.str().c_str(), static_cast<mode_t>(perms));
    if (rc != SSH_OK) return detail::make_sftp_error_info(native_, core_->raw(), "sftp_mkdir", SSHPP_HERE);
    return {};
}

SSHPP_INLINE Result<void> Sftp::try_mkdir_p(const RemotePath& path, std::filesystem::perms perms) {
    const std::string& full = path.str();
    std::string current;
    if (!full.empty() && full.front() == '/') current = "/";
    std::size_t pos = 0;
    while (pos < full.size()) {
        std::size_t next = full.find('/', pos);
        std::string segment = full.substr(pos, next == std::string::npos ? std::string::npos : next - pos);
        if (!segment.empty()) {
            if (!current.empty() && current.back() != '/') current += '/';
            current += segment;
            auto exists = try_exists(current);
            if (!exists) return exists.error();
            if (!*exists) {
                auto made = try_mkdir(current, perms);
                if (!made) return made;
            }
        }
        if (next == std::string::npos) break;
        pos = next + 1;
    }
    return {};
}

SSHPP_INLINE Result<void> Sftp::try_rmdir(const RemotePath& path) {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Sftp::try_rmdir"};
    int rc = sftp_rmdir(native_, path.str().c_str());
    if (rc != SSH_OK) return detail::make_sftp_error_info(native_, core_->raw(), "sftp_rmdir", SSHPP_HERE);
    return {};
}

SSHPP_INLINE Result<void> Sftp::try_remove(const RemotePath& path) {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Sftp::try_remove"};
    int rc = sftp_unlink(native_, path.str().c_str());
    if (rc != SSH_OK) return detail::make_sftp_error_info(native_, core_->raw(), "sftp_unlink", SSHPP_HERE);
    return {};
}

SSHPP_INLINE Result<void> Sftp::try_rename(const RemotePath& from, const RemotePath& to) {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Sftp::try_rename"};
    int rc = sftp_rename(native_, from.str().c_str(), to.str().c_str());
    if (rc != SSH_OK) return detail::make_sftp_error_info(native_, core_->raw(), "sftp_rename", SSHPP_HERE);
    return {};
}

SSHPP_INLINE Result<void> Sftp::try_symlink(const RemotePath& target, const RemotePath& link) {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Sftp::try_symlink"};
    int rc = sftp_symlink(native_, target.str().c_str(), link.str().c_str());
    if (rc != SSH_OK) return detail::make_sftp_error_info(native_, core_->raw(), "sftp_symlink", SSHPP_HERE);
    return {};
}

SSHPP_INLINE Result<RemotePath> Sftp::try_readlink(const RemotePath& path) const {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Sftp::try_readlink"};
    char* raw = sftp_readlink(native_, path.str().c_str());
    if (raw == nullptr) {
        return detail::make_sftp_error_info(native_, core_->raw(), "sftp_readlink", SSHPP_HERE);
    }
    RemotePath result{std::string(raw)};
    ssh_string_free_char(raw);
    return result;
}

SSHPP_INLINE Result<RemotePath> Sftp::try_canonicalize(const RemotePath& path) const {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Sftp::try_canonicalize"};
    char* raw = sftp_canonicalize_path(native_, path.str().c_str());
    if (raw == nullptr) {
        return detail::make_sftp_error_info(native_, core_->raw(), "sftp_canonicalize_path", SSHPP_HERE);
    }
    RemotePath result{std::string(raw)};
    ssh_string_free_char(raw);
    return result;
}

SSHPP_INLINE Result<Directory> Sftp::try_open_directory(const RemotePath& path) const {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Sftp::try_open_directory"};
    sftp_dir raw = sftp_opendir(native_, path.str().c_str());
    if (raw == nullptr) {
        return detail::make_sftp_error_info(native_, core_->raw(), "sftp_opendir", SSHPP_HERE);
    }
    return Directory(raw, native_, core_, path);
}

SSHPP_INLINE Result<std::vector<Attributes>> Sftp::try_list(const RemotePath& path) const {
    auto dir = try_open_directory(path);
    if (!dir) return dir.error();
    std::vector<Attributes> result;
    for (;;) {
        auto entry = dir->next();
        if (!entry) break;
        if (entry->name == "." || entry->name == "..") continue;
        result.push_back(std::move(*entry));
    }
    if (dir->last_error()) return dir->last_error();
    return result;
}

SSHPP_INLINE Result<DirectoryRange> entries(Sftp& sftp, const RemotePath& path) {
    auto dir = sftp.try_open_directory(path);
    if (!dir) return dir.error();
    return DirectoryRange(std::move(*dir));
}

} // namespace sshpp::sftp
