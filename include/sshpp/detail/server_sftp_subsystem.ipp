// SPDX-License-Identifier: LGPL-2.1-or-later
// Generated from src/server_sftp_subsystem.cpp; see docs/design/09 §9.3.
#pragma once

#include <sshpp/server/sftp_subsystem.hpp>
#include <sshpp/channel.hpp>
#include <sshpp/detail/invoke.hpp>

#include <libssh/libssh.h>
// sftp_server_new/_init/_free are declared in sftp.h only behind an
// internal-looking `#ifdef WITH_SERVER` guard that libssh never exposes via a
// public config header. The symbols are always present in a libssh built
// with server support (verified via SSHPP_HAS_SERVER at configure time), so
// define the guard ourselves to unlock the declarations.
#define WITH_SERVER 1
#include <libssh/sftp.h>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <ctime>
#include <memory>
#include <string>
#include <vector>

namespace sshpp::server {

namespace {

struct HandleEntry {
    bool                  is_dir = false;
    int                   fd = -1;
    DIR*                  dir = nullptr;
    std::filesystem::path path;
};

void close_handle(HandleEntry* h) {
    if (h == nullptr) return;
    if (h->is_dir) {
        if (h->dir != nullptr) ::closedir(h->dir);
    } else {
        if (h->fd >= 0) ::close(h->fd);
    }
    delete h;
}

void fill_attributes(sftp_attributes attr, const struct stat& st) {
    std::memset(attr, 0, sizeof(*attr));
    attr->flags = SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_UIDGID | SSH_FILEXFER_ATTR_PERMISSIONS |
                 SSH_FILEXFER_ATTR_ACMODTIME;
    attr->size = static_cast<std::uint64_t>(st.st_size);
    attr->uid = st.st_uid;
    attr->gid = st.st_gid;
    attr->permissions = st.st_mode;
    attr->atime = static_cast<std::uint32_t>(st.st_atime);
    attr->mtime = static_cast<std::uint32_t>(st.st_mtime);
    if (S_ISREG(st.st_mode)) attr->type = SSH_FILEXFER_TYPE_REGULAR;
    else if (S_ISDIR(st.st_mode)) attr->type = SSH_FILEXFER_TYPE_DIRECTORY;
    else if (S_ISLNK(st.st_mode)) attr->type = SSH_FILEXFER_TYPE_SYMLINK;
    else attr->type = SSH_FILEXFER_TYPE_SPECIAL;
}

std::string format_longname(const std::string& name, const struct stat& st) {
    char perms[11] = "----------";
    if (S_ISDIR(st.st_mode)) perms[0] = 'd';
    else if (S_ISLNK(st.st_mode)) perms[0] = 'l';
    mode_t m = st.st_mode;
    const char* bits = "rwxrwxrwx";
    for (int i = 0; i < 9; ++i) {
        if (m & (0400 >> i)) perms[i + 1] = bits[i];
    }
    char buf[512];
    std::snprintf(buf, sizeof(buf), "%s %3d %-8u %-8u %10lld %s", perms, 1,
                 static_cast<unsigned>(st.st_uid), static_cast<unsigned>(st.st_gid),
                 static_cast<long long>(st.st_size), name.c_str());
    return buf;
}

int posix_open_flags(std::uint32_t sftp_flags) {
    int flags = 0;
    if ((sftp_flags & SSH_FXF_READ) != 0 && (sftp_flags & SSH_FXF_WRITE) != 0) flags = O_RDWR;
    else if ((sftp_flags & SSH_FXF_WRITE) != 0) flags = O_WRONLY;
    else flags = O_RDONLY;
    if (sftp_flags & SSH_FXF_CREAT) flags |= O_CREAT;
    if (sftp_flags & SSH_FXF_TRUNC) flags |= O_TRUNC;
    if (sftp_flags & SSH_FXF_EXCL) flags |= O_EXCL;
    if (sftp_flags & SSH_FXF_APPEND) flags |= O_APPEND;
    return flags;
}

} // namespace

SSHPP_INLINE SftpSubsystemHandler::~SftpSubsystemHandler() {
    for (auto& t : worker_threads_) {
        if (t.joinable()) t.join();
    }
}

SSHPP_INLINE bool SftpSubsystemHandler::on_subsystem_request(Channel& channel, std::string_view name) {
    if (name != "sftp") return false;
    // Must not block here: the channel-request "success" reply for this very
    // subsystem request is sent by libssh right after this callback returns,
    // and the client won't send its first SFTP packet before receiving it.
    // Run the actual (blocking) SFTP server loop on a dedicated thread instead.
    worker_threads_.emplace_back([this, &channel] { (void)try_serve(channel); });
    return true;
}

SSHPP_INLINE void SftpSubsystemHandler::on_close(Channel&) {}

namespace {

/// Joins `root` with a client-supplied sftp path and verifies the result stays
/// under `root` once symlinks/`.."` are resolved. See the class-level comment
/// in sftp_subsystem.hpp.
Result<std::filesystem::path> resolve_sftp_path(const std::filesystem::path& root, std::string_view sftp_path) {
    std::string clean(sftp_path);
    std::size_t start = clean.find_first_not_of('/');
    std::filesystem::path rel = (start == std::string::npos) ? std::filesystem::path(".")
                                                              : std::filesystem::path(clean.substr(start));
    std::filesystem::path joined = root / rel;

    std::error_code ec;
    std::filesystem::path canon_root = std::filesystem::weakly_canonical(root, ec);
    if (ec) return ErrorInfo{make_error_code(errc::invalid_argument), ec.message(), "resolve_sftp_path"};
    std::filesystem::path canon = std::filesystem::weakly_canonical(joined, ec);
    if (ec) return ErrorInfo{make_error_code(errc::invalid_argument), ec.message(), "resolve_sftp_path"};

    auto mismatch = std::mismatch(canon_root.begin(), canon_root.end(), canon.begin(), canon.end());
    if (mismatch.first != canon_root.end()) {
        return ErrorInfo{make_error_code(errc::invalid_argument), "path escapes the sftp root", "resolve_sftp_path"};
    }
    return canon;
}

std::string to_client_path(const std::filesystem::path& root, const std::filesystem::path& canon) {
    std::error_code ec;
    auto canon_root = std::filesystem::weakly_canonical(root, ec);
    auto rel = canon.lexically_relative(canon_root);
    if (ec || rel.empty() || rel == ".") return "/";
    return "/" + rel.generic_string();
}

} // namespace

SSHPP_INLINE Result<void> SftpSubsystemHandler::try_serve(Channel& channel) const {
    // Serializes every libssh call this function makes against the owning
    // Session's Event/message poll loop, which may run concurrently on a
    // different thread and touches the same underlying ssh_session (raw
    // ssh_channel_read()s here vs. ssh_event_dopoll() there are not safe to
    // interleave). See Channel::session_mutex() and Session::try_poll().
    std::lock_guard<std::recursive_mutex> session_lock(channel.session_mutex());

    ssh_session raw_session = ssh_channel_get_session(channel.native_handle());
    sftp_session sftp = sftp_server_new(raw_session, channel.native_handle());
    if (sftp == nullptr) {
        return ErrorInfo{make_error_code(errc::sftp_unavailable), "", "sftp_server_new"};
    }
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
    if (sftp_server_init(sftp) != 0) {
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
        sftp_server_free(sftp);
        return ErrorInfo{make_error_code(errc::sftp_unavailable), "", "sftp_server_init"};
    }
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

    for (;;) {
        sftp_client_message msg = sftp_get_client_message(sftp);
        if (msg == nullptr) break;

        const std::uint8_t type = sftp_client_message_get_type(msg);
        const char* filename_c = sftp_client_message_get_filename(msg);
        std::string_view filename = filename_c != nullptr ? std::string_view(filename_c) : std::string_view{};

        auto deny_if_read_only = [&]() -> bool {
            if (!options_.read_only) return false;
            sftp_reply_status(msg, SSH_FX_PERMISSION_DENIED, "read-only sftp root");
            return true;
        };

        switch (type) {
            case SSH_FXP_REALPATH: {
                auto resolved = resolve_sftp_path(options_.root, filename);
                if (!resolved) {
                    sftp_reply_status(msg, SSH_FX_NO_SUCH_FILE, "");
                    break;
                }
                sftp_attributes_struct attr{};
                struct stat st{};
                if (::lstat(resolved->c_str(), &st) == 0) fill_attributes(&attr, st);
                std::string client_path = to_client_path(options_.root, *resolved);
                sftp_reply_name(msg, client_path.c_str(), &attr);
                break;
            }
            case SSH_FXP_STAT:
            case SSH_FXP_LSTAT: {
                auto resolved = resolve_sftp_path(options_.root, filename);
                if (!resolved) {
                    sftp_reply_status(msg, SSH_FX_NO_SUCH_FILE, "");
                    break;
                }
                struct stat st{};
                int rc = (type == SSH_FXP_LSTAT || !options_.follow_symlinks_out_of_root)
                            ? ::lstat(resolved->c_str(), &st)
                            : ::stat(resolved->c_str(), &st);
                if (rc != 0) {
                    sftp_reply_status(msg, SSH_FX_NO_SUCH_FILE, std::strerror(errno));
                    break;
                }
                sftp_attributes_struct attr{};
                fill_attributes(&attr, st);
                sftp_reply_attr(msg, &attr);
                break;
            }
            case SSH_FXP_FSTAT: {
                auto* handle = static_cast<HandleEntry*>(sftp_handle(sftp, msg->handle));
                if (handle == nullptr) {
                    sftp_reply_status(msg, SSH_FX_INVALID_HANDLE, "");
                    break;
                }
                struct stat st{};
                int rc = handle->is_dir ? ::stat(handle->path.c_str(), &st)
                                       : ::fstat(handle->fd, &st);
                if (rc != 0) {
                    sftp_reply_status(msg, SSH_FX_FAILURE, std::strerror(errno));
                    break;
                }
                sftp_attributes_struct attr{};
                fill_attributes(&attr, st);
                sftp_reply_attr(msg, &attr);
                break;
            }
            case SSH_FXP_OPENDIR: {
                auto resolved = resolve_sftp_path(options_.root, filename);
                if (!resolved) {
                    sftp_reply_status(msg, SSH_FX_NO_SUCH_FILE, "");
                    break;
                }
                DIR* dir = ::opendir(resolved->c_str());
                if (dir == nullptr) {
                    sftp_reply_status(msg, SSH_FX_NO_SUCH_FILE, std::strerror(errno));
                    break;
                }
                auto* entry = new HandleEntry{};
                entry->is_dir = true;
                entry->dir = dir;
                entry->path = *resolved;
                ssh_string handle_str = sftp_handle_alloc(sftp, entry);
                if (handle_str == nullptr) {
                    close_handle(entry);
                    sftp_reply_status(msg, SSH_FX_FAILURE, "");
                    break;
                }
                sftp_reply_handle(msg, handle_str);
                ssh_string_free(handle_str);
                break;
            }
            case SSH_FXP_READDIR: {
                auto* handle = static_cast<HandleEntry*>(sftp_handle(sftp, msg->handle));
                if (handle == nullptr || !handle->is_dir) {
                    sftp_reply_status(msg, SSH_FX_INVALID_HANDLE, "");
                    break;
                }
                errno = 0;
                dirent* de = ::readdir(handle->dir);
                if (de == nullptr) {
                    sftp_reply_status(msg, SSH_FX_EOF, "");
                    break;
                }
                int added = 0;
                for (; de != nullptr; de = ::readdir(handle->dir)) {
                    std::string name = de->d_name;
                    struct stat st{};
                    std::filesystem::path child = handle->path / name;
                    if (::lstat(child.c_str(), &st) != 0) continue;
                    sftp_attributes_struct attr{};
                    fill_attributes(&attr, st);
                    std::string longname = format_longname(name, st);
                    sftp_reply_names_add(msg, name.c_str(), longname.c_str(), &attr);
                    if (++added >= 64) break; // bound the reply batch size
                }
                sftp_reply_names(msg);
                break;
            }
            case SSH_FXP_OPEN: {
                if (((msg->flags & (SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_TRUNC | SSH_FXF_APPEND)) != 0) &&
                    deny_if_read_only()) {
                    break;
                }
                auto resolved = resolve_sftp_path(options_.root, filename);
                if (!resolved) {
                    sftp_reply_status(msg, SSH_FX_NO_SUCH_FILE, "");
                    break;
                }
                mode_t mode = 0644;
                if (msg->attr != nullptr && (msg->attr->flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0) {
                    mode = msg->attr->permissions & 07777;
                }
                int fd = ::open(resolved->c_str(), posix_open_flags(msg->flags), mode);
                if (fd < 0) {
                    sftp_reply_status(msg, errno == ENOENT ? SSH_FX_NO_SUCH_FILE : SSH_FX_FAILURE,
                                     std::strerror(errno));
                    break;
                }
                auto* entry = new HandleEntry{};
                entry->is_dir = false;
                entry->fd = fd;
                entry->path = *resolved;
                ssh_string handle_str = sftp_handle_alloc(sftp, entry);
                if (handle_str == nullptr) {
                    close_handle(entry);
                    sftp_reply_status(msg, SSH_FX_FAILURE, "");
                    break;
                }
                sftp_reply_handle(msg, handle_str);
                ssh_string_free(handle_str);
                break;
            }
            case SSH_FXP_READ: {
                auto* handle = static_cast<HandleEntry*>(sftp_handle(sftp, msg->handle));
                if (handle == nullptr || handle->is_dir) {
                    sftp_reply_status(msg, SSH_FX_INVALID_HANDLE, "");
                    break;
                }
                std::vector<char> buf(std::min<std::uint32_t>(msg->len, 64 * 1024));
                ssize_t n = ::pread(handle->fd, buf.data(), buf.size(), static_cast<off_t>(msg->offset));
                if (n < 0) {
                    sftp_reply_status(msg, SSH_FX_FAILURE, std::strerror(errno));
                } else if (n == 0) {
                    sftp_reply_status(msg, SSH_FX_EOF, "");
                } else {
                    sftp_reply_data(msg, buf.data(), static_cast<int>(n));
                }
                break;
            }
            case SSH_FXP_WRITE: {
                if (deny_if_read_only()) break;
                auto* handle = static_cast<HandleEntry*>(sftp_handle(sftp, msg->handle));
                if (handle == nullptr || handle->is_dir) {
                    sftp_reply_status(msg, SSH_FX_INVALID_HANDLE, "");
                    break;
                }
                const char* data = sftp_client_message_get_data(msg);
                // NOTE: msg->len is the *requested* length for READ; for WRITE
                // the payload's actual length is the data string's own length.
                std::uint32_t len = msg->data != nullptr ? static_cast<std::uint32_t>(ssh_string_len(msg->data))
                                                         : 0;
                if (options_.max_file_size != 0 && msg->offset + len > options_.max_file_size) {
                    sftp_reply_status(msg, SSH_FX_PERMISSION_DENIED, "file too large");
                    break;
                }
                ssize_t n = ::pwrite(handle->fd, data, len, static_cast<off_t>(msg->offset));
                if (n < 0) {
                    sftp_reply_status(msg, SSH_FX_FAILURE, std::strerror(errno));
                } else {
                    sftp_reply_status(msg, SSH_FX_OK, "");
                }
                break;
            }
            case SSH_FXP_CLOSE: {
                auto* handle = static_cast<HandleEntry*>(sftp_handle(sftp, msg->handle));
                if (handle != nullptr) {
                    sftp_handle_remove(sftp, handle);
                    close_handle(handle);
                }
                sftp_reply_status(msg, SSH_FX_OK, "");
                break;
            }
            case SSH_FXP_REMOVE: {
                if (deny_if_read_only()) break;
                auto resolved = resolve_sftp_path(options_.root, filename);
                if (!resolved || ::unlink(resolved->c_str()) != 0) {
                    sftp_reply_status(msg, SSH_FX_NO_SUCH_FILE, "");
                } else {
                    sftp_reply_status(msg, SSH_FX_OK, "");
                }
                break;
            }
            case SSH_FXP_MKDIR: {
                if (deny_if_read_only()) break;
                auto resolved = resolve_sftp_path(options_.root, filename);
                mode_t mode = 0755;
                if (resolved && msg->attr != nullptr && (msg->attr->flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0) {
                    mode = msg->attr->permissions & 07777;
                }
                if (!resolved || ::mkdir(resolved->c_str(), mode) != 0) {
                    sftp_reply_status(msg, SSH_FX_FAILURE, resolved ? std::strerror(errno) : "invalid path");
                } else {
                    sftp_reply_status(msg, SSH_FX_OK, "");
                }
                break;
            }
            case SSH_FXP_RMDIR: {
                if (deny_if_read_only()) break;
                auto resolved = resolve_sftp_path(options_.root, filename);
                if (!resolved || ::rmdir(resolved->c_str()) != 0) {
                    sftp_reply_status(msg, SSH_FX_FAILURE, "");
                } else {
                    sftp_reply_status(msg, SSH_FX_OK, "");
                }
                break;
            }
            case SSH_FXP_RENAME: {
                if (deny_if_read_only()) break;
                auto from = resolve_sftp_path(options_.root, filename);
                const char* new_path_c = sftp_client_message_get_data(msg);
                auto to = resolve_sftp_path(options_.root, new_path_c != nullptr ? new_path_c : "");
                if (!from || !to || ::rename(from->c_str(), to->c_str()) != 0) {
                    sftp_reply_status(msg, SSH_FX_FAILURE, "");
                } else {
                    sftp_reply_status(msg, SSH_FX_OK, "");
                }
                break;
            }
            case SSH_FXP_READLINK: {
                auto resolved = resolve_sftp_path(options_.root, filename);
                char buf[4096];
                ssize_t n = resolved ? ::readlink(resolved->c_str(), buf, sizeof(buf) - 1) : -1;
                if (n < 0) {
                    sftp_reply_status(msg, SSH_FX_NO_SUCH_FILE, "");
                } else {
                    buf[n] = '\0';
                    sftp_attributes_struct attr{};
                    sftp_reply_name(msg, buf, &attr);
                }
                break;
            }
            case SSH_FXP_SYMLINK: {
                if (deny_if_read_only()) break;
                // For SYMLINK, libssh's client_message repurposes filename as the
                // link target and the data field as the new link path.
                const char* link_path_c = sftp_client_message_get_data(msg);
                auto link_path = resolve_sftp_path(options_.root, link_path_c != nullptr ? link_path_c : "");
                if (!link_path || ::symlink(std::string(filename).c_str(), link_path->c_str()) != 0) {
                    sftp_reply_status(msg, SSH_FX_FAILURE, "");
                } else {
                    sftp_reply_status(msg, SSH_FX_OK, "");
                }
                break;
            }
            default:
                sftp_reply_status(msg, SSH_FX_OP_UNSUPPORTED, "unsupported sftp request");
                break;
        }

        sftp_client_message_free(msg);
    }

    // Known minor leak (~192 bytes/session): libssh's sftp_server_init()
    // allocates an internal ssh_buffer that sftp_server_free() does not
    // release in the version this was tested against (confirmed via
    // LeakSanitizer stack traces pointing entirely into libssh, not into any
    // sshpp-owned allocation) - not something this wrapper can fix without
    // reaching into libssh's private sftp_session_struct internals.
    sftp_server_free(sftp);
    return {};
}

} // namespace sshpp::server
