// SPDX-License-Identifier: LGPL-2.1-or-later
// Generated from src/algorithms.cpp; see docs/design/09 §9.3.
#include <sshpp/config.hpp>
// SPDX-License-Identifier: LGPL-2.1-or-later
#include <sshpp/sftp/algorithms.hpp>

#include <fstream>
#include <vector>

namespace sshpp::sftp {

namespace {

/// Rejects names that could escape the destination directory: no separators, no "..".
/// Defends against a malicious server sending unexpected entry names (cf. CVE-2019-6111).
bool is_safe_entry_name(const std::string& name) {
    if (name.empty() || name == "." || name == "..") return false;
    if (name.find('/') != std::string::npos) return false;
    if (name.find('\0') != std::string::npos) return false;
#ifdef _WIN32
    if (name.find('\\') != std::string::npos) return false;
#endif
    return true;
}

} // namespace

SSHPP_INLINE Result<std::uint64_t> try_download(Sftp& sftp, const RemotePath& remote,
                                   const std::filesystem::path& local, TransferOptions opts) {
    if (opts.overwrite == Overwrite::fail && std::filesystem::exists(local)) {
        return ErrorInfo{make_error_code(errc::invalid_argument), "destination already exists", "try_download"};
    }
    auto file = sftp.try_open(remote, OpenMode::read);
    if (!file) return file.error();

    std::ofstream out(local, std::ios::binary | std::ios::trunc);
    if (!out) {
        return ErrorInfo{make_error_code(errc::invalid_argument), "cannot open " + local.string(), "try_download"};
    }

    std::vector<std::byte> buf(opts.chunk_size);
    std::uint64_t total = 0;
    for (;;) {
        auto r = file->try_read(MutableByteView(buf.data(), buf.size()));
        if (!r) return r.error();
        if (*r == 0) break;
        out.write(reinterpret_cast<const char*>(buf.data()), static_cast<std::streamsize>(*r));
        total += *r;
        if (opts.progress) {
            Progress p;
            p.bytes_done = total;
            if (!opts.progress(p)) {
                return ErrorInfo{make_error_code(errc::cancelled), "", "try_download"};
            }
        }
    }
    out.close();

    if (opts.preserve_permissions) {
        auto attrs = file->try_stat();
        if (attrs) {
            std::error_code ec;
            std::filesystem::permissions(local, attrs->std_perms(), ec);
        }
    }
    return total;
}

SSHPP_INLINE Result<std::uint64_t> try_upload(Sftp& sftp, const std::filesystem::path& local,
                                 const RemotePath& remote, TransferOptions opts) {
    std::ifstream in(local, std::ios::binary);
    if (!in) {
        return ErrorInfo{make_error_code(errc::invalid_argument), "cannot open " + local.string(), "try_upload"};
    }

    OpenMode mode = OpenMode::write | OpenMode::create;
    mode = mode | (opts.overwrite == Overwrite::replace ? OpenMode::truncate : OpenMode::exclusive);
    std::filesystem::perms perms = std::filesystem::perms::owner_read | std::filesystem::perms::owner_write;
    if (opts.preserve_permissions) {
        std::error_code ec;
        auto local_perms = std::filesystem::status(local, ec).permissions();
        if (!ec) perms = local_perms;
    }

    auto file = sftp.try_open(remote, mode, perms);
    if (!file) return file.error();

    std::vector<char> buf(opts.chunk_size);
    std::uint64_t total = 0;
    while (in) {
        in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        std::streamsize n = in.gcount();
        if (n <= 0) break;
        auto r = file->try_write_all(ByteView(buf.data(), static_cast<std::size_t>(n)));
        if (!r) return r.error();
        total += static_cast<std::uint64_t>(n);
        if (opts.progress) {
            Progress p;
            p.bytes_done = total;
            if (!opts.progress(p)) {
                return ErrorInfo{make_error_code(errc::cancelled), "", "try_upload"};
            }
        }
    }
    return total;
}

SSHPP_INLINE Result<std::string> try_read_file(Sftp& sftp, const RemotePath& path, std::size_t limit) {
    auto file = sftp.try_open(path, OpenMode::read);
    if (!file) return file.error();

    std::string result;
    std::vector<std::byte> buf(65536);
    for (;;) {
        auto r = file->try_read(MutableByteView(buf.data(), buf.size()));
        if (!r) return r.error();
        if (*r == 0) break;
        result.append(reinterpret_cast<const char*>(buf.data()), *r);
        if (result.size() > limit) {
            return ErrorInfo{make_error_code(errc::invalid_argument), "file exceeds limit", "try_read_file"};
        }
    }
    return result;
}

SSHPP_INLINE Result<void> try_write_file(Sftp& sftp, const RemotePath& path, ByteView data,
                            std::filesystem::perms perms) {
    auto file = sftp.try_open(path, OpenMode::write | OpenMode::create | OpenMode::truncate, perms);
    if (!file) return file.error();
    return file->try_write_all(data);
}

SSHPP_INLINE Result<TreeStats> try_download_tree(Sftp& sftp, const RemotePath& remote,
                                    const std::filesystem::path& local, TransferOptions opts) {
    TreeStats stats;
    std::error_code ec;
    std::filesystem::create_directories(local, ec);

    auto listing = sftp.try_list(remote);
    if (!listing) return listing.error();

    for (const auto& entry : *listing) {
        if (!is_safe_entry_name(entry.name)) {
            ++stats.skipped;
            continue;
        }
        RemotePath remote_child = remote / entry.name;
        std::filesystem::path local_child = local / entry.name;

        // Defend against a server that walks the destination outside `local` via a
        // crafted name; weakly_canonical resolves any residual ".."/symlink tricks.
        auto canon_root = std::filesystem::weakly_canonical(local, ec);
        auto canon_child = std::filesystem::weakly_canonical(local_child, ec);
        if (ec || canon_child.string().rfind(canon_root.string(), 0) != 0) {
            ++stats.skipped;
            continue;
        }

        if (entry.is_symlink()) {
            ++stats.skipped; // symlinks are never followed or recreated by default
            continue;
        }
        if (entry.is_directory()) {
            auto sub = try_download_tree(sftp, remote_child, local_child, opts);
            if (!sub) return sub.error();
            stats.directories += 1 + sub->directories;
            stats.files += sub->files;
            stats.bytes += sub->bytes;
            stats.skipped += sub->skipped;
        } else if (entry.is_regular()) {
            auto n = try_download(sftp, remote_child, local_child, opts);
            if (!n) return n.error();
            ++stats.files;
            stats.bytes += *n;
        } else {
            ++stats.skipped;
        }
    }
    return stats;
}

} // namespace sshpp::sftp
