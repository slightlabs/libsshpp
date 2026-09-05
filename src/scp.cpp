// SPDX-License-Identifier: LGPL-2.1-or-later
//
// libssh's ssh_scp_* API is marked deprecated upstream (SCP itself is legacy,
// see scp.hpp); the deprecation warnings are expected here and suppressed.
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

#include <sshpp/scp/scp.hpp>
#include <sshpp/detail/invoke.hpp>
#include <sshpp/session.hpp>

#include <libssh/libssh.h>

#include <algorithm>
#include <fstream>
#include <istream>
#include <ostream>
#include <type_traits>
#include <vector>

namespace sshpp::scp {

namespace {

static_assert(std::is_same_v<native_scp, ssh_scp>, "libssh changed ssh_scp's definition");

int mode_to_native(Mode mode) {
    switch (mode) {
        case Mode::read: return SSH_SCP_READ;
        case Mode::write: return SSH_SCP_WRITE;
        case Mode::read_recursive: return SSH_SCP_READ | SSH_SCP_RECURSIVE;
        case Mode::write_recursive: return SSH_SCP_WRITE | SSH_SCP_RECURSIVE;
    }
    return SSH_SCP_READ;
}

bool is_safe_entry_name(const std::string& name) {
    if (name.empty() || name == "." || name == "..") return false;
    if (name.find('/') != std::string::npos) return false;
    return true;
}

} // namespace

// ---------------------------------------------------------------- Reader ----

Reader::Reader(Session& session, const RemotePath& location, bool recursive)
    : native_(ssh_scp_new(session.native_handle(),
                          mode_to_native(recursive ? Mode::read_recursive : Mode::read),
                          location.str().c_str())),
      core_(session.core_) {}

Reader::~Reader() {
    if (native_ != nullptr) {
        ssh_scp_close(native_);
        ssh_scp_free(native_);
    }
}

Reader::Reader(Reader&& other) noexcept
    : native_(std::exchange(other.native_, nullptr)), core_(std::move(other.core_)) {}

Reader& Reader::operator=(Reader&& other) noexcept {
    if (this != &other) {
        if (native_ != nullptr) { ssh_scp_close(native_); ssh_scp_free(native_); }
        native_ = std::exchange(other.native_, nullptr);
        core_ = std::move(other.core_);
    }
    return *this;
}

Result<void> Reader::try_init() {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::scp_error), "", "Reader::try_init"};
    if (ssh_scp_init(native_) != SSH_OK) {
        return detail::make_error_info(core_->raw(), "ssh_scp_init", SSHPP_HERE, errc::scp_error);
    }
    return {};
}

Result<std::optional<Request>> Reader::try_next() {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Reader::try_next"};
    int rc = ssh_scp_pull_request(native_);
    switch (rc) {
        case SSH_SCP_REQUEST_EOF:
            return std::optional<Request>{};
        case SSH_ERROR:
            return detail::make_error_info(core_->raw(), "ssh_scp_pull_request", SSHPP_HERE, errc::scp_error);
        default:
            break;
    }
    Request req;
    const char* name = ssh_scp_request_get_filename(native_);
    req.name = name ? name : "";
    req.permissions = static_cast<std::filesystem::perms>(ssh_scp_request_get_permissions(native_) & 07777);
    switch (rc) {
        case SSH_SCP_REQUEST_NEWDIR: req.type = RequestType::new_directory; break;
        case SSH_SCP_REQUEST_NEWFILE:
            req.type = RequestType::new_file;
            req.size = ssh_scp_request_get_size64(native_);
            break;
        case SSH_SCP_REQUEST_ENDDIR: req.type = RequestType::end_directory; break;
        case SSH_SCP_REQUEST_WARNING: {
            req.type = RequestType::warning;
            const char* w = ssh_scp_request_get_warning(native_);
            req.warning = w ? w : "";
            break;
        }
        default:
            return detail::make_error_info(core_->raw(), "ssh_scp_pull_request", SSHPP_HERE, errc::scp_error);
    }
    return std::optional<Request>{std::move(req)};
}

Result<void> Reader::try_accept() {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Reader::try_accept"};
    if (ssh_scp_accept_request(native_) != SSH_OK) {
        return detail::make_error_info(core_->raw(), "ssh_scp_accept_request", SSHPP_HERE, errc::scp_error);
    }
    return {};
}

Result<void> Reader::try_deny(std::string_view reason) {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Reader::try_deny"};
    std::string r(reason);
    if (ssh_scp_deny_request(native_, r.c_str()) != SSH_OK) {
        return detail::make_error_info(core_->raw(), "ssh_scp_deny_request", SSHPP_HERE, errc::scp_error);
    }
    return {};
}

Result<std::size_t> Reader::try_read(MutableByteView buf) {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Reader::try_read"};
    int n = ssh_scp_read(native_, buf.data(), buf.size());
    if (n == SSH_ERROR) {
        return detail::make_error_info(core_->raw(), "ssh_scp_read", SSHPP_HERE, errc::scp_error);
    }
    return static_cast<std::size_t>(n);
}

Result<std::uint64_t> Reader::try_read_to(std::ostream& out, ProgressCallback progress) {
    std::vector<std::byte> buf(64 * 1024);
    std::uint64_t total = 0;
    auto req_result = try_next();
    if (!req_result) return req_result.error();
    if (!*req_result || (*req_result)->type != RequestType::new_file) {
        return ErrorInfo{make_error_code(errc::scp_error), "expected a file request", "Reader::try_read_to"};
    }
    std::uint64_t size = (*req_result)->size;

    auto accept_result = try_accept();
    if (!accept_result) return accept_result.error();

    while (total < size) {
        std::size_t want = static_cast<std::size_t>(std::min<std::uint64_t>(buf.size(), size - total));
        auto r = try_read(MutableByteView(buf.data(), want));
        if (!r) return r.error();
        if (*r == 0) break;
        out.write(reinterpret_cast<const char*>(buf.data()), static_cast<std::streamsize>(*r));
        total += *r;
        if (progress) {
            Progress p;
            p.bytes_done = total;
            p.bytes_total = size;
            if (!progress(p)) return ErrorInfo{make_error_code(errc::cancelled), "", "Reader::try_read_to"};
        }
    }
    return total;
}

// ---------------------------------------------------------------- Writer ----

Writer::Writer(Session& session, const RemotePath& destination_dir, bool recursive)
    : native_(ssh_scp_new(session.native_handle(),
                          mode_to_native(recursive ? Mode::write_recursive : Mode::write),
                          destination_dir.str().c_str())),
      core_(session.core_) {}

Writer::~Writer() {
    if (native_ != nullptr) {
        ssh_scp_close(native_);
        ssh_scp_free(native_);
    }
}

Writer::Writer(Writer&& other) noexcept
    : native_(std::exchange(other.native_, nullptr)), core_(std::move(other.core_)) {}

Writer& Writer::operator=(Writer&& other) noexcept {
    if (this != &other) {
        if (native_ != nullptr) { ssh_scp_close(native_); ssh_scp_free(native_); }
        native_ = std::exchange(other.native_, nullptr);
        core_ = std::move(other.core_);
    }
    return *this;
}

Result<void> Writer::try_init() {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::scp_error), "", "Writer::try_init"};
    if (ssh_scp_init(native_) != SSH_OK) {
        return detail::make_error_info(core_->raw(), "ssh_scp_init", SSHPP_HERE, errc::scp_error);
    }
    return {};
}

Result<void> Writer::try_push_file(std::string_view name, std::uint64_t size, std::filesystem::perms perms) {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Writer::try_push_file"};
    std::string n(name);
    if (ssh_scp_push_file64(native_, n.c_str(), size, static_cast<int>(perms)) != SSH_OK) {
        return detail::make_error_info(core_->raw(), "ssh_scp_push_file64", SSHPP_HERE, errc::scp_error);
    }
    return {};
}

Result<void> Writer::try_push_directory(std::string_view name, std::filesystem::perms perms) {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Writer::try_push_directory"};
    std::string n(name);
    if (ssh_scp_push_directory(native_, n.c_str(), static_cast<int>(perms)) != SSH_OK) {
        return detail::make_error_info(core_->raw(), "ssh_scp_push_directory", SSHPP_HERE, errc::scp_error);
    }
    return {};
}

Result<void> Writer::try_leave_directory() {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Writer::try_leave_directory"};
    if (ssh_scp_leave_directory(native_) != SSH_OK) {
        return detail::make_error_info(core_->raw(), "ssh_scp_leave_directory", SSHPP_HERE, errc::scp_error);
    }
    return {};
}

Result<void> Writer::try_write(ByteView data) {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Writer::try_write"};
    if (ssh_scp_write(native_, data.data(), data.size()) != SSH_OK) {
        return detail::make_error_info(core_->raw(), "ssh_scp_write", SSHPP_HERE, errc::scp_error);
    }
    return {};
}

Result<std::uint64_t> Writer::try_write_from(std::istream& in, std::uint64_t size, ProgressCallback progress) {
    std::vector<char> buf(64 * 1024);
    std::uint64_t total = 0;
    while (total < size && in) {
        std::size_t want = static_cast<std::size_t>(std::min<std::uint64_t>(buf.size(), size - total));
        in.read(buf.data(), static_cast<std::streamsize>(want));
        std::streamsize n = in.gcount();
        if (n <= 0) break;
        auto r = try_write(ByteView(buf.data(), static_cast<std::size_t>(n)));
        if (!r) return r.error();
        total += static_cast<std::uint64_t>(n);
        if (progress) {
            Progress p;
            p.bytes_done = total;
            p.bytes_total = size;
            if (!progress(p)) return ErrorInfo{make_error_code(errc::cancelled), "", "Writer::try_write_from"};
        }
    }
    if (total != size) {
        return ErrorInfo{make_error_code(errc::scp_error), "short local read", "Writer::try_write_from"};
    }
    return total;
}

// ------------------------------------------------------------- Layer 4 -----

Result<std::uint64_t> try_download(Session& session, const RemotePath& remote,
                                   const std::filesystem::path& local, ProgressCallback progress) {
    Reader reader(session, remote, false);
    auto init_result = reader.try_init();
    if (!init_result) return init_result.error();

    auto req_result = reader.try_next();
    if (!req_result) return req_result.error();
    if (!*req_result || !is_safe_entry_name((*req_result)->name)) {
        return ErrorInfo{make_error_code(errc::scp_error), "unexpected or unsafe remote entry", "scp::try_download"};
    }
    if ((*req_result)->type != RequestType::new_file) {
        return ErrorInfo{make_error_code(errc::scp_error), "remote path is not a regular file", "scp::try_download"};
    }
    std::uint64_t size = (*req_result)->size;

    auto accept_result = reader.try_accept();
    if (!accept_result) return accept_result.error();

    std::ofstream out(local, std::ios::binary | std::ios::trunc);
    if (!out) {
        return ErrorInfo{make_error_code(errc::invalid_argument), "cannot open " + local.string(), "scp::try_download"};
    }

    std::vector<std::byte> buf(64 * 1024);
    std::uint64_t total = 0;
    while (total < size) {
        std::size_t want = static_cast<std::size_t>(std::min<std::uint64_t>(buf.size(), size - total));
        auto r = reader.try_read(MutableByteView(buf.data(), want));
        if (!r) return r.error();
        if (*r == 0) break;
        out.write(reinterpret_cast<const char*>(buf.data()), static_cast<std::streamsize>(*r));
        total += *r;
        if (progress) {
            Progress p;
            p.bytes_done = total;
            p.bytes_total = size;
            if (!progress(p)) return ErrorInfo{make_error_code(errc::cancelled), "", "scp::try_download"};
        }
    }
    return total;
}

Result<std::uint64_t> try_upload(Session& session, const std::filesystem::path& local,
                                 const RemotePath& remote, ProgressCallback progress) {
    std::error_code ec;
    auto file_size = std::filesystem::file_size(local, ec);
    if (ec) {
        return ErrorInfo{make_error_code(errc::invalid_argument), "cannot stat " + local.string(), "scp::try_upload"};
    }
    auto perms = std::filesystem::status(local, ec).permissions();
    if (ec) perms = std::filesystem::perms::owner_read | std::filesystem::perms::owner_write;

    Writer writer(session, remote, false);
    auto init_result = writer.try_init();
    if (!init_result) return init_result.error();

    auto push_result = writer.try_push_file(local.filename().string(), file_size, perms);
    if (!push_result) return push_result.error();

    std::ifstream in(local, std::ios::binary);
    if (!in) {
        return ErrorInfo{make_error_code(errc::invalid_argument), "cannot open " + local.string(), "scp::try_upload"};
    }
    return writer.try_write_from(in, file_size, progress);
}

} // namespace sshpp::scp
