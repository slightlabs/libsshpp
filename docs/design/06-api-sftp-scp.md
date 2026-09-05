# 06 — SFTP and SCP API

Headers: `<sshpp/sftp/sftp.hpp>`, `<sshpp/sftp/file.hpp>`, `<sshpp/sftp/directory.hpp>`,
`<sshpp/sftp/attributes.hpp>`, `<sshpp/sftp/algorithms.hpp>`, `<sshpp/scp/scp.hpp>`.

Enabled by `LIBSSHPP_WITH_SFTP` / `LIBSSHPP_WITH_SCP` (both `ON` by default).

## 6.1 `sftp::Attributes`

libssh's `sftp_attributes` is a heap-allocated C struct with `char*` fields that must be freed
with `sftp_attributes_free`. We copy it into a value type at the boundary — the extra copy is
irrelevant next to a network round-trip, and it removes an entire class of lifetime bugs.

```cpp
namespace sshpp::sftp {

enum class FileType { regular, directory, symlink, special, unknown,
                      socket, char_device, block_device, fifo };

struct SSHPP_API Attributes {
    std::string   name;                 // basename, as returned by readdir
    std::string   long_name;            // ls -l style line (readdir only)
    FileType      type = FileType::unknown;
    std::uint64_t size = 0;
    std::uint32_t uid = 0, gid = 0;
    std::optional<std::string> owner, group;    // SFTP v4+ textual names
    std::uint32_t permissions = 0;              // POSIX mode bits
    std::uint32_t flags = 0;                    // SSH_FILEXFER_ATTR_* actually present

    std::optional<std::chrono::system_clock::time_point> atime, mtime, createtime;
    std::optional<std::chrono::nanoseconds> atime_ns, mtime_ns;

    std::vector<std::pair<std::string, std::string>> extended;  // extended_type/data pairs
    std::optional<std::string> acl;

    bool is_regular()   const noexcept;
    bool is_directory() const noexcept;
    bool is_symlink()   const noexcept;
    std::filesystem::perms std_perms() const noexcept;
    bool has(AttributeFlag) const noexcept;     // was this field actually sent?
};

/// Partial attributes for setstat: only engaged fields are transmitted.
struct SSHPP_API AttributeUpdate {
    std::optional<std::uint64_t> size;
    std::optional<std::uint32_t> permissions;
    std::optional<std::pair<std::uint32_t, std::uint32_t>> uid_gid;
    std::optional<std::chrono::system_clock::time_point> atime, mtime;
};

} // namespace sshpp::sftp
```

`has()` matters: SFTP servers may omit fields, and a `permissions == 0` that means "not sent"
must be distinguishable from `0000`.

## 6.2 `sftp::Sftp` — the session

```cpp
namespace sshpp::sftp {

enum class OpenMode : int {          // maps to O_* flags
    read       = 1 << 0,
    write      = 1 << 1,
    read_write = read | write,
    create     = 1 << 2,
    truncate   = 1 << 3,
    append     = 1 << 4,
    exclusive  = 1 << 5,             // O_EXCL, use with create
};
SSHPP_API OpenMode operator|(OpenMode, OpenMode) noexcept;

struct Limits {                       // sftp_limits, libssh >= 0.10.5
    std::uint64_t max_packet_length;
    std::uint64_t max_read_length;
    std::uint64_t max_write_length;
    std::uint64_t max_open_handles;   // 0 = unlimited/unknown
};

class SSHPP_API Sftp {
public:
    Sftp() = default;
    explicit Sftp(Session&);                 // sftp_new, no I/O yet
    /// Run SFTP over an already-opened channel (e.g. a custom subsystem name).
    static Result<Sftp> over_channel(Channel);
    ~Sftp();                                 // sftp_free
    Sftp(Sftp&&) noexcept; Sftp& operator=(Sftp&&) noexcept;

    Result<void> try_init();                 // sftp_init: protocol handshake
    explicit operator bool() const noexcept;
    native_sftp native_handle() const noexcept;
    Session session() const;

    int  protocol_version() const noexcept;              // sftp_server_version
    bool supports_extension(std::string_view name,
                            std::string_view version = {}) const;  // sftp_extension_supported
    std::vector<std::pair<std::string, std::string>> extensions() const;
    Result<Limits> try_limits() const;

    // ---- files -----------------------------------------------------------
    Result<File> try_open(const RemotePath&, OpenMode,
                          std::filesystem::perms create_perms = perms::owner_read_write);

    // ---- metadata ---------------------------------------------------------
    Result<Attributes> try_stat (const RemotePath&) const;
    Result<Attributes> try_lstat(const RemotePath&) const;
    Result<bool>       try_exists(const RemotePath&) const;   // stat, mapping no_such_file->false
    Result<void>       try_setstat(const RemotePath&, const AttributeUpdate&);
    Result<void>       try_chmod (const RemotePath&, std::filesystem::perms);
    Result<void>       try_chown (const RemotePath&, std::uint32_t uid, std::uint32_t gid);
    Result<void>       try_utimes(const RemotePath&,
                                  std::chrono::system_clock::time_point atime,
                                  std::chrono::system_clock::time_point mtime);

    // ---- namespace ----------------------------------------------------------
    Result<void>       try_mkdir(const RemotePath&,
                                 std::filesystem::perms = perms::owner_all);
    Result<void>       try_mkdir_p(const RemotePath&, std::filesystem::perms = perms::owner_all);
    Result<void>       try_rmdir(const RemotePath&);
    Result<void>       try_remove(const RemotePath&);            // sftp_unlink
    Result<void>       try_rename(const RemotePath& from, const RemotePath& to);
    Result<void>       try_symlink(const RemotePath& target, const RemotePath& link);
    Result<RemotePath> try_readlink(const RemotePath&) const;
    Result<RemotePath> try_canonicalize(const RemotePath&) const;
    Result<RemotePath> try_home() const;                          // canonicalize(".")

    // ---- directories ----------------------------------------------------------
    Result<Directory>  try_open_directory(const RemotePath&) const;
    Result<std::vector<Attributes>> try_list(const RemotePath&) const;

    // ---- filesystem ------------------------------------------------------------
    Result<Statvfs>    try_statvfs(const RemotePath&) const;

    // ---- errors -----------------------------------------------------------------
    sftp_errc last_status() const noexcept;      // sftp_get_error
};

} // namespace sshpp::sftp
```

`Session::try_open_sftp()` is the ergonomic entry point: it constructs `Sftp` and calls
`try_init()` in one step, returning `Result<Sftp>`.

## 6.3 `sftp::File`

```cpp
namespace sshpp::sftp {

class SSHPP_API File {
public:
    File() = default;
    ~File();                                     // sftp_close
    File(File&&) noexcept; File& operator=(File&&) noexcept;

    explicit operator bool() const noexcept;
    native_sftp_file native_handle() const noexcept;
    const RemotePath& path() const noexcept;     // for diagnostics

    Result<std::size_t> try_read (MutableByteView);   // 0 == EOF
    Result<void>        try_read_exact(MutableByteView);
    Result<std::size_t> try_write(ByteView);
    Result<void>        try_write_all(ByteView);

    Result<std::uint64_t> try_tell() const;           // sftp_tell64
    Result<void>          try_seek(std::uint64_t);    // sftp_seek64
    Result<void>          try_rewind();
    Result<Attributes>    try_stat() const;           // sftp_fstat
    Result<Statvfs>       try_statvfs() const;
    Result<void>          try_sync();                 // fsync@openssh.com extension
    Result<void>          try_truncate(std::uint64_t);
    Result<void>          try_close();                // explicit; idempotent

    Result<void> try_set_blocking(bool);              // sftp_file_set_(non)blocking

    // ---- pipelined I/O (libssh >= 0.11 sftp_aio_*) -----------------------------
    // Falls back to a synchronous loop when SSHPP_HAS_SFTP_AIO is 0.
    class ReadAhead;                                  // see below
    class WriteBehind;
};

} // namespace sshpp::sftp
```

### Throughput: why `ReadAhead`/`WriteBehind` exist

A naive `sftp_read` loop does one round-trip per 32 KiB chunk; on a 100 ms RTT link that caps
throughput at ~320 KiB/s regardless of bandwidth. Real speed requires keeping N requests in
flight. libssh ≥ 0.11 exposes `sftp_aio_begin_read` / `sftp_aio_wait_read` for exactly this.

```cpp
class SSHPP_API File::ReadAhead {
public:
    ReadAhead(File&, std::size_t chunk = 0, std::size_t depth = 0);  // 0 = derive from Limits
    /// Returns the next contiguous chunk in file order; empty span == EOF.
    Result<ByteView> try_next();
};

class SSHPP_API File::WriteBehind {
public:
    WriteBehind(File&, std::size_t chunk = 0, std::size_t depth = 0);
    Result<void> try_write(ByteView);
    Result<void> try_flush();     // also called by the destructor (errors -> handler)
};
```

Defaults are derived from `Sftp::try_limits()`: `chunk = min(max_read_length, 256 KiB)`,
`depth = 16`. On pre-0.11 libssh the same classes compile but degrade to a synchronous loop,
so user code is source-portable.

## 6.4 `sftp::Directory` and iteration

```cpp
namespace sshpp::sftp {

class SSHPP_API Directory {
public:
    ~Directory();                                   // sftp_closedir
    Directory(Directory&&) noexcept;

    /// nullopt when exhausted. Errors are reported through last_error().
    std::optional<Attributes> next();
    bool eof() const noexcept;                      // sftp_dir_eof
    const ErrorInfo& last_error() const noexcept;
    const RemotePath& path() const noexcept;
};

/// InputIterator over a Directory. Skips "." and ".." by default.
class SSHPP_API DirectoryIterator {
public:
    using value_type = Attributes;
    using iterator_category = std::input_iterator_tag;

    DirectoryIterator() = default;                  // end
    explicit DirectoryIterator(Directory&, bool skip_dot_entries = true);

    const Attributes& operator*() const;
    DirectoryIterator& operator++();                // throws SftpError on read failure
    bool operator==(const DirectoryIterator&) const noexcept;
};

/// Range adapter: `for (const auto& e : sftp::entries(sftp, "/var/log"))`
SSHPP_API DirectoryRange entries(Sftp&, const RemotePath&);

/// Recursive walk with symlink-loop protection and a depth limit.
struct RecursiveOptions {
    bool follow_symlinks = false;
    std::size_t max_depth = 64;
    std::function<bool(const RemotePath&, const Attributes&)> filter;   // false = prune
};
SSHPP_API RecursiveDirectoryRange recursive_entries(Sftp&, const RemotePath&,
                                                    RecursiveOptions = {});

} // namespace sshpp::sftp
```

Iterators throw on error (they have no other channel); `Directory::next()` is the non-throwing
form. `recursive_entries` defends against symlink loops by tracking visited
`(uid-independent) canonical paths` and enforcing `max_depth`, since a hostile server can
otherwise make a walk run forever (OWASP A04 — insecure design / resource exhaustion).

## 6.5 `<sshpp/sftp/algorithms.hpp>` — Layer-4 transfers

```cpp
namespace sshpp::sftp {

struct Progress {
    std::uint64_t bytes_done = 0;
    std::optional<std::uint64_t> bytes_total;
    const RemotePath* current = nullptr;
};
/// Return false to abort the transfer (yields errc::cancelled).
using ProgressCallback = std::function<bool(const Progress&)>;

enum class Overwrite { fail, replace, skip_if_same_size_and_mtime };

struct TransferOptions {
    Overwrite         overwrite = Overwrite::fail;
    bool              preserve_times = true;
    bool              preserve_permissions = true;
    bool              resume = false;                    // append from existing size
    bool              atomic = true;                     // upload to .part, then rename
    std::size_t       chunk_size = 0;                    // 0 = auto from Limits
    ProgressCallback  progress;
};

Result<std::uint64_t> try_download(Sftp&, const RemotePath& remote,
                                   const std::filesystem::path& local,
                                   TransferOptions = {});
Result<std::uint64_t> try_upload  (Sftp&, const std::filesystem::path& local,
                                   const RemotePath& remote, TransferOptions = {});
Result<std::uint64_t> try_download_to(Sftp&, const RemotePath&, std::ostream&,
                                      TransferOptions = {});
Result<std::uint64_t> try_upload_from(Sftp&, std::istream&, const RemotePath&,
                                      TransferOptions = {});
Result<std::string>   try_read_file(Sftp&, const RemotePath&, std::size_t limit = 16u << 20);
Result<void>          try_write_file(Sftp&, const RemotePath&, ByteView,
                                     std::filesystem::perms = perms::owner_read_write);

struct TreeStats { std::uint64_t files = 0, directories = 0, bytes = 0, skipped = 0; };
Result<TreeStats> try_download_tree(Sftp&, const RemotePath&, const std::filesystem::path&,
                                    TransferOptions = {}, RecursiveOptions = {});
Result<TreeStats> try_upload_tree  (Sftp&, const std::filesystem::path&, const RemotePath&,
                                    TransferOptions = {});

} // namespace sshpp::sftp
```

Security requirements baked into `try_download_tree`:

* Every remote entry name is validated to contain no `/`, no `..`, and no NUL before being
  joined to the local destination; the resulting path is checked to still be under the
  destination root after `weakly_canonical`. This blocks the "malicious server writes to
  `../../etc/cron.d/x`" path-traversal attack (OWASP A01).
* Symlinks are not followed by default and are recreated as symlinks only if
  `follow_symlinks == false && allow_symlink_creation == true` (default `false`, i.e. skipped
  with a `skipped` count).
* `atomic` uploads use `<name>.<pid>.part` + `sftp_rename`, so a crashed transfer never leaves a
  truncated file at the final path.

## 6.6 `sftp::Statvfs`

```cpp
struct SSHPP_API Statvfs {
    std::uint64_t block_size, fragment_size, blocks, blocks_free, blocks_available;
    std::uint64_t files, files_free, files_available;
    std::uint64_t fsid, flags, name_max;
    bool read_only() const noexcept;      // SSH_FXE_STATVFS_ST_RDONLY
    bool no_suid()   const noexcept;
    std::uint64_t bytes_free() const noexcept;
};
```

## 6.7 SCP

SCP is legacy and, in OpenSSH ≥ 9, `scp(1)` uses SFTP by default. We still wrap it because
embedded/BSD servers may only offer SCP.

```cpp
namespace sshpp::scp {

enum class Mode { read, write, read_recursive, write_recursive };

enum class RequestType { new_file, new_directory, end_directory, eof, warning };

struct Request {
    RequestType   type;
    std::string   name;             // file or directory name (basename)
    std::uint64_t size = 0;
    std::filesystem::perms permissions{};
    std::string   warning;          // for RequestType::warning
};

class SSHPP_API Reader {
public:
    Reader() = default;
    Reader(Session&, const RemotePath&, bool recursive);
    ~Reader();                                       // ssh_scp_close + free
    Reader(Reader&&) noexcept;

    Result<void> try_init();

    /// nullopt when the transfer is complete (SSH_SCP_REQUEST_EOF).
    Result<std::optional<Request>> try_next();
    Result<void> try_accept();                       // ssh_scp_accept_request
    Result<void> try_deny(std::string_view reason);
    Result<std::size_t> try_read(MutableByteView);
    Result<std::uint64_t> try_read_to(std::ostream&, ProgressCallback = {});
};

class SSHPP_API Writer {
public:
    Writer(Session&, const RemotePath& destination_dir, bool recursive);
    ~Writer();
    Result<void> try_init();

    Result<void> try_push_file(std::string_view name, std::uint64_t size,
                               std::filesystem::perms = perms::owner_read_write);
    Result<void> try_push_directory(std::string_view name,
                                    std::filesystem::perms = perms::owner_all);
    Result<void> try_leave_directory();
    Result<void> try_write(ByteView);
    Result<std::uint64_t> try_write_from(std::istream&, std::uint64_t size,
                                         ProgressCallback = {});
};

// Layer-4 one-liners with the same path-traversal hardening as the SFTP tree helpers.
Result<std::uint64_t> try_download(Session&, const RemotePath&, const std::filesystem::path&,
                                   ProgressCallback = {});
Result<std::uint64_t> try_upload  (Session&, const std::filesystem::path&, const RemotePath&,
                                   ProgressCallback = {});

} // namespace sshpp::scp
```

`ssh_scp_push_file64` and `ssh_scp_request_get_size64` are always used (never the 32-bit
variants). The recursive reader enforces the same name validation as §6.5 — SCP's classic
CVE-2019-6111 is precisely a server sending unexpected filenames, and the wrapper must not
reproduce it.

The header carries a prominent note recommending SFTP over SCP, and `scp::` symbols are marked
`[[deprecated]]` only if the user defines `SSHPP_SCP_DEPRECATION_WARNINGS`.

## 6.8 Examples

```cpp
auto sftp = session.try_open_sftp().value();

// Directory listing
for (const auto& e : sshpp::sftp::entries(sftp, "/var/log")) {
    if (e.is_regular())
        std::printf("%10llu %s\n", (unsigned long long)e.size, e.name.c_str());
}

// Resumable, progress-reporting download
sshpp::sftp::TransferOptions to;
to.resume = true;
to.overwrite = sshpp::sftp::Overwrite::replace;
to.progress = [](const auto& p) {
    if (p.bytes_total) std::printf("\r%3llu%%", 100ull * p.bytes_done / *p.bytes_total);
    return true;
};
sshpp::sftp::try_download(sftp, "/srv/image.iso", "image.iso", to).value();

// Atomic small write
sshpp::sftp::try_write_file(sftp, "/etc/app/config.json", config_bytes).value();
```
