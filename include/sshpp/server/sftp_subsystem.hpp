// SPDX-License-Identifier: LGPL-2.1-or-later
//
// A chroot-style SFTP server subsystem. See docs/design/08 §8.7.
//
// Deliberately NOT a ChannelHandler in the on_data() sense: libssh's SFTP
// server helpers (sftp_server_new/sftp_get_client_message) do their own
// blocking ssh_channel_read() internally, which cannot be driven from the
// event-loop's async channel_data callback. try_serve() instead owns the
// channel synchronously (typically from a dedicated thread, one per SFTP
// subsystem request) -- see the "Concurrency" note below. This still
// implements the ChannelHandler interface for convenience: on_subsystem_request
// spawns that thread.
//
// This is the single most security-sensitive component in the library: every
// client-supplied path is resolved with resolve() (join -> weakly_canonical ->
// verify it stays under the canonicalized root) before touching the
// filesystem; any failure is reported as SSH_FX_PERMISSION_DENIED /
// SSH_FX_NO_SUCH_FILE rather than ever passing an unchecked path to a POSIX
// call. There is no support for arbitrary absolute paths breaking out of root.
#pragma once

#include <sshpp/config.hpp>

#include <sshpp/error.hpp>
#include <sshpp/export.hpp>
#include <sshpp/result.hpp>
#include <sshpp/server/handlers.hpp>

#include <cstdint>
#include <filesystem>
#include <thread>
#include <vector>

namespace sshpp::server {

/// Serves SFTP (protocol version 3) over an already-open channel, confined to
/// `root`. See docs/design/08 §8.7.
///
/// Concurrency: try_serve() performs raw, blocking reads/writes on the given
/// channel from the calling thread. If that thread is different from the one
/// driving the session's Event/message loop, the underlying Session must not
/// be used concurrently from both without external synchronization (same
/// caveat as LocalForward/RemoteForward's pump threads).
class SSHPP_API SftpSubsystemHandler : public ChannelHandler {
public:
    struct Options {
        std::filesystem::path root;
        bool          read_only = false;
        bool          follow_symlinks_out_of_root = false;
        std::uint64_t max_file_size = 0; // 0 = unlimited
    };

    explicit SftpSubsystemHandler(Options options) : options_(std::move(options)) {}
    ~SftpSubsystemHandler() override;

    /// Runs the SFTP server loop until the client closes the subsystem
    /// channel or an unrecoverable protocol error occurs. Blocks.
    Result<void> try_serve(Channel& channel) const;

    // ---- ChannelHandler: spawns a dedicated thread running try_serve() ---------
    bool on_subsystem_request(Channel&, std::string_view name) override;
    void on_close(Channel&) override;

private:
    Options            options_;
    mutable std::vector<std::thread> worker_threads_;
};

} // namespace sshpp::server

#if SSHPP_HEADER_ONLY
#include <sshpp/detail/server_sftp_subsystem.ipp>
#endif
