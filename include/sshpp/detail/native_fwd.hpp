// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Opaque forward declarations of libssh's C handle types. Public sshpp headers
// only ever see these typedefs, never <libssh/libssh.h> itself (see docs/design/02 §2.4).
#pragma once

// These must be forward-declared at global scope (not inside namespace sshpp) so that
// they refer to the *same* types libssh.h itself forward-declares/defines, rather than
// creating unrelated sshpp::ssh_session_struct etc. that silently fail to convert.
struct ssh_session_struct;
struct ssh_channel_struct;
struct ssh_key_struct;
struct ssh_bind_struct;
struct ssh_message_struct;
struct ssh_event_struct;
struct sftp_session_struct;
struct sftp_file_struct;
struct sftp_dir_struct;
struct ssh_scp_struct;
struct ssh_connector_struct;

namespace sshpp {

using native_session   = ::ssh_session_struct*;
using native_channel   = ::ssh_channel_struct*;
using native_key       = ::ssh_key_struct*;
using native_bind      = ::ssh_bind_struct*;
using native_message   = ::ssh_message_struct*;
using native_event     = ::ssh_event_struct*;
using native_sftp      = ::sftp_session_struct*;
using native_sftp_file = ::sftp_file_struct*;
using native_sftp_dir  = ::sftp_dir_struct*;
using native_scp       = ::ssh_scp_struct*;
using native_connector = ::ssh_connector_struct*;

} // namespace sshpp
