// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Umbrella header for the parts of libsshpp implemented so far (M0 + M1: core client).
// SFTP, SCP, forwarding and the server module are not yet implemented; see
// docs/design/11-versioning-and-roadmap.md for the milestone plan.
#pragma once

#include <sshpp/config.hpp>

#include <sshpp/auth.hpp>
#include <sshpp/channel.hpp>
#include <sshpp/error.hpp>
#include <sshpp/event.hpp>
#include <sshpp/exec.hpp>
#include <sshpp/host_key_verifier.hpp>
#include <sshpp/key.hpp>
#include <sshpp/known_hosts.hpp>
#include <sshpp/library.hpp>
#include <sshpp/result.hpp>
#include <sshpp/session.hpp>
#include <sshpp/session_options.hpp>
#include <sshpp/types.hpp>

#if SSHPP_WITH_SFTP
#include <sshpp/sftp/algorithms.hpp>
#include <sshpp/sftp/sftp.hpp>
#endif

#if SSHPP_WITH_SCP
#include <sshpp/scp/scp.hpp>
#endif
