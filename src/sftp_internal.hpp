// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Internal helper shared by sftp.cpp, file.cpp and directory.cpp. Not installed.
#pragma once

#include <sshpp/sftp/attributes.hpp>

#include <libssh/sftp.h>

namespace sshpp::sftp::internal {

Attributes attributes_from_native(sftp_attributes raw);

} // namespace sshpp::sftp::internal
