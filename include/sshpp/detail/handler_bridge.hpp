// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Forward declaration only; see detail/handler_bridge.ipp for the definition.
// Kept out of the public server headers so they don't have to include
// <libssh/callbacks.h>. Not part of the public API.
#pragma once

#include <sshpp/config.hpp>

namespace sshpp::detail {
class HandlerBridge;
} // namespace sshpp::detail
