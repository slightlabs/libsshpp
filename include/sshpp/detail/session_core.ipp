// SPDX-License-Identifier: LGPL-2.1-or-later
// Generated from src/session_core.cpp; see docs/design/09 §9.3.
#include <sshpp/config.hpp>
// SPDX-License-Identifier: LGPL-2.1-or-later
#include <sshpp/detail/session_core.hpp>

#include <libssh/libssh.h>

namespace sshpp::detail {

SSHPP_INLINE SessionCore::~SessionCore() {
    if (raw_ != nullptr) {
        ssh_disconnect(raw_);
        ssh_free(raw_);
        raw_ = nullptr;
    }
}

SSHPP_INLINE void SessionCore::replace(native_session raw) noexcept {
    if (raw_ != nullptr) {
        ssh_disconnect(raw_);
        ssh_free(raw_);
    }
    raw_ = raw;
}

} // namespace sshpp::detail
