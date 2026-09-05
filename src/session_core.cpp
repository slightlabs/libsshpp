// SPDX-License-Identifier: LGPL-2.1-or-later
#include <sshpp/detail/session_core.hpp>

#include <libssh/libssh.h>

namespace sshpp::detail {

SessionCore::~SessionCore() {
    if (raw_ != nullptr) {
        ssh_disconnect(raw_);
        ssh_free(raw_);
        raw_ = nullptr;
    }
}

void SessionCore::replace(native_session raw) noexcept {
    if (raw_ != nullptr) {
        ssh_disconnect(raw_);
        ssh_free(raw_);
    }
    raw_ = raw;
}

} // namespace sshpp::detail
