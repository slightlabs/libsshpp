// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

namespace sshpp {

enum class AuthStatus { success, denied, partial, info_required, again, error };

struct AuthMethods {
    bool none = false, password = false, public_key = false,
         host_based = false, interactive = false, gssapi_mic = false;

    static AuthMethods from_bits(int bits) noexcept;
    int  to_bits() const noexcept;
    bool any() const noexcept { return password || public_key || host_based || interactive || gssapi_mic; }
};

} // namespace sshpp
