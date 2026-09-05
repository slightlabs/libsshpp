// SPDX-License-Identifier: LGPL-2.1-or-later
#include <sshpp/host_key_verifier.hpp>

#include <algorithm>

namespace sshpp {

HostKeyVerifier::Decision StrictHostKeyPolicy::verify(const Context& ctx) const {
    return ctx.status == KnownHostsStatus::ok ? Decision::accept : Decision::reject;
}

HostKeyVerifier::Decision TofuHostKeyPolicy::verify(const Context& ctx) const {
    switch (ctx.status) {
        case KnownHostsStatus::ok: return Decision::accept;
        // not_found: known_hosts file itself doesn't exist yet.
        // unknown: the file exists but has no entry for this host.
        // Both are legitimate "first use" cases for TOFU.
        case KnownHostsStatus::not_found:
        case KnownHostsStatus::unknown: return Decision::accept_and_remember;
        default: return Decision::reject;
    }
}

HostKeyVerifier::Decision AcceptAnyHostKeyPolicy::verify(const Context&) const {
    return Decision::accept;
}

HostKeyVerifier::Decision PinnedHostKeyPolicy::verify(const Context& ctx) const {
    bool match = std::any_of(pins_.begin(), pins_.end(),
                             [&](const Fingerprint& f) { return f == ctx.sha256; });
    return match ? Decision::accept : Decision::reject;
}

} // namespace sshpp
