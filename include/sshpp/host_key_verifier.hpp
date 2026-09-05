// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include <sshpp/export.hpp>
#include <sshpp/fwd.hpp>
#include <sshpp/key.hpp>
#include <sshpp/known_hosts.hpp>

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace sshpp {

/// Tag type that can only be constructed via i_understand_this_is_insecure(),
/// so AcceptAnyHostKeyPolicy cannot be reached by accident.
struct InsecureOptIn { explicit InsecureOptIn() = default; };
inline InsecureOptIn i_understand_this_is_insecure() { return InsecureOptIn{}; }

/// Policy object consulted by Session::verify_host_key(). See docs/design/04 §4.6.
class SSHPP_API HostKeyVerifier {
public:
    struct Context {
        std::string_view host;
        std::uint16_t    port;
        KnownHostsStatus status;
        const Key&       presented_key;
        Fingerprint      sha256;
        Session&         session;
    };
    enum class Decision { accept, accept_and_remember, reject };

    virtual ~HostKeyVerifier() = default;
    virtual Decision verify(const Context&) const = 0;
};

/// Reject anything not already in known_hosts. The only safe default.
class SSHPP_API StrictHostKeyPolicy final : public HostKeyVerifier {
public:
    Decision verify(const Context&) const override;
};

/// Accept-and-remember on first use; reject on change (OpenSSH accept-new).
class SSHPP_API TofuHostKeyPolicy final : public HostKeyVerifier {
public:
    Decision verify(const Context&) const override;
};

/// Accept everything. Requires the i_understand_this_is_insecure() tag.
class SSHPP_API AcceptAnyHostKeyPolicy final : public HostKeyVerifier {
public:
    explicit AcceptAnyHostKeyPolicy(InsecureOptIn) {}
    Decision verify(const Context&) const override;
};

/// Pin one or more fingerprints; ignores known_hosts entirely.
class SSHPP_API PinnedHostKeyPolicy final : public HostKeyVerifier {
public:
    explicit PinnedHostKeyPolicy(std::vector<Fingerprint> fps) : pins_(std::move(fps)) {}
    Decision verify(const Context&) const override;

private:
    std::vector<Fingerprint> pins_;
};

/// Delegates to a user callback (e.g. a GUI prompt).
class SSHPP_API CallbackHostKeyPolicy final : public HostKeyVerifier {
public:
    explicit CallbackHostKeyPolicy(std::function<Decision(const Context&)> cb) : cb_(std::move(cb)) {}
    Decision verify(const Context& ctx) const override { return cb_(ctx); }

private:
    std::function<Decision(const Context&)> cb_;
};

} // namespace sshpp
