// SPDX-License-Identifier: LGPL-2.1-or-later
#include <sshpp/session_options.hpp>

#include <sshpp/error.hpp>

namespace sshpp {

Result<void> SessionOptions::validate() const {
    if (host.empty()) {
        ErrorInfo info;
        info.operation = "SessionOptions::validate";
        info.code = make_error_code(errc::invalid_argument);
        info.message = "host must not be empty";
        return info;
    }
    return {};
}

Result<SessionOptions> SessionOptions::parse_target(std::string_view target) {
    SessionOptions opts;
    std::string_view rest = target;

    auto at_pos = rest.find('@');
    if (at_pos != std::string_view::npos) {
        opts.user = std::string(rest.substr(0, at_pos));
        rest = rest.substr(at_pos + 1);
    }

    if (!rest.empty() && rest.front() == '[') {
        auto close = rest.find(']');
        if (close == std::string_view::npos) {
            ErrorInfo info;
            info.operation = "SessionOptions::parse_target";
            info.code = make_error_code(errc::invalid_argument);
            info.message = "unterminated '[' in target";
            return info;
        }
        opts.host = std::string(rest.substr(1, close - 1));
        rest = rest.substr(close + 1);
        if (!rest.empty() && rest.front() == ':') {
            rest.remove_prefix(1);
            opts.port = static_cast<std::uint16_t>(std::stoi(std::string(rest)));
        }
    } else {
        auto colon = rest.rfind(':');
        if (colon != std::string_view::npos) {
            opts.host = std::string(rest.substr(0, colon));
            opts.port = static_cast<std::uint16_t>(std::stoi(std::string(rest.substr(colon + 1))));
        } else {
            opts.host = std::string(rest);
        }
    }

    auto validated = opts.validate();
    if (!validated) return validated.error();
    return opts;
}

} // namespace sshpp
