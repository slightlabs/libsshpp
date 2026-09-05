// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Connects, verifies the host key TOFU-style, authenticates and runs a command.
// Usage: 01_exec <user@host[:port]> <command...>
#include <sshpp/sshpp.hpp>

#include <cstdlib>
#include <iostream>

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "usage: " << argv[0] << " <user@host[:port]> <command...>\n";
        return 2;
    }

    try {
        sshpp::Library lib{{.log_level = sshpp::LogLevel::warning}};

        auto opts = sshpp::SessionOptions::parse_target(argv[1]).value();
        opts.timeout = std::chrono::seconds{10};

        sshpp::Session session{opts};
        session.connect();
        session.verify_host_key(sshpp::TofuHostKeyPolicy{});

        sshpp::auth::Chain chain;
        chain.emplace<sshpp::auth::Agent>();
        chain.emplace<sshpp::auth::PublicKeyAuto>();
        session.authenticate(chain);

        std::vector<std::string> cmd(argv + 2, argv + argc);
        auto result = sshpp::Exec{session}.try_run(cmd);
        if (!result) {
            std::cerr << result.error().to_string() << '\n';
            return 1;
        }
        std::cout << result->stdout_text;
        std::cerr << result->stderr_text;
        return result->exit_code;
    } catch (const sshpp::HostKeyError& e) {
        std::cerr << "host key rejected: " << e.what() << '\n';
        return 2;
    } catch (const sshpp::Error& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
