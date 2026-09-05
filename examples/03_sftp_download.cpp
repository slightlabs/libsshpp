// SPDX-License-Identifier: LGPL-2.1-or-later
//
// Downloads a remote file over SFTP.
// Usage: 03_sftp_download <user@host[:port]> <remote-path> <local-path>
#include <sshpp/sftp/algorithms.hpp>
#include <sshpp/sshpp.hpp>

#include <iostream>

int main(int argc, char** argv) {
    if (argc != 4) {
        std::cerr << "usage: " << argv[0] << " <user@host[:port]> <remote-path> <local-path>\n";
        return 2;
    }

    try {
        sshpp::Library lib;

        auto opts = sshpp::SessionOptions::parse_target(argv[1]).value();
        opts.timeout = std::chrono::seconds{10};

        sshpp::Session session{opts};
        session.connect();
        session.verify_host_key(sshpp::TofuHostKeyPolicy{});

        sshpp::auth::Chain chain;
        chain.emplace<sshpp::auth::Agent>();
        chain.emplace<sshpp::auth::PublicKeyAuto>();
        session.authenticate(chain);

        auto sftp = session.try_open_sftp().value();
        auto bytes = sshpp::sftp::try_download(sftp, argv[2], argv[3]);
        if (!bytes) {
            std::cerr << bytes.error().to_string() << '\n';
            return 1;
        }
        std::cout << "downloaded " << *bytes << " bytes\n";
        return 0;
    } catch (const sshpp::Error& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
