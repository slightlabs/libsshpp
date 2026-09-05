#include <catch2/catch_test_macros.hpp>
#include <sshpp/scp/scp.hpp>
#include <sshpp/sshpp.hpp>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

using namespace sshpp;

namespace {

std::string env(const char* name) {
    const char* v = std::getenv(name);
    if (v == nullptr) {
        FAIL("missing required environment variable " << name);
    }
    return v;
}

Session make_connected_session() {
    SessionOptions opts;
    opts.host = env("SSHPP_TEST_HOST");
    opts.port = static_cast<std::uint16_t>(std::stoi(env("SSHPP_TEST_PORT")));
    opts.user = env("SSHPP_TEST_USER");
    opts.identities.push_back(env("SSHPP_TEST_KEY"));
    opts.known_hosts = env("SSHPP_TEST_KNOWN_HOSTS");
    opts.timeout = std::chrono::seconds{5};

    Session session{opts};
    session.connect();
    session.verify_host_key(TofuHostKeyPolicy{});
    auth::PublicKeyAuto authenticator;
    session.authenticate(authenticator);
    return session;
}

} // namespace

TEST_CASE("SCP upload/download round trip against a real sshd", "[integration][scp]") {
    Session session = make_connected_session();

    auto tmp_dir = std::filesystem::temp_directory_path() / "sshpp_scp_test";
    std::filesystem::create_directories(tmp_dir);

    auto local_src = tmp_dir / "upload.txt";
    const std::string content = "hello from sshpp scp\n";
    {
        std::ofstream out(local_src, std::ios::binary);
        out << content;
    }

    RemotePath remote_file = RemotePath(tmp_dir.string()) / "upload.txt";
    auto upload_result = scp::try_upload(session, local_src, RemotePath(tmp_dir.string()));
    REQUIRE(upload_result.has_value());
    CHECK(*upload_result == content.size());

    auto local_dst = tmp_dir / "downloaded.txt";
    auto download_result = scp::try_download(session, remote_file, local_dst);
    REQUIRE(download_result.has_value());
    CHECK(*download_result == content.size());

    {
        std::ifstream in(local_dst, std::ios::binary);
        std::string downloaded((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        CHECK(downloaded == content);
    }

    std::filesystem::remove_all(tmp_dir);
}
