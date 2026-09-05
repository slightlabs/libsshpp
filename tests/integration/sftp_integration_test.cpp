#include <catch2/catch_test_macros.hpp>
#include <sshpp/sftp/algorithms.hpp>
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

TEST_CASE("SFTP file round trip against a real sshd", "[integration][sftp]") {
    Session session = make_connected_session();

    auto sftp_result = session.try_open_sftp();
    REQUIRE(sftp_result.has_value());
    sftp::Sftp sftp_session = std::move(*sftp_result);

    auto tmp_dir = std::filesystem::temp_directory_path() / "sshpp_sftp_test";
    std::filesystem::create_directories(tmp_dir);
    RemotePath remote_dir = tmp_dir.string() + "/remote_root";

    auto mkdir_result = sftp_session.try_mkdir_p(remote_dir);
    REQUIRE(mkdir_result.has_value());

    RemotePath remote_file = remote_dir / "hello.txt";
    const std::string content = "hello from sshpp sftp\n";
    auto write_result = sftp::try_write_file(sftp_session, remote_file, ByteView(content));
    REQUIRE(write_result.has_value());

    auto stat_result = sftp_session.try_stat(remote_file);
    REQUIRE(stat_result.has_value());
    CHECK(stat_result->size == content.size());
    CHECK(stat_result->is_regular());

    auto read_result = sftp::try_read_file(sftp_session, remote_file);
    REQUIRE(read_result.has_value());
    CHECK(*read_result == content);

    auto list_result = sftp_session.try_list(remote_dir);
    REQUIRE(list_result.has_value());
    CHECK(list_result->size() == 1);
    CHECK(list_result->front().name == "hello.txt");

    auto local_download = tmp_dir / "downloaded.txt";
    auto download_result = sftp::try_download(sftp_session, remote_file, local_download);
    REQUIRE(download_result.has_value());
    CHECK(*download_result == content.size());
    {
        std::ifstream in(local_download, std::ios::binary);
        std::string downloaded((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        CHECK(downloaded == content);
    }

    auto remove_result = sftp_session.try_remove(remote_file);
    CHECK(remove_result.has_value());

    std::filesystem::remove_all(tmp_dir);
}
