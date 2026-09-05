#include <catch2/catch_test_macros.hpp>
#include <sshpp/sftp/attributes.hpp>

using namespace sshpp::sftp;

TEST_CASE("Attributes::std_perms masks to POSIX permission bits", "[sftp][attributes]") {
    Attributes a;
    a.permissions = 0100644; // regular file, rw-r--r--
    auto perms = a.std_perms();
    CHECK(perms == (std::filesystem::perms::owner_read | std::filesystem::perms::owner_write |
                    std::filesystem::perms::group_read | std::filesystem::perms::others_read));
}

TEST_CASE("Attributes type predicates", "[sftp][attributes]") {
    Attributes a;
    a.type = FileType::directory;
    CHECK(a.is_directory());
    CHECK_FALSE(a.is_regular());
    CHECK_FALSE(a.is_symlink());
}
