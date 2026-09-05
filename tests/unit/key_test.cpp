#include <catch2/catch_test_macros.hpp>
#include <sshpp/key.hpp>
#include <sshpp/library.hpp>

using namespace sshpp;

TEST_CASE("Key::generate produces a usable ed25519 key", "[key]") {
    Library lib;
    auto key = Key::generate(KeyType::ed25519);
    REQUIRE(key.has_value());
    CHECK(key->is_private());
    CHECK(key->type() == KeyType::ed25519);
    CHECK(key->type_name() == "ssh-ed25519");
}

TEST_CASE("Key public/private round trip via authorized_keys line", "[key]") {
    Library lib;
    auto key = Key::generate(KeyType::ed25519).value();
    auto pub = key.public_part();
    REQUIRE(pub.has_value());
    CHECK(pub->is_public());

    auto line = pub->to_authorized_keys_line("test-comment");
    REQUIRE(line.has_value());
    CHECK(line->find("ssh-ed25519") == 0);
    CHECK(line->find("test-comment") != std::string::npos);

    auto parsed = Key::from_authorized_keys_line(*line);
    REQUIRE(parsed.has_value());
    CHECK(parsed->equals(*pub, /*compare_private=*/false));
}

TEST_CASE("Fingerprint equality is reflexive", "[key]") {
    Library lib;
    auto key = Key::generate(KeyType::ed25519).value();
    auto fp1 = key.fingerprint(HashType::sha256).value();
    auto fp2 = key.fingerprint(HashType::sha256).value();
    CHECK(fp1 == fp2);
    CHECK_FALSE(fp1.to_string().empty());
}
