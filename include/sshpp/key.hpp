// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include <sshpp/detail/native_fwd.hpp>
#include <sshpp/export.hpp>
#include <sshpp/result.hpp>
#include <sshpp/types.hpp>

#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace sshpp {

enum class KeyType {
    unknown, dss, rsa, rsa1, ecdsa_p256, ecdsa_p384, ecdsa_p521,
    ed25519, dss_cert01, rsa_cert01, ecdsa_p256_cert01, ecdsa_p384_cert01,
    ecdsa_p521_cert01, ed25519_cert01, sk_ecdsa, sk_ed25519,
    sk_ecdsa_cert01, sk_ed25519_cert01,
};

enum class HashType { md5, sha1, sha256 };

/// Request passed to a passphrase/password prompt callback.
struct PassphraseRequest {
    std::string key_path;
    std::string comment;
    int         attempt = 0;
};
using PassphraseCallback = std::function<Result<SecureString>(const PassphraseRequest&)>;
using PasswordCallback   = std::function<Result<SecureString>()>;

class SSHPP_API Fingerprint {
public:
    Fingerprint() = default;
    Fingerprint(HashType type, std::vector<std::byte> bytes) : type_(type), bytes_(std::move(bytes)) {}

    HashType type() const noexcept { return type_; }
    ByteView bytes() const noexcept { return bytes_; }

    std::string to_string() const;
    std::string to_hex() const;

    bool operator==(const Fingerprint& other) const noexcept;
    bool operator!=(const Fingerprint& other) const noexcept { return !(*this == other); }

private:
    HashType type_ = HashType::sha256;
    std::vector<std::byte> bytes_;
};

/// A public or private SSH key. See docs/design/04 §4.5.
/// `PublicKey` in host-key APIs is an alias for this type with the invariant is_public().
class SSHPP_API Key {
public:
    Key() = default;
    ~Key();
    Key(Key&&) noexcept;
    Key& operator=(Key&&) noexcept;
    Key(const Key&) = delete;
    Key& operator=(const Key&) = delete;

    explicit operator bool() const noexcept { return native_ != nullptr; }
    native_key native_handle() const noexcept { return native_; }
    static Key from_native(native_key, Ownership);

    static Result<Key> from_private_file(const std::filesystem::path&, PassphraseCallback = {});
    static Result<Key> from_public_file(const std::filesystem::path&);
    static Result<Key> from_public_base64(std::string_view b64, KeyType type);
    static Result<Key> from_authorized_keys_line(std::string_view line);

    Result<std::string>  to_public_base64() const;
    Result<std::string>  to_authorized_keys_line(std::string_view comment = {}) const;
    Result<void>         write_public_file(const std::filesystem::path&) const;
    Result<Key>          public_part() const;

    KeyType     type() const noexcept;
    std::string type_name() const;
    int         bits() const noexcept;
    bool        is_private() const noexcept;
    bool        is_public() const noexcept;
    Result<Fingerprint> fingerprint(HashType = HashType::sha256) const;
    bool        equals(const Key& other, bool compare_private = false) const noexcept;

    static Result<Key> generate(KeyType, int bits = 0);

private:
    explicit Key(native_key n, bool owning) : native_(n), owning_(owning) {}
    native_key native_ = nullptr;
    bool       owning_ = true;
};

using PublicKey = Key;

} // namespace sshpp
