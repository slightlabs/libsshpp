// SPDX-License-Identifier: LGPL-2.1-or-later
// Generated from src/key.cpp; see docs/design/09 §9.3.
#include <sshpp/config.hpp>
// SPDX-License-Identifier: LGPL-2.1-or-later
#include <sshpp/key.hpp>

#include <libssh/libssh.h>

#include <cstring>
#include <sstream>
#include <type_traits>

namespace sshpp {

namespace {

static_assert(std::is_same_v<native_key, ssh_key>, "libssh changed ssh_key's definition");

KeyType key_type_from_native(ssh_keytypes_e t) {
    switch (t) {
        case SSH_KEYTYPE_DSS: return KeyType::dss;
        case SSH_KEYTYPE_RSA: return KeyType::rsa;
        case SSH_KEYTYPE_RSA1: return KeyType::rsa1;
        case SSH_KEYTYPE_ECDSA_P256: return KeyType::ecdsa_p256;
        case SSH_KEYTYPE_ECDSA_P384: return KeyType::ecdsa_p384;
        case SSH_KEYTYPE_ECDSA_P521: return KeyType::ecdsa_p521;
        case SSH_KEYTYPE_ED25519: return KeyType::ed25519;
        case SSH_KEYTYPE_DSS_CERT01: return KeyType::dss_cert01;
        case SSH_KEYTYPE_RSA_CERT01: return KeyType::rsa_cert01;
        case SSH_KEYTYPE_ECDSA_P256_CERT01: return KeyType::ecdsa_p256_cert01;
        case SSH_KEYTYPE_ECDSA_P384_CERT01: return KeyType::ecdsa_p384_cert01;
        case SSH_KEYTYPE_ECDSA_P521_CERT01: return KeyType::ecdsa_p521_cert01;
        case SSH_KEYTYPE_ED25519_CERT01: return KeyType::ed25519_cert01;
        case SSH_KEYTYPE_SK_ECDSA: return KeyType::sk_ecdsa;
        case SSH_KEYTYPE_SK_ED25519: return KeyType::sk_ed25519;
        case SSH_KEYTYPE_SK_ECDSA_CERT01: return KeyType::sk_ecdsa_cert01;
        case SSH_KEYTYPE_SK_ED25519_CERT01: return KeyType::sk_ed25519_cert01;
        case SSH_KEYTYPE_UNKNOWN:
        default: return KeyType::unknown;
    }
}

ssh_keytypes_e key_type_to_native(KeyType t) {
    switch (t) {
        case KeyType::dss: return SSH_KEYTYPE_DSS;
        case KeyType::rsa: return SSH_KEYTYPE_RSA;
        case KeyType::rsa1: return SSH_KEYTYPE_RSA1;
        case KeyType::ecdsa_p256: return SSH_KEYTYPE_ECDSA_P256;
        case KeyType::ecdsa_p384: return SSH_KEYTYPE_ECDSA_P384;
        case KeyType::ecdsa_p521: return SSH_KEYTYPE_ECDSA_P521;
        case KeyType::ed25519: return SSH_KEYTYPE_ED25519;
        case KeyType::dss_cert01: return SSH_KEYTYPE_DSS_CERT01;
        case KeyType::rsa_cert01: return SSH_KEYTYPE_RSA_CERT01;
        case KeyType::ecdsa_p256_cert01: return SSH_KEYTYPE_ECDSA_P256_CERT01;
        case KeyType::ecdsa_p384_cert01: return SSH_KEYTYPE_ECDSA_P384_CERT01;
        case KeyType::ecdsa_p521_cert01: return SSH_KEYTYPE_ECDSA_P521_CERT01;
        case KeyType::ed25519_cert01: return SSH_KEYTYPE_ED25519_CERT01;
        case KeyType::sk_ecdsa: return SSH_KEYTYPE_SK_ECDSA;
        case KeyType::sk_ed25519: return SSH_KEYTYPE_SK_ED25519;
        case KeyType::sk_ecdsa_cert01: return SSH_KEYTYPE_SK_ECDSA_CERT01;
        case KeyType::sk_ed25519_cert01: return SSH_KEYTYPE_SK_ED25519_CERT01;
        case KeyType::unknown:
        default: return SSH_KEYTYPE_UNKNOWN;
    }
}

struct PassphraseTrampolineData {
    const PassphraseCallback* cb;
    std::string               key_path;
    int                       attempt = 0;
};

int passphrase_trampoline(const char* prompt, char* buf, size_t len, int /*echo*/, int /*verify*/,
                         void* userdata) {
    (void)prompt;
    auto* data = static_cast<PassphraseTrampolineData*>(userdata);
    if (data == nullptr || data->cb == nullptr || !*data->cb) return -1;
    PassphraseRequest req;
    req.key_path = data->key_path;
    req.attempt = data->attempt;
    auto result = (*data->cb)(req);
    if (!result) return -1;
    std::string_view v = result->view();
    if (v.size() >= len) return -1;
    std::memcpy(buf, v.data(), v.size());
    buf[v.size()] = '\0';
    return 0;
}

} // namespace

SSHPP_INLINE Key::~Key() {
    if (native_ != nullptr && owning_) {
        ssh_key_free(native_);
    }
    native_ = nullptr;
}

SSHPP_INLINE Key::Key(Key&& other) noexcept
    : native_(std::exchange(other.native_, nullptr)), owning_(other.owning_) {}

SSHPP_INLINE Key& Key::operator=(Key&& other) noexcept {
    if (this != &other) {
        if (native_ != nullptr && owning_) ssh_key_free(native_);
        native_ = std::exchange(other.native_, nullptr);
        owning_ = other.owning_;
    }
    return *this;
}

SSHPP_INLINE Key Key::from_native(native_key n, Ownership o) { return Key(n, o == Ownership::owning); }

SSHPP_INLINE Result<Key> Key::from_private_file(const std::filesystem::path& path, PassphraseCallback cb) {
    ssh_key key = nullptr;
    PassphraseTrampolineData data{&cb, path.string(), 0};
    int rc = ssh_pki_import_privkey_file(path.string().c_str(), nullptr,
                                         cb ? passphrase_trampoline : nullptr,
                                         cb ? &data : nullptr, &key);
    if (rc != SSH_OK || key == nullptr) {
        ErrorInfo info;
        info.operation = "ssh_pki_import_privkey_file";
        info.code = make_error_code(errc::key_import_failed);
        info.message = "failed to import private key from " + path.string();
        return info;
    }
    return Key(key, true);
}

SSHPP_INLINE Result<Key> Key::from_public_file(const std::filesystem::path& path) {
    ssh_key key = nullptr;
    int rc = ssh_pki_import_pubkey_file(path.string().c_str(), &key);
    if (rc != SSH_OK || key == nullptr) {
        ErrorInfo info;
        info.operation = "ssh_pki_import_pubkey_file";
        info.code = make_error_code(errc::key_import_failed);
        info.message = "failed to import public key from " + path.string();
        return info;
    }
    return Key(key, true);
}

SSHPP_INLINE Result<Key> Key::from_public_base64(std::string_view b64, KeyType type) {
    ssh_key key = nullptr;
    std::string b64_str(b64);
    int rc = ssh_pki_import_pubkey_base64(b64_str.c_str(), key_type_to_native(type), &key);
    if (rc != SSH_OK || key == nullptr) {
        ErrorInfo info;
        info.operation = "ssh_pki_import_pubkey_base64";
        info.code = make_error_code(errc::key_import_failed);
        return info;
    }
    return Key(key, true);
}

SSHPP_INLINE Result<Key> Key::from_authorized_keys_line(std::string_view line) {
    std::istringstream iss{std::string(line)};
    std::string type_name, b64, comment;
    iss >> type_name >> b64;
    std::getline(iss, comment);
    if (!comment.empty() && comment.front() == ' ') comment.erase(0, 1);

    ssh_keytypes_e native_type = ssh_key_type_from_name(type_name.c_str());
    if (native_type == SSH_KEYTYPE_UNKNOWN) {
        ErrorInfo info;
        info.operation = "ssh_key_type_from_name";
        info.code = make_error_code(errc::unsupported_key_type);
        info.message = "unrecognized key type '" + type_name + "'";
        return info;
    }
    return from_public_base64(b64, key_type_from_native(native_type));
}

SSHPP_INLINE Result<std::string> Key::to_public_base64() const {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Key::to_public_base64"};
    char* b64 = nullptr;
    int rc = ssh_pki_export_pubkey_base64(native_, &b64);
    if (rc != SSH_OK || b64 == nullptr) {
        ErrorInfo info;
        info.operation = "ssh_pki_export_pubkey_base64";
        info.code = make_error_code(errc::key_export_failed);
        return info;
    }
    std::string result(b64);
    ssh_string_free_char(b64);
    return result;
}

SSHPP_INLINE Result<std::string> Key::to_authorized_keys_line(std::string_view comment) const {
    auto b64 = to_public_base64();
    if (!b64) return b64.error();
    std::string line = type_name() + " " + *b64;
    if (!comment.empty()) {
        line += " ";
        line += comment;
    }
    return line;
}

SSHPP_INLINE Result<void> Key::write_public_file(const std::filesystem::path& path) const {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Key::write_public_file"};
    int rc = ssh_pki_export_pubkey_file(native_, path.string().c_str());
    if (rc != SSH_OK) {
        ErrorInfo info;
        info.operation = "ssh_pki_export_pubkey_file";
        info.code = make_error_code(errc::key_export_failed);
        return info;
    }
    return {};
}

SSHPP_INLINE Result<Key> Key::public_part() const {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Key::public_part"};
    ssh_key pub = nullptr;
    int rc = ssh_pki_export_privkey_to_pubkey(native_, &pub);
    if (rc != SSH_OK || pub == nullptr) {
        ErrorInfo info;
        info.operation = "ssh_pki_export_privkey_to_pubkey";
        info.code = make_error_code(errc::key_export_failed);
        return info;
    }
    return Key(pub, true);
}

SSHPP_INLINE KeyType Key::type() const noexcept {
    if (native_ == nullptr) return KeyType::unknown;
    return key_type_from_native(ssh_key_type(native_));
}

SSHPP_INLINE std::string Key::type_name() const {
    if (native_ == nullptr) return "unknown";
    const char* n = ssh_key_type_to_char(ssh_key_type(native_));
    return n ? n : "unknown";
}

SSHPP_INLINE int Key::bits() const noexcept {
    // libssh does not expose a portable "key bits" accessor across all key types via
    // the public API; fingerprint/type checks cover the wrapper's documented use cases.
    return 0;
}

SSHPP_INLINE bool Key::is_private() const noexcept { return native_ != nullptr && ssh_key_is_private(native_) != 0; }
SSHPP_INLINE bool Key::is_public() const noexcept { return native_ != nullptr && ssh_key_is_public(native_) != 0; }

SSHPP_INLINE Result<Fingerprint> Key::fingerprint(HashType type) const {
    if (native_ == nullptr) return ErrorInfo{make_error_code(errc::invalid_handle), "", "Key::fingerprint"};
    ssh_publickey_hash_type native_type;
    switch (type) {
        case HashType::md5: native_type = SSH_PUBLICKEY_HASH_MD5; break;
        case HashType::sha1: native_type = SSH_PUBLICKEY_HASH_SHA1; break;
        case HashType::sha256:
        default: native_type = SSH_PUBLICKEY_HASH_SHA256; break;
    }
    unsigned char* hash = nullptr;
    size_t hlen = 0;
    int rc = ssh_get_publickey_hash(native_, native_type, &hash, &hlen);
    if (rc != SSH_OK || hash == nullptr) {
        ErrorInfo info;
        info.operation = "ssh_get_publickey_hash";
        info.code = make_error_code(errc::key_export_failed);
        return info;
    }
    std::vector<std::byte> bytes(hlen);
    std::memcpy(bytes.data(), hash, hlen);
    ssh_string_free_char(reinterpret_cast<char*>(hash));
    return Fingerprint(type, std::move(bytes));
}

SSHPP_INLINE bool Key::equals(const Key& other, bool compare_private) const noexcept {
    if (native_ == nullptr || other.native_ == nullptr) return native_ == other.native_;
    return ssh_key_cmp(native_, other.native_,
                       compare_private ? SSH_KEY_CMP_PRIVATE : SSH_KEY_CMP_PUBLIC) == 0;
}

SSHPP_INLINE Result<Key> Key::generate(KeyType type, int bits) {
    ssh_key key = nullptr;
    int default_bits = bits;
    if (default_bits == 0) {
        switch (type) {
            case KeyType::rsa: default_bits = 3072; break;
            case KeyType::ecdsa_p256: default_bits = 256; break;
            case KeyType::ecdsa_p384: default_bits = 384; break;
            case KeyType::ecdsa_p521: default_bits = 521; break;
            default: default_bits = 0; break;
        }
    }
    int rc = ssh_pki_generate(key_type_to_native(type), default_bits, &key);
    if (rc != SSH_OK || key == nullptr) {
        ErrorInfo info;
        info.operation = "ssh_pki_generate";
        info.code = make_error_code(errc::key_generation_failed);
        return info;
    }
    return Key(key, true);
}

// --- Fingerprint ---------------------------------------------------------------

SSHPP_INLINE std::string Fingerprint::to_string() const {
    if (bytes_.empty()) return {};
    char* hex = ssh_get_hexa(reinterpret_cast<const unsigned char*>(bytes_.data()), bytes_.size());
    std::string result;
    const char* prefix = type_ == HashType::sha256 ? "SHA256:" : (type_ == HashType::sha1 ? "SHA1:" : "MD5:");
    if (hex != nullptr) {
        result = prefix;
        result += hex;
        ssh_string_free_char(hex);
    }
    return result;
}

SSHPP_INLINE std::string Fingerprint::to_hex() const {
    if (bytes_.empty()) return {};
    char* hex = ssh_get_hexa(reinterpret_cast<const unsigned char*>(bytes_.data()), bytes_.size());
    std::string result = hex ? hex : "";
    if (hex) ssh_string_free_char(hex);
    return result;
}

SSHPP_INLINE bool Fingerprint::operator==(const Fingerprint& other) const noexcept {
    if (type_ != other.type_ || bytes_.size() != other.bytes_.size()) return false;
    // Constant-time compare.
    unsigned char diff = 0;
    for (std::size_t i = 0; i < bytes_.size(); ++i) {
        diff = static_cast<unsigned char>(diff | (static_cast<unsigned char>(bytes_[i]) ^
                                                  static_cast<unsigned char>(other.bytes_[i])));
    }
    return diff == 0;
}

} // namespace sshpp
