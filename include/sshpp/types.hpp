// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include <cstddef>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace sshpp {

/// Whether a wrapper type owns (frees) the native handle it holds, or merely borrows it
/// (e.g. a channel handed to a server callback that libssh still owns).
enum class Ownership { owning, borrowed };

/// A minimal span-like non-owning view over contiguous bytes (C++17 has no std::span).
template <class T>
class BasicByteSpan {
public:
    using element_type = T;

    constexpr BasicByteSpan() noexcept = default;
    constexpr BasicByteSpan(T* data, std::size_t size) noexcept : data_(data), size_(size) {}

    template <class Byte, class = std::enable_if_t<sizeof(Byte) == 1 && std::is_const_v<T>>>
    BasicByteSpan(const Byte* data, std::size_t size) noexcept
        : data_(reinterpret_cast<T*>(data)), size_(size) {}

    // Mutable view constructed from a contiguous non-const byte-sized buffer.
    template <class Byte, class = std::enable_if_t<sizeof(Byte) == 1 && !std::is_const_v<T>>>
    BasicByteSpan(Byte* data, std::size_t size) noexcept
        : data_(reinterpret_cast<T*>(data)), size_(size) {}

    constexpr T*           data() const noexcept { return data_; }
    constexpr std::size_t  size() const noexcept { return size_; }
    constexpr bool         empty() const noexcept { return size_ == 0; }
    constexpr T&           operator[](std::size_t i) const noexcept { return data_[i]; }
    constexpr T*           begin() const noexcept { return data_; }
    constexpr T*           end() const noexcept { return data_ + size_; }

    BasicByteSpan subspan(std::size_t offset, std::size_t count = static_cast<std::size_t>(-1)) const noexcept {
        std::size_t n = (count == static_cast<std::size_t>(-1)) ? (size_ - offset) : count;
        return BasicByteSpan(data_ + offset, n);
    }

private:
    T*          data_ = nullptr;
    std::size_t size_ = 0;
};

/// Input byte range. Implicitly constructible from std::string_view / std::vector<std::byte>.
class ByteView : public BasicByteSpan<const std::byte> {
public:
    using BasicByteSpan::BasicByteSpan;
    constexpr ByteView() noexcept = default;
    ByteView(std::string_view sv) noexcept : BasicByteSpan(sv.data(), sv.size()) {}
    ByteView(const std::vector<std::byte>& v) noexcept : BasicByteSpan(v.data(), v.size()) {}

    std::string_view as_string_view() const noexcept {
        return {reinterpret_cast<const char*>(data()), size()};
    }
};

/// Output byte range (caller-owned, mutable buffer to write into).
class MutableByteView : public BasicByteSpan<std::byte> {
public:
    using BasicByteSpan::BasicByteSpan;
    constexpr MutableByteView() noexcept = default;
    MutableByteView(std::vector<std::byte>& v) noexcept : BasicByteSpan(v.data(), v.size()) {}
};

/// A remote (POSIX, '/'-separated) path. Deliberately distinct from std::filesystem::path,
/// which would mangle separators on Windows. See docs/design/02 ADR-7.
class RemotePath {
public:
    RemotePath() = default;
    RemotePath(std::string p) : path_(std::move(p)) {}
    RemotePath(const char* p) : path_(p) {}

    const std::string& str() const noexcept { return path_; }
    bool empty() const noexcept { return path_.empty(); }

    RemotePath operator/(std::string_view child) const {
        std::string result = path_;
        if (!result.empty() && result.back() != '/' && !child.empty() && child.front() != '/') {
            result.push_back('/');
        }
        result.append(child);
        return RemotePath{std::move(result)};
    }

    friend bool operator==(const RemotePath& a, const RemotePath& b) noexcept {
        return a.path_ == b.path_;
    }
    friend bool operator!=(const RemotePath& a, const RemotePath& b) noexcept { return !(a == b); }

private:
    std::string path_;
};

namespace detail {

/// Allocator that scrubs memory on deallocation, for SecureString.
template <class T>
struct ZeroingAllocator {
    using value_type = T;

    ZeroingAllocator() noexcept = default;
    template <class U> ZeroingAllocator(const ZeroingAllocator<U>&) noexcept {}

    T* allocate(std::size_t n) {
        return static_cast<T*>(::operator new(n * sizeof(T)));
    }
    void deallocate(T* p, std::size_t n) noexcept {
        if (p != nullptr && n != 0) {
            volatile auto* vp = reinterpret_cast<volatile unsigned char*>(p);
            for (std::size_t i = 0; i < n * sizeof(T); ++i) vp[i] = 0;
        }
        ::operator delete(p);
    }

    template <class U> bool operator==(const ZeroingAllocator<U>&) const noexcept { return true; }
    template <class U> bool operator!=(const ZeroingAllocator<U>&) const noexcept { return false; }
};

} // namespace detail

/// A string for secrets (passwords, passphrases) that scrubs its buffer on deallocation.
/// Deliberately has no operator<< so it cannot be logged by accident.
class SecureString {
public:
    using storage_type = std::basic_string<char, std::char_traits<char>, detail::ZeroingAllocator<char>>;

    SecureString() = default;
    SecureString(const char* s) : data_(s) {}
    SecureString(std::string_view sv) : data_(sv.begin(), sv.end()) {}
    SecureString(std::string s) : data_(s.begin(), s.end()) {
        // Best effort: scrub the caller's temporary now that we've copied it.
        volatile auto* vp = reinterpret_cast<volatile char*>(s.data());
        for (std::size_t i = 0; i < s.size(); ++i) vp[i] = 0;
    }

    const char* c_str() const noexcept { return data_.c_str(); }
    std::size_t size() const noexcept { return data_.size(); }
    bool empty() const noexcept { return data_.empty(); }
    std::string_view view() const noexcept { return {data_.data(), data_.size()}; }

private:
    storage_type data_;
};

} // namespace sshpp
