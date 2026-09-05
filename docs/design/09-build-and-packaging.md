# 09 — Build System and Packaging

## 9.1 Requirements

| ID | Requirement |
|----|-------------|
| B-1 | `find_package(libsshpp CONFIG REQUIRED)` + `target_link_libraries(app PRIVATE libsshpp::libsshpp)` is the entire consumer story. |
| B-2 | Works from a Conan 2 package, from a system install, from `FetchContent`/CPM, and as a vendored subdirectory. |
| B-3 | Static, shared and header-only, selectable without editing sources. |
| B-4 | No transitive leak of libssh headers to consumers (see [02 §2.4](02-architecture.md#24-hiding-the-c-api)); libssh appears as a `PRIVATE` link dependency for static/shared builds. |
| B-5 | Cross-compilation clean (no `try_run`, no host-tool assumptions in the library target). |
| B-6 | Reproducible: no `file(GLOB)` for sources. |
| B-7 | CMake ≥ 3.23 (for `FILE_SET HEADERS`); a documented ≥ 3.21 fallback path exists for distro packagers. |

## 9.2 Top-level `CMakeLists.txt` (structure)

```cmake
cmake_minimum_required(VERSION 3.23)

project(libsshpp
    VERSION      1.0.0
    DESCRIPTION  "Modern C++17 wrapper for libssh"
    HOMEPAGE_URL "https://github.com/<org>/libsshpp"
    LANGUAGES    CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
include(GNUInstallDirs)
include(CMakeDependentOption)

# Are we the top-level project or a subproject?
if(PROJECT_IS_TOP_LEVEL)
    set(LIBSSHPP_DEFAULT_DEV ON)
else()
    set(LIBSSHPP_DEFAULT_DEV OFF)
endif()

# ---------------------------------------------------------------- options ----
option(LIBSSHPP_HEADER_ONLY        "Build as a header-only INTERFACE library" OFF)
option(LIBSSHPP_WITH_SFTP          "Enable the SFTP module"        ON)
option(LIBSSHPP_WITH_SCP           "Enable the SCP module"         ON)
option(LIBSSHPP_WITH_SERVER        "Enable the server module"      ON)
option(LIBSSHPP_WITH_FORWARDING    "Enable port forwarding"        ON)
option(LIBSSHPP_WITH_CONSOLE       "Enable tty helpers (Shell::interact, prompts)" ON)
option(LIBSSHPP_WITH_PCAP          "Enable pcap capture"           OFF)
option(LIBSSHPP_USE_SSH_CONNECTOR  "Use ssh_connector_* for pumps" ON)

option(LIBSSHPP_BUILD_EXAMPLES     "Build examples"     ${LIBSSHPP_DEFAULT_DEV})
option(LIBSSHPP_BUILD_TESTS        "Build tests"        ${LIBSSHPP_DEFAULT_DEV})
option(LIBSSHPP_BUILD_BENCHMARKS   "Build benchmarks"   OFF)
option(LIBSSHPP_BUILD_DOCS         "Build Doxygen docs" OFF)
option(LIBSSHPP_BUILD_FUZZERS      "Build libFuzzer targets" OFF)

option(LIBSSHPP_WARNINGS_AS_ERRORS "Treat warnings as errors" ${LIBSSHPP_DEFAULT_DEV})
option(LIBSSHPP_INSTALL            "Generate the install target" ON)
set(LIBSSHPP_SANITIZERS "" CACHE STRING "Semicolon list: address;undefined;thread;memory")

cmake_dependent_option(LIBSSHPP_SYSTEM_TESTS
    "Enable tests requiring a Dockerised OpenSSH server" OFF
    "LIBSSHPP_BUILD_TESTS" OFF)

# ------------------------------------------------------------ dependencies ---
# Conan / vcpkg provide libssh::libssh in CONFIG mode; FindLibssh.cmake is the
# pkg-config-based fallback for system installs.
find_package(libssh CONFIG QUIET)
if(NOT libssh_FOUND)
    find_package(Libssh MODULE REQUIRED)      # cmake/FindLibssh.cmake -> libssh::libssh
endif()

if(libssh_VERSION AND libssh_VERSION VERSION_LESS 0.10.4)
    message(FATAL_ERROR "libsshpp requires libssh >= 0.10.4 (found ${libssh_VERSION})")
endif()

# --------------------------------------------------------------- the target --
if(LIBSSHPP_HEADER_ONLY)
    add_library(libsshpp INTERFACE)
    set(_scope INTERFACE)
else()
    add_library(libsshpp)                     # STATIC or SHARED per BUILD_SHARED_LIBS
    set(_scope PUBLIC)
    target_sources(libsshpp PRIVATE ${LIBSSHPP_SOURCES})   # explicit list, no GLOB
endif()
add_library(libsshpp::libsshpp ALIAS libsshpp)

target_compile_features(libsshpp ${_scope} cxx_std_17)

target_include_directories(libsshpp ${_scope}
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

target_sources(libsshpp ${_scope}
    FILE_SET  HEADERS
    BASE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_BINARY_DIR}/include
    FILES     ${LIBSSHPP_HEADERS} ${CMAKE_CURRENT_BINARY_DIR}/include/sshpp/config.hpp
              ${CMAKE_CURRENT_BINARY_DIR}/include/sshpp/export.hpp)

# libssh is PRIVATE for compiled builds (B-4). Header-only must expose it.
if(LIBSSHPP_HEADER_ONLY)
    target_link_libraries(libsshpp INTERFACE libssh::libssh)
    target_compile_definitions(libsshpp INTERFACE SSHPP_HEADER_ONLY=1)
else()
    target_link_libraries(libsshpp PRIVATE libssh::libssh)
endif()

find_package(Threads REQUIRED)
target_link_libraries(libsshpp ${_scope} Threads::Threads)
if(WIN32)
    target_link_libraries(libsshpp PRIVATE ws2_32)
endif()

set_target_properties(libsshpp PROPERTIES
    OUTPUT_NAME            sshpp
    VERSION                ${PROJECT_VERSION}
    SOVERSION              ${PROJECT_VERSION_MAJOR}
    CXX_VISIBILITY_PRESET  hidden
    VISIBILITY_INLINES_HIDDEN ON
    POSITION_INDEPENDENT_CODE ON
    EXPORT_NAME            libsshpp)
```

Then: `include(CompilerWarnings)`, `include(Sanitizers)`, generated headers (§9.4), install
rules (§9.5), and `add_subdirectory` for tests/examples/bench/docs guarded by their options.

## 9.3 Header-only mode

Implementation files are written once, as `.ipp` files under `include/sshpp/detail/`, and:

* **Compiled mode** — `src/session.cpp` is `#define SSHPP_SOURCE 1` + `#include
  <sshpp/detail/session.ipp>`. Functions get no `inline`.
* **Header-only mode** — `sshpp/session.hpp` ends with
  `#if defined(SSHPP_HEADER_ONLY) #include <sshpp/detail/session.ipp> #endif`, and
  `SSHPP_INLINE` expands to `inline`.

```cpp
// sshpp/config.hpp (generated)
#if defined(SSHPP_HEADER_ONLY)
#  define SSHPP_INLINE inline
#else
#  define SSHPP_INLINE
#endif
```

Every out-of-line definition is written `SSHPP_INLINE Result<void> Session::try_connect() { … }`.
One CI job builds the whole test-suite in header-only mode to prove there are no ODR or
missing-`inline` mistakes.

Caveats, documented in the README: header-only exposes libssh headers to the consumer
(breaking NFR-4 by necessity), compiles much slower, and has the same licensing profile as
static linking.

## 9.4 Feature detection and generated headers

`cmake/FeatureChecks.cmake` uses `check_cxx_symbol_exists` / `check_cxx_source_compiles`
against libssh — never `try_run`, so cross-compilation stays clean (B-5):

```cmake
include(CheckCXXSymbolExists)
cmake_push_check_state()
    set(CMAKE_REQUIRED_LIBRARIES libssh::libssh)
    check_cxx_symbol_exists(sftp_aio_begin_read           "libssh/sftp.h"   SSHPP_HAS_SFTP_AIO)
    check_cxx_symbol_exists(ssh_channel_get_exit_state    "libssh/libssh.h" SSHPP_HAS_CHANNEL_EXIT_STATE)
    check_cxx_symbol_exists(sftp_limits                   "libssh/sftp.h"   SSHPP_HAS_SFTP_LIMITS)
    check_cxx_symbol_exists(ssh_connector_new             "libssh/callbacks.h" SSHPP_HAS_CONNECTOR)
    check_cxx_symbol_exists(ssh_bind_new                  "libssh/server.h" SSHPP_HAS_SERVER)
    check_cxx_symbol_exists(ssh_userauth_gssapi           "libssh/libssh.h" SSHPP_HAS_GSSAPI)
cmake_pop_check_state()
configure_file(cmake/config.hpp.in include/sshpp/config.hpp @ONLY)
```

`sshpp/config.hpp` (generated) contains the version macros, the feature macros above, the
module toggles (`SSHPP_WITH_SFTP` …) and `SSHPP_INLINE`. `sshpp/export.hpp` is produced by
`generate_export_header()` and defines `SSHPP_API`, `SSHPP_NO_EXPORT`, `SSHPP_DEPRECATED`.

`Library::features()` reports the same information at runtime, so a binary built against a
newer libssh and run against an older one degrades predictably instead of crashing.

## 9.5 Install and CMake package config

```cmake
if(LIBSSHPP_INSTALL)
    install(TARGETS libsshpp
            EXPORT  libsshppTargets
            FILE_SET HEADERS DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
            RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR}
            LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
            ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR})

    install(EXPORT libsshppTargets
            NAMESPACE   libsshpp::
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libsshpp)

    include(CMakePackageConfigHelpers)
    configure_package_config_file(cmake/libsshppConfig.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/libsshppConfig.cmake
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libsshpp)
    write_basic_package_version_file(
        ${CMAKE_CURRENT_BINARY_DIR}/libsshppConfigVersion.cmake
        COMPATIBILITY SameMajorVersion)          # matches the SemVer policy in doc 11

    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libsshppConfig.cmake
                  ${CMAKE_CURRENT_BINARY_DIR}/libsshppConfigVersion.cmake
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libsshpp)

    install(FILES LICENSE THIRD_PARTY_NOTICES.md
            DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/licenses/libsshpp)
    # pkg-config for non-CMake consumers
    configure_file(cmake/libsshpp.pc.in libsshpp.pc @ONLY)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libsshpp.pc
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
endif()

export(EXPORT libsshppTargets NAMESPACE libsshpp::
       FILE ${CMAKE_CURRENT_BINARY_DIR}/libsshppTargets.cmake)   # build-tree usage
```

`cmake/libsshppConfig.cmake.in`:

```cmake
@PACKAGE_INIT@
include(CMakeFindDependencyMacro)
find_dependency(Threads)

# Only a static or header-only libsshpp forces the consumer to resolve libssh.
if(@LIBSSHPP_NEEDS_LIBSSH_DOWNSTREAM@)
    find_dependency(libssh @libssh_VERSION@)
endif()

include("${CMAKE_CURRENT_LIST_DIR}/libsshppTargets.cmake")

set(libsshpp_WITH_SFTP   @LIBSSHPP_WITH_SFTP@)
set(libsshpp_WITH_SCP    @LIBSSHPP_WITH_SCP@)
set(libsshpp_WITH_SERVER @LIBSSHPP_WITH_SERVER@)
set(libsshpp_HEADER_ONLY @LIBSSHPP_HEADER_ONLY@)

check_required_components(libsshpp)
```

`LIBSSHPP_NEEDS_LIBSSH_DOWNSTREAM` is `TRUE` for static and header-only builds (where libssh
symbols must be resolved by the consumer's link line) and `FALSE` for shared builds.

Consumer-side component support: `find_package(libsshpp CONFIG REQUIRED COMPONENTS sftp server)`
fails with a clear message if the installed package was built without them.

## 9.6 Conan 2 recipe

`conanfile.py`:

```python
from conan import ConanFile
from conan.tools.cmake import CMake, CMakeToolchain, CMakeDeps, cmake_layout
from conan.tools.files import copy, get
from conan.tools.build import check_min_cppstd
from conan.tools.scm import Version
from conan.errors import ConanInvalidConfiguration
import os


class LibsshppConan(ConanFile):
    name = "libsshpp"
    version = "1.0.0"
    license = "LGPL-2.1-or-later"
    url = "https://github.com/<org>/libsshpp"
    homepage = url
    description = "Modern C++17 wrapper for libssh"
    topics = ("ssh", "sftp", "scp", "libssh", "cpp17", "networking")

    package_type = "library"
    settings = "os", "arch", "compiler", "build_type"

    options = {
        "shared":        [True, False],
        "fPIC":          [True, False],
        "header_only":   [True, False],
        "with_sftp":     [True, False],
        "with_scp":      [True, False],
        "with_server":   [True, False],
        "with_forwarding": [True, False],
        "with_console":  [True, False],
        "with_pcap":     [True, False],
    }
    default_options = {
        "shared": False,
        "fPIC": True,
        "header_only": False,
        "with_sftp": True,
        "with_scp": True,
        "with_server": True,
        "with_forwarding": True,
        "with_console": True,
        "with_pcap": False,
        # Sub-dependency defaults: shared libssh keeps LGPL relinking simple.
        "libssh/*:shared": True,
        "libssh/*:with_zlib": True,
        "libssh/*:with_server": True,
    }

    exports_sources = "CMakeLists.txt", "cmake/*", "include/*", "src/*", "LICENSE", "THIRD_PARTY_NOTICES.md"

    def config_options(self):
        if self.settings.os == "Windows":
            del self.options.fPIC

    def configure(self):
        if self.options.header_only:
            self.options.rm_safe("shared")
            self.options.rm_safe("fPIC")
            self.package_type = "header-library"
        elif self.options.shared:
            self.options.rm_safe("fPIC")
        if not self.options.with_sftp:
            # SCP is independent, but the tree helpers in sftp/algorithms need SFTP.
            pass

    def requirements(self):
        # Public transitive only for header-only/static consumers.
        self.requires("libssh/0.11.1",
                      transitive_headers=bool(self.options.header_only),
                      transitive_libs=not (self.options.get_safe("shared", False)))

    def build_requirements(self):
        self.tool_requires("cmake/[>=3.23 <5]")
        if self.conf.get("tools.build:skip_test", default=False) is False:
            self.test_requires("catch2/3.5.4")

    def validate(self):
        check_min_cppstd(self, 17)
        if self.options.with_server and not self.dependencies["libssh"].options.with_server:
            raise ConanInvalidConfiguration(
                "libsshpp/*:with_server=True requires libssh/*:with_server=True")

    def layout(self):
        cmake_layout(self)

    def generate(self):
        tc = CMakeToolchain(self)
        tc.cache_variables["LIBSSHPP_HEADER_ONLY"]     = bool(self.options.header_only)
        tc.cache_variables["LIBSSHPP_WITH_SFTP"]       = bool(self.options.with_sftp)
        tc.cache_variables["LIBSSHPP_WITH_SCP"]        = bool(self.options.with_scp)
        tc.cache_variables["LIBSSHPP_WITH_SERVER"]     = bool(self.options.with_server)
        tc.cache_variables["LIBSSHPP_WITH_FORWARDING"] = bool(self.options.with_forwarding)
        tc.cache_variables["LIBSSHPP_WITH_CONSOLE"]    = bool(self.options.with_console)
        tc.cache_variables["LIBSSHPP_WITH_PCAP"]       = bool(self.options.with_pcap)
        tc.cache_variables["LIBSSHPP_BUILD_EXAMPLES"]  = False
        tc.cache_variables["LIBSSHPP_BUILD_TESTS"]     = not self.conf.get(
            "tools.build:skip_test", default=True, check_type=bool)
        tc.generate()
        CMakeDeps(self).generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()
        if not self.conf.get("tools.build:skip_test", default=True, check_type=bool):
            cmake.ctest(cli_args=["--output-on-failure"])

    def package(self):
        copy(self, "LICENSE", self.source_folder,
             os.path.join(self.package_folder, "licenses"))
        CMake(self).install()

    def package_info(self):
        self.cpp_info.set_property("cmake_file_name", "libsshpp")
        self.cpp_info.set_property("cmake_target_name", "libsshpp::libsshpp")
        self.cpp_info.set_property("pkg_config_name", "libsshpp")

        if self.options.header_only:
            self.cpp_info.bindirs = []
            self.cpp_info.libdirs = []
            self.cpp_info.defines.append("SSHPP_HEADER_ONLY=1")
        else:
            self.cpp_info.libs = ["sshpp"]

        if self.settings.os in ("Linux", "FreeBSD"):
            self.cpp_info.system_libs.extend(["pthread", "dl"])
        elif self.settings.os == "Windows":
            self.cpp_info.system_libs.append("ws2_32")
```

Notes:

* `transitive_headers` is enabled only for header-only, matching B-4 and the CMake config.
* `transitive_libs` is enabled for static builds so the consumer's link line gets libssh.
* Defaulting `libssh/*:shared=True` is a deliberate licensing choice (see
  [01 §1.7](01-goals-and-scope.md#17-licensing)); the README explains how to override it and
  what that implies.
* `test_package/` builds a tiny program that spins up `server::TestServer` and connects to it,
  so the package test exercises a real handshake without network access.

### Consumer `conanfile.txt`

```ini
[requires]
libsshpp/1.0.0

[generators]
CMakeDeps
CMakeToolchain

[options]
libsshpp/*:with_server=False
libssh/*:shared=True
```

## 9.7 `CMakePresets.json`

Presets cover the combinations CI builds, so contributors run exactly what CI runs:

| Preset | Description |
|---|---|
| `dev` | Ninja, Debug, tests + examples, warnings-as-errors |
| `dev-asan` | `dev` + `-fsanitize=address,undefined` |
| `dev-tsan` | `dev` + `-fsanitize=thread` |
| `dev-header-only` | `LIBSSHPP_HEADER_ONLY=ON`, tests on |
| `release` | RelWithDebInfo, LTO/IPO on, tests on |
| `release-shared` | `BUILD_SHARED_LIBS=ON` |
| `minimal` | All modules `OFF` except core — proves the option matrix compiles |
| `conan-*` | Generated by `conan install` (`CMakeToolchain` writes `conan-default` etc.) |

`configurePresets` set `CMAKE_EXPORT_COMPILE_COMMANDS=ON` and
`CMAKE_TOOLCHAIN_FILE` from `CONAN_TOOLCHAIN` when present, so
`conan install . -b missing && cmake --preset conan-release` just works.

## 9.8 `FetchContent` / CPM

```cmake
include(FetchContent)
FetchContent_Declare(libsshpp
    GIT_REPOSITORY https://github.com/<org>/libsshpp.git
    GIT_TAG        v1.0.0)
set(LIBSSHPP_BUILD_TESTS    OFF CACHE BOOL "" FORCE)
set(LIBSSHPP_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(libsshpp)
target_link_libraries(app PRIVATE libsshpp::libsshpp)
```

libssh itself is **not** fetched — `FetchContent` users must provide `libssh::libssh` (system
package, vcpkg, or Conan). Building libssh from source pulls in OpenSSL/mbedTLS/zlib and is
firmly out of scope; the configure step fails with a message that says exactly this and lists
the three supported ways to get it.

## 9.9 Other package managers

* **vcpkg** — a port is maintained in-tree at `packaging/vcpkg/`, using the same CMake options;
  features map to `sftp`, `scp`, `server`, `forwarding`.
* **Debian/Fedora** — `packaging/debian/` and `packaging/libsshpp.spec` build shared-only with
  all modules on and split `libsshpp1` / `libsshpp-dev`.
* **Nix** — `flake.nix` exposing `packages.default` and a `devShell` with the full toolchain.

None of these are release blockers for 1.0 except Conan and the CMake package.
