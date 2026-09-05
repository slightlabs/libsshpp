cmake_minimum_required(VERSION 3.23)

project(libsshpp
    VERSION      0.1.0
    DESCRIPTION  "Modern C++17 wrapper for libssh"
    HOMEPAGE_URL "https://github.com/example/libsshpp"
    LANGUAGES    CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
include(GNUInstallDirs)
include(CMakeDependentOption)
include(GenerateExportHeader)

if(PROJECT_IS_TOP_LEVEL)
    set(LIBSSHPP_DEFAULT_DEV ON)
else()
    set(LIBSSHPP_DEFAULT_DEV OFF)
endif()

# ---------------------------------------------------------------- options ----
option(LIBSSHPP_HEADER_ONLY        "Build as a header-only INTERFACE library" OFF)
# SCP, server and forwarding modules are not implemented yet (see
# docs/design/11-versioning-and-roadmap.md, M3); the options exist so client
# code guarded by them compiles cleanly against a future release.
option(LIBSSHPP_WITH_SFTP          "Enable the SFTP module"                          ON)
option(LIBSSHPP_WITH_SCP           "Enable the SCP module (not yet implemented)"     OFF)
option(LIBSSHPP_WITH_SERVER        "Enable the server module (not yet implemented)"  OFF)
option(LIBSSHPP_WITH_FORWARDING    "Enable port forwarding (not yet implemented)"    OFF)
option(LIBSSHPP_WITH_CONSOLE       "Enable tty helpers (not yet implemented)"        OFF)
option(LIBSSHPP_WITH_PCAP          "Enable pcap capture"           OFF)
option(LIBSSHPP_USE_SSH_CONNECTOR  "Use ssh_connector_* for pumps" ON)

option(LIBSSHPP_BUILD_EXAMPLES     "Build examples"     ${LIBSSHPP_DEFAULT_DEV})
option(LIBSSHPP_BUILD_TESTS        "Build tests"        ${LIBSSHPP_DEFAULT_DEV})
option(LIBSSHPP_BUILD_BENCHMARKS   "Build benchmarks"   OFF)

option(LIBSSHPP_WARNINGS_AS_ERRORS "Treat warnings as errors" OFF)
option(LIBSSHPP_INSTALL            "Generate the install target" ON)
set(LIBSSHPP_SANITIZERS "" CACHE STRING "Semicolon list: address;undefined;thread;memory")

cmake_dependent_option(LIBSSHPP_SYSTEM_TESTS
    "Enable tests requiring a real sshd" OFF
    "LIBSSHPP_BUILD_TESTS" OFF)

# ------------------------------------------------------------ dependencies ---
find_package(Libssh MODULE REQUIRED)

find_package(Threads REQUIRED)

# ---------------------------------------------------------- feature checks ---
include(FeatureChecks)

set(LIBSSHPP_NEEDS_LIBSSH_DOWNSTREAM $<NOT:$<BOOL:${BUILD_SHARED_LIBS}>>)
if(LIBSSHPP_HEADER_ONLY)
    set(LIBSSHPP_NEEDS_LIBSSH_DOWNSTREAM TRUE)
else()
    set(LIBSSHPP_NEEDS_LIBSSH_DOWNSTREAM FALSE)
endif()

# config.hpp.in's #cmakedefine01 directives reference SSHPP_* variable names,
# distinct from the LIBSSHPP_* cache options users set on the command line.
set(SSHPP_HEADER_ONLY     ${LIBSSHPP_HEADER_ONLY})
set(SSHPP_WITH_SFTP       ${LIBSSHPP_WITH_SFTP})
set(SSHPP_WITH_SCP        ${LIBSSHPP_WITH_SCP})
set(SSHPP_WITH_SERVER     ${LIBSSHPP_WITH_SERVER})
set(SSHPP_WITH_FORWARDING ${LIBSSHPP_WITH_FORWARDING})
set(SSHPP_WITH_CONSOLE    ${LIBSSHPP_WITH_CONSOLE})
set(SSHPP_WITH_PCAP       ${LIBSSHPP_WITH_PCAP})

configure_file(cmake/config.hpp.in ${CMAKE_CURRENT_BINARY_DIR}/include/sshpp/config.hpp @ONLY)

# --------------------------------------------------------------- sources -----
set(LIBSSHPP_HEADERS
    include/sshpp/sshpp.hpp
    include/sshpp/fwd.hpp
    include/sshpp/library.hpp
    include/sshpp/error.hpp
    include/sshpp/result.hpp
    include/sshpp/types.hpp
    include/sshpp/auth_types.hpp
    include/sshpp/session.hpp
    include/sshpp/session_options.hpp
    include/sshpp/auth.hpp
    include/sshpp/key.hpp
    include/sshpp/known_hosts.hpp
    include/sshpp/host_key_verifier.hpp
    include/sshpp/channel.hpp
    include/sshpp/event.hpp
    include/sshpp/exec.hpp
    include/sshpp/detail/native_fwd.hpp
    include/sshpp/detail/unique_handle.hpp
    include/sshpp/detail/session_core.hpp
    include/sshpp/detail/invoke.hpp)

set(LIBSSHPP_SOURCES
    src/error.cpp
    src/invoke.cpp
    src/session_core.cpp
    src/library.cpp
    src/key.cpp
    src/known_hosts.cpp
    src/host_key_verifier.cpp
    src/session_options.cpp
    src/auth.cpp
    src/session.cpp
    src/channel.cpp
    src/event.cpp
    src/exec.cpp)

if(LIBSSHPP_WITH_SFTP)
    list(APPEND LIBSSHPP_HEADERS
        include/sshpp/sftp/attributes.hpp
        include/sshpp/sftp/file.hpp
        include/sshpp/sftp/directory.hpp
        include/sshpp/sftp/sftp.hpp
        include/sshpp/sftp/algorithms.hpp)
    list(APPEND LIBSSHPP_SOURCES
        src/sftp.cpp
        src/file.cpp
        src/directory.cpp
        src/algorithms.cpp)
endif()

# --------------------------------------------------------------- the target --
if(LIBSSHPP_HEADER_ONLY)
    add_library(libsshpp INTERFACE)
    set(_scope INTERFACE)
else()
    add_library(libsshpp ${LIBSSHPP_SOURCES})
    set(_scope PUBLIC)
endif()
add_library(libsshpp::libsshpp ALIAS libsshpp)

target_compile_features(libsshpp ${_scope} cxx_std_17)

target_include_directories(libsshpp ${_scope}
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

if(LIBSSHPP_HEADER_ONLY)
    target_link_libraries(libsshpp INTERFACE libssh::libssh)
    target_compile_definitions(libsshpp INTERFACE SSHPP_HEADER_ONLY=1)
else()
    target_link_libraries(libsshpp PRIVATE libssh::libssh)
    generate_export_header(libsshpp
        BASE_NAME SSHPP
        EXPORT_MACRO_NAME SSHPP_API
        NO_EXPORT_MACRO_NAME SSHPP_NO_EXPORT
        EXPORT_FILE_NAME ${CMAKE_CURRENT_BINARY_DIR}/include/sshpp/export.hpp)
    if(NOT LIBSSHPP_WARNINGS_AS_ERRORS)
        include(CompilerWarnings)
        libsshpp_set_warnings(libsshpp)
    endif()
    include(Sanitizers)
    libsshpp_enable_sanitizers(libsshpp)
endif()

find_package(Threads REQUIRED)
target_link_libraries(libsshpp ${_scope} Threads::Threads)

if(NOT LIBSSHPP_HEADER_ONLY)
    set_target_properties(libsshpp PROPERTIES
        OUTPUT_NAME            sshpp
        VERSION                ${PROJECT_VERSION}
        SOVERSION              ${PROJECT_VERSION_MAJOR}
        CXX_VISIBILITY_PRESET  hidden
        VISIBILITY_INLINES_HIDDEN ON
        POSITION_INDEPENDENT_CODE ON
        EXPORT_NAME            libsshpp)
endif()

# ----------------------------------------------------------------- install ---
if(LIBSSHPP_INSTALL AND NOT LIBSSHPP_HEADER_ONLY)
    install(TARGETS libsshpp
            EXPORT  libsshppTargets
            RUNTIME  DESTINATION ${CMAKE_INSTALL_BINDIR}
            LIBRARY  DESTINATION ${CMAKE_INSTALL_LIBDIR}
            ARCHIVE  DESTINATION ${CMAKE_INSTALL_LIBDIR})

    install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/sshpp
            DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/include/sshpp/config.hpp
                  ${CMAKE_CURRENT_BINARY_DIR}/include/sshpp/export.hpp
            DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/sshpp)

    install(EXPORT libsshppTargets
            NAMESPACE   libsshpp::
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libsshpp)

    include(CMakePackageConfigHelpers)
    configure_package_config_file(cmake/libsshppConfig.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/libsshppConfig.cmake
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libsshpp)
    write_basic_package_version_file(
        ${CMAKE_CURRENT_BINARY_DIR}/libsshppConfigVersion.cmake
        COMPATIBILITY SameMajorVersion)

    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libsshppConfig.cmake
                  ${CMAKE_CURRENT_BINARY_DIR}/libsshppConfigVersion.cmake
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/libsshpp)
endif()

if(LIBSSHPP_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if(LIBSSHPP_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
