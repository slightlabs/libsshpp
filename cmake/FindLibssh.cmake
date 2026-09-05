# Locates libssh and normalizes the imported target to libssh::libssh.
#
# Distro packages of libssh (e.g. Debian/Ubuntu libssh-dev) export a CONFIG
# package whose imported target is plain `ssh`, not namespaced. Conan/vcpkg
# packages typically export `libssh::libssh` directly. This module accepts
# either and always leaves libssh::libssh defined.

find_package(libssh CONFIG QUIET)

if(TARGET libssh::libssh)
    set(Libssh_FOUND TRUE)
elseif(TARGET ssh)
    add_library(libssh::libssh ALIAS ssh)
    set(Libssh_FOUND TRUE)
else()
    find_path(LIBSSH_INCLUDE_DIR NAMES libssh/libssh.h)
    find_library(LIBSSH_LIBRARY NAMES ssh)
    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(Libssh
        REQUIRED_VARS LIBSSH_LIBRARY LIBSSH_INCLUDE_DIR)
    if(Libssh_FOUND AND NOT TARGET libssh::libssh)
        add_library(libssh::libssh UNKNOWN IMPORTED)
        set_target_properties(libssh::libssh PROPERTIES
            IMPORTED_LOCATION "${LIBSSH_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${LIBSSH_INCLUDE_DIR}")
    endif()
    mark_as_advanced(LIBSSH_INCLUDE_DIR LIBSSH_LIBRARY)
endif()

if(NOT Libssh_FOUND AND Libssh_FIND_REQUIRED)
    message(FATAL_ERROR "libssh not found (looked for CONFIG package and system install)")
endif()
