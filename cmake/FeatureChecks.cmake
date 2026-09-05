# Feature detection against the resolved libssh::libssh target.
# Uses check_cxx_symbol_exists only -- no try_run -- to stay cross-compilation safe (B-5).

include(CheckCXXSymbolExists)
include(CMakePushCheckState)

cmake_push_check_state(RESET)
    get_target_property(_libssh_target libssh::libssh ALIASED_TARGET)
    if(NOT _libssh_target)
        set(_libssh_target libssh::libssh)
    endif()

    get_target_property(_libssh_includes ${_libssh_target} INTERFACE_INCLUDE_DIRECTORIES)
    if(_libssh_includes)
        set(CMAKE_REQUIRED_INCLUDES ${_libssh_includes})
    endif()
    set(CMAKE_REQUIRED_LIBRARIES ${_libssh_target})

    check_cxx_symbol_exists(sftp_aio_begin_read           "libssh/sftp.h"      SSHPP_HAS_SFTP_AIO)
    check_cxx_symbol_exists(ssh_channel_get_exit_state    "libssh/libssh.h"    SSHPP_HAS_CHANNEL_EXIT_STATE)
    check_cxx_symbol_exists(sftp_limits                   "libssh/sftp.h"      SSHPP_HAS_SFTP_LIMITS)
    check_cxx_symbol_exists(ssh_connector_new             "libssh/callbacks.h" SSHPP_HAS_CONNECTOR)
    check_cxx_symbol_exists(ssh_bind_new                  "libssh/server.h"    SSHPP_HAS_SERVER)
    check_cxx_symbol_exists(ssh_userauth_gssapi           "libssh/libssh.h"    SSHPP_HAS_GSSAPI)
cmake_pop_check_state()
