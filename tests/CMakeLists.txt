find_package(Catch2 3 REQUIRED)
include(Catch)

add_executable(sshpp_unit_tests
    unit/error_test.cpp
    unit/result_test.cpp
    unit/session_options_test.cpp
    unit/exec_test.cpp
    unit/key_test.cpp)
if(LIBSSHPP_WITH_SFTP)
    target_sources(sshpp_unit_tests PRIVATE unit/sftp_attributes_test.cpp)
endif()
target_link_libraries(sshpp_unit_tests PRIVATE libsshpp::libsshpp Catch2::Catch2WithMain)
catch_discover_tests(sshpp_unit_tests)

if(LIBSSHPP_SYSTEM_TESTS)
    add_executable(sshpp_integration_test integration/exec_integration_test.cpp)
    if(LIBSSHPP_WITH_SFTP)
        target_sources(sshpp_integration_test PRIVATE integration/sftp_integration_test.cpp)
    endif()
    if(LIBSSHPP_WITH_SCP)
        target_sources(sshpp_integration_test PRIVATE integration/scp_integration_test.cpp)
    endif()
    if(LIBSSHPP_WITH_FORWARDING)
        target_sources(sshpp_integration_test PRIVATE integration/forwarding_integration_test.cpp)
    endif()
    if(LIBSSHPP_WITH_SERVER)
        target_sources(sshpp_integration_test PRIVATE integration/server_integration_test.cpp
                                                       integration/server_callback_integration_test.cpp)
    endif()
    target_link_libraries(sshpp_integration_test PRIVATE libsshpp::libsshpp Catch2::Catch2WithMain)

    find_program(BASH_EXECUTABLE bash REQUIRED)
    add_test(NAME sshpp_integration
             COMMAND ${BASH_EXECUTABLE}
                     ${CMAKE_CURRENT_SOURCE_DIR}/integration/run_with_sshd.sh
                     $<TARGET_FILE:sshpp_integration_test>)
endif()
