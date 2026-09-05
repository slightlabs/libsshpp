add_executable(01_exec 01_exec.cpp)
target_link_libraries(01_exec PRIVATE libsshpp::libsshpp)

if(LIBSSHPP_WITH_SFTP)
    add_executable(03_sftp_download 03_sftp_download.cpp)
    target_link_libraries(03_sftp_download PRIVATE libsshpp::libsshpp)
endif()
