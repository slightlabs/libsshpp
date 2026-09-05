function(libsshpp_set_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 $<$<BOOL:${LIBSSHPP_WARNINGS_AS_ERRORS}>:/WX>)
    else()
        target_compile_options(${target} PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow
            $<$<BOOL:${LIBSSHPP_WARNINGS_AS_ERRORS}>:-Werror>)
    endif()
endfunction()
