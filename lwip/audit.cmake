execute_process(COMMAND "${NM}" --defined-only --format=sysv "${ARCHIVE}"
    RESULT_VARIABLE result OUTPUT_VARIABLE symbols ERROR_VARIABLE error)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "lwIP state audit: ${error}")
endif()
string(REPLACE "\n" ";" lines "${symbols}")
foreach(line IN LISTS lines)
    if(line MATCHES "^([^|]+)\\|[^|]*\\|[ \t]*([BbCcDdGgSsVv])[ \t]*\\|([^|]*)\\|([^|]*)\\|[^|]*\\|(.+)$")
        string(STRIP "${CMAKE_MATCH_1}" name)
        string(STRIP "${CMAKE_MATCH_3}" kind)
        string(STRIP "${CMAKE_MATCH_4}" size)
        string(STRIP "${CMAKE_MATCH_5}" section)
        if(name STREQUAL "md_lwip_current" AND kind STREQUAL "TLS")
            continue()
        endif()
        # GCC section anchors name existing TLS storage; they allocate no state.
        if(name MATCHES "^\\.LANCHOR[0-9]+$" AND kind STREQUAL "TLS"
                AND size MATCHES "^0*$" AND section MATCHES "^\\.t(bss|data)(\\.|$)")
            continue()
        endif()
        # PIE const pointers need loader relocations, then GNU_RELRO protects
        # them. Runtime consumers explicitly link with -z relro -z now.
        if(section MATCHES "^\\.(data\\.rel\\.ro|rodata)(\\.|$)")
            continue()
        endif()
        message(FATAL_ERROR "lwIP has shared mutable state: ${line}")
    endif()
endforeach()
