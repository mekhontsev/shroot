set(SHROOT_SQLITE bundled CACHE STRING "SQLite provider: bundled, system, or an existing CMake target")
if(SHROOT_SQLITE STREQUAL "bundled")
    include(FetchContent)
    FetchContent_Declare(shroot_sqlite
        URL https://www.sqlite.org/2026/sqlite-amalgamation-3510300.zip
        URL_HASH SHA256=acb1e6f5d832484bf6d32b681e858c38add8b2acdfd42ac5df24b8afb46552b4
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
    FetchContent_MakeAvailable(shroot_sqlite)
    add_library(shroot-sqlite STATIC ${shroot_sqlite_SOURCE_DIR}/sqlite3.c)
    target_include_directories(shroot-sqlite PUBLIC ${shroot_sqlite_SOURCE_DIR})
    # Independent connections need global SQLite protection, not a mutex per query.
    target_compile_definitions(shroot-sqlite PRIVATE SQLITE_ENABLE_PREUPDATE_HOOK
        SQLITE_THREADSAFE=2 SQLITE_OMIT_LOAD_EXTENSION SQLITE_DQS=0
        SQLITE_DEFAULT_MEMSTATUS=0 SQLITE_OMIT_DEPRECATED)
    target_compile_options(shroot-sqlite PRIVATE -O2 ${shroot_archive_code})
    set(shroot_sqlite_target shroot-sqlite)
elseif(SHROOT_SQLITE STREQUAL "system")
    find_package(SQLite3 3.37 REQUIRED)
    set(shroot_sqlite_target SQLite::SQLite3)
elseif(TARGET "${SHROOT_SQLITE}")
    set(shroot_sqlite_target "${SHROOT_SQLITE}")
else()
    message(FATAL_ERROR "SHROOT_SQLITE must be bundled, system, or an existing CMake target: ${SHROOT_SQLITE}")
endif()
get_target_property(sqlite_type ${shroot_sqlite_target} TYPE)
if(SHROOT_STATIC_RUNTIME AND sqlite_type STREQUAL "SHARED_LIBRARY")
    message(FATAL_ERROR "Shared SQLite requires SHROOT_STATIC_RUNTIME=OFF")
endif()

# Only this adapter belongs to Shroot. Never modify an integrator's SQLite target.
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)
add_library(guest-database STATIC ${CMAKE_CURRENT_LIST_DIR}/../src/storage_database.c)
target_link_libraries(guest-database PUBLIC ${shroot_sqlite_target} Threads::Threads)
target_compile_definitions(guest-database PUBLIC SQLITE_ENABLE_PREUPDATE_HOOK)
target_compile_options(guest-database PRIVATE -std=c17 -O2 -Wall -Wextra -Werror ${shroot_archive_code})
