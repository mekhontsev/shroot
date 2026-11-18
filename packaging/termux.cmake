# cmake -S . -B build/termux -C packaging/termux.cmake
# TERMUX_PREFIX is the target prefix in a package build; PREFIX is set on-device.
set(prefix "$ENV{TERMUX_PREFIX}")
if(prefix STREQUAL "")
    set(prefix "$ENV{PREFIX}")
endif()
if(NOT IS_ABSOLUTE "${prefix}" OR prefix STREQUAL "/")
    message(FATAL_ERROR "Set TERMUX_PREFIX to the target Termux installation prefix")
endif()
set(CMAKE_INSTALL_PREFIX "${prefix}" CACHE PATH "Termux installation prefix")
set(SHROOT_DEFAULT_LIBRARY "${prefix}/var/lib/shroot" CACHE STRING "Termux CLI library")
set(CPACK_GENERATOR DEB CACHE STRING "Termux package format")
set(SHROOT_TERMUX_PACKAGE ON CACHE INTERNAL "Building the Termux distribution")
set(CPACK_INSTALL_DEFAULT_DIRECTORY_PERMISSIONS
    OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
    CACHE STRING "Package directory permissions independent of the build user's umask")
set(CPACK_DEBIAN_PACKAGE_SECTION utils CACHE STRING "Termux package section")
set(CPACK_PACKAGING_INSTALL_PREFIX "${prefix}" CACHE STRING "Target path inside the package")
set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE aarch64 CACHE STRING "Termux package architecture")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Shroot contributors" CACHE STRING "Package maintainer")
set(CPACK_DEBIAN_PACKAGE_DESCRIPTION "Native ARM64 Linux environment manager and runtime" CACHE STRING "Package description")
