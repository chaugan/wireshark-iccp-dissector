# CMakeLists.txt
#
# Wireshark ICCP / TASE.2 dissector plugin
# IEC 60870-6 Inter-Control Center Communications Protocol
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Out-of-tree build. Requires an installed (or locally built) Wireshark whose
# CMake config package is discoverable, e.g. via:
#
#   cmake -G "Visual Studio 17 2022" -A x64 \
#         -DCMAKE_PREFIX_PATH=C:/Development/wsbuild64 ..
#
# After build, `cmake --build . --target copy_plugin` installs the DLL into
# the plugin directory reported by Wireshark's CMake config package.

cmake_minimum_required(VERSION 3.16)

project(iccp
    VERSION 0.0.1
    DESCRIPTION "Wireshark ICCP / TASE.2 (IEC 60870-6) dissector plugin"
    LANGUAGES C
)

find_package(Wireshark CONFIG REQUIRED)

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "${Wireshark_INSTALL_PREFIX}"
        CACHE PATH "Installation prefix" FORCE
    )
endif()

if(NOT Wireshark_PLUGINS_ENABLED)
    message(WARNING "Wireshark was compiled without support for plugins")
endif()

include(CheckTypeSize)
check_type_size("ssize_t" SSIZE_T)

set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_C_STANDARD 11)

if(CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_C_FLAGS "-Wall -Wextra ${CMAKE_C_FLAGS}")
endif()

add_compile_definitions(
    VERSION=\"${PROJECT_VERSION}\"
    $<$<BOOL:${HAVE_SSIZE_T}>:HAVE_SSIZE_T>
)

set(DISSECTOR_SRC
    plugin.c
    packet-iccp.c
)

add_library(iccp MODULE ${DISSECTOR_SRC})
set_target_properties(iccp PROPERTIES PREFIX "" DEFINE_SYMBOL "")
target_link_libraries(iccp epan)

install(TARGETS iccp
    LIBRARY DESTINATION "${Wireshark_PLUGIN_LIBDIR}/epan" NAMELINK_SKIP
)

add_custom_target(copy_plugin
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:iccp> "${Wireshark_PLUGIN_INSTALL_DIR}/epan"
    COMMENT "Installing plugin to: ${Wireshark_PLUGIN_INSTALL_DIR}/epan"
)

string(TOLOWER "${PROJECT_NAME}-${PROJECT_VERSION}" _pkgname)

add_custom_target(package_prep
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/${_pkgname}
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:iccp> ${CMAKE_BINARY_DIR}/${_pkgname}
)

add_custom_target(package
    COMMAND ${CMAKE_COMMAND} -E tar czf ${CMAKE_BINARY_DIR}/${_pkgname}.tar.gz --format=gnutar -- ${CMAKE_BINARY_DIR}/${_pkgname}
)
add_dependencies(package package_prep)

add_custom_target(package_zip
    COMMAND ${CMAKE_COMMAND} -E tar cf ${CMAKE_BINARY_DIR}/${_pkgname}.zip --format=zip -- ${CMAKE_BINARY_DIR}/${_pkgname}
)
add_dependencies(package_zip package_prep)
