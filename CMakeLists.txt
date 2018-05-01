cmake_minimum_required(VERSION 3.5)

project(tcpcontrack) # TCT

set (TCT_VERSION_MAJOR 0)
set (TCT_VERSION_MINOR 1)
set (TCT_VERSION_BUILD 0)

set (TCT_SOURCE_DIR ${CMAKE_SOURCE_DIR})

set (TCT_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/src/tct.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/main.c)

set (TCT_HEADERS
        ${CMAKE_CURRENT_SOURCE_DIR}/src/tct.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/tct_logger.h
        ${CMAKE_CURRENT_SOURCE_DIR}/src/uthash.h)

set (TCT_INCLUDE_DIRECTORIES
        ${CMAKE_BINARY_DIR}/substitutes)


configure_file (${TCT_SOURCE_DIR}/substitutes/version_no.h.in ${CMAKE_BINARY_DIR}/substitutes/tct_version_no.h )
include_directories (${TCT_INCLUDE_DIRECTORIES})
add_executable (tct ${TCT_SOURCES} ${TCT_HEADERS})
target_link_libraries (tct pcap)
