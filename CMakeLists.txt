cmake_minimum_required (VERSION 3.5)
project(dns_proxy)

include_directories(${CMAKE_CURRENT_BINARY_DIR})
# cjson

set(cJSON_ROOTDIR "dependencies/cJSON")
include_directories(${cJSON_ROOTDIR})

set(ABSOLUTE_cJSON_ROOTDIR "${CMAKE_CURRENT_SOURCE_DIR}/${cJSON_ROOTDIR}")
if(NOT EXISTS "${ABSOLUTE_cJSON_ROOTDIR}/CMakeLists.txt")
    message(FATAL_ERROR "${ABSOLUTE_cJSON_ROOTDIR}/CMakeLists.txt missing. try to download with \"git submodule update --init --recursive\" and try again.")
endif()

option(BUILD_SHARED_LIBS "Build shared libraries" OFF)
option(ENABLE_CJSON_TEST "Enable building cJSON test" OFF)
option(ENABLE_CJSON_UTILS "Enable building the cJSON_Utils library." ON)
add_subdirectory("${cJSON_ROOTDIR}")

# includes
include_directories("include")
# sources
file(GLOB_RECURSE SOURCES RELATIVE ${CMAKE_SOURCE_DIR} "src/*")
add_executable(dns_proxy ${SOURCES})
target_link_libraries(dns_proxy PRIVATE cjson cjson_utils)
add_executable(test_dump "./test/dump.c")
