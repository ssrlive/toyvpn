cmake_minimum_required(VERSION 3.0)
project(ToyVpnServer C)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

set(CMAKE_C_STANDARD 90)

if(NOT CMAKE_SYSTEM_NAME MATCHES "Android|Linux")
    message(FATAL_ERROR "FATAL. Support linux only recently.")
endif()

set(LIBUV_BUILD_TESTS OFF)
set(LIBUV_BUILD_BENCH OFF)
add_subdirectory(libuv)

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_definitions(-Wall -Werror -ggdb3 -std=c99 -Wextra -pedantic -D__FUNCTION__=__func__)
endif()

add_subdirectory(cstl)

add_executable(ToyVpnServer
  ToyVpnServer2.c
  sockaddr_universal.c
  sockaddr_universal.h
  ref_count_def.h
  )

target_link_libraries(ToyVpnServer uv_a cstl)
target_include_directories(ToyVpnServer PRIVATE libuv/include ${CSTL_ROOT_DIR}/inc)
if(ANDROID)
    set_target_properties(ToyVpnServer PROPERTIES PREFIX "lib" SUFFIX ".so")
endif()
