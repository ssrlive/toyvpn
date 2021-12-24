cmake_minimum_required(VERSION 3.0)
project(ToyVpnServer C)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

set(CMAKE_C_STANDARD 90)

add_executable(ToyVpnServer ToyVpnServer.c)
if(ANDROID)
    set_target_properties(ToyVpnServer PROPERTIES PREFIX "lib" SUFFIX ".so")
endif()
