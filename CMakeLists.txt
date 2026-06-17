cmake_minimum_required(VERSION 4.2)
project(vpn)

set(CMAKE_CXX_STANDARD 17)

add_subdirectory(src/server)
add_subdirectory(src/client)
