cmake_minimum_required(VERSION 4.2)
project(vpn)

set(CMAKE_CXX_STANDARD 17)
#set(CMAKE_CXX_STANDARD 20)
#set(CMAKE_CXX_STANDARD_REQUIRED ON)
#set(CMAKE_CXX_EXTENSIONS OFF)

find_package(fmt REQUIRED)

add_subdirectory(src/server)
add_subdirectory(src/client)
