cmake_minimum_required(VERSION 4.2)
project(vpn)

set(CMAKE_CXX_STANDARD 17)
#set(CMAKE_CXX_STANDARD 20)
#set(CMAKE_CXX_STANDARD_REQUIRED ON)
#set(CMAKE_CXX_EXTENSIONS OFF)

find_package(fmt REQUIRED)
find_package(Boost REQUIRED COMPONENTS program_options)
find_library(SODIUM_LIBRARY sodium REQUIRED)

add_subdirectory(src/server)
add_subdirectory(src/client)
