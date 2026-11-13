cmake_minimum_required(VERSION 3.25.1)
project(poma-vpn
        VERSION 0.1.0.0
        LANGUAGES CXX
        HOMEPAGE_URL "https://github.com/khromenokroman/vpn")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(BUILD_TESTS "Собирать тесты" ON)

find_package(fmt REQUIRED)
find_package(Boost REQUIRED CONFIG COMPONENTS program_options)
find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)

include(GNUInstallDirs)

# общий код сервера и клиента
add_library(vpn_share STATIC
        src/share/crypto.cpp
        src/share/device.cpp
        src/share/key_file.cpp
        src/share/os.cpp
)
target_include_directories(vpn_share PUBLIC src)
target_compile_options(vpn_share PUBLIC -Wall -Wextra)
target_compile_definitions(vpn_share PUBLIC POMA_VPN_VERSION="${PROJECT_VERSION}")
target_link_libraries(vpn_share PUBLIC fmt::fmt PkgConfig::SODIUM Threads::Threads)

add_executable(vpn-server
        src/server/server.cpp
)
target_link_libraries(vpn-server PRIVATE vpn_share Boost::program_options)

add_executable(vpn-client
        src/client/client.cpp
)
target_link_libraries(vpn-client PRIVATE vpn_share Boost::program_options)

if (BUILD_TESTS)
    enable_testing()
    find_package(GTest REQUIRED)

    add_executable(vpn_tests
            tests/test_crypto.cpp
            tests/test_key_file.cpp
    )
    target_link_libraries(vpn_tests PRIVATE vpn_share GTest::gtest_main GTest::gmock)
    add_test(NAME vpn_tests COMMAND vpn_tests)
endif ()
