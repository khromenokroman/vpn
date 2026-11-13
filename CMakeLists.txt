cmake_minimum_required(VERSION 3.25.1)
project(poma-vpn
        VERSION 0.4.0.0
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
        src/share/signal_fd.cpp
        src/share/stop_event.cpp
        src/share/command.cpp
        src/share/net.cpp
        src/share/packet.cpp
        src/share/routing.cpp
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

# упаковка: два deb-пакета, сервер и клиент ставятся независимо
install(TARGETS vpn-server RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT server)
install(TARGETS vpn-client RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT client)

foreach (role server client)
    set(VPN_PACKAGE poma-vpn-${role})
    set(VPN_UNIT ${VPN_PACKAGE}.service)
    if (role STREQUAL "server")
        set(VPN_GENERATE_KEY yes)
    else ()
        set(VPN_GENERATE_KEY no)
    endif ()
    set(out ${CMAKE_CURRENT_BINARY_DIR}/debian/${role})
    configure_file(debian/${VPN_PACKAGE}.service.in ${out}/${VPN_UNIT} @ONLY)
    configure_file(debian/conffiles.in ${out}/conffiles @ONLY)
    foreach (script postinst prerm postrm)
        configure_file(debian/${script}.in ${out}/${script} @ONLY
                FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
    endforeach ()
    install(FILES ${out}/${VPN_UNIT} DESTINATION lib/systemd/system COMPONENT ${role})
    install(FILES debian/copyright DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/doc/${VPN_PACKAGE} COMPONENT ${role})
    install(FILES debian/default-${role} DESTINATION ${CMAKE_INSTALL_FULL_SYSCONFDIR}/default RENAME ${VPN_PACKAGE} COMPONENT ${role})
    string(TOUPPER ${role} ROLE)
    set(CPACK_DEBIAN_${ROLE}_PACKAGE_NAME ${VPN_PACKAGE})
    set(CPACK_DEBIAN_${ROLE}_PACKAGE_CONTROL_EXTRA ${out}/conffiles ${out}/postinst ${out}/prerm ${out}/postrm)
endforeach ()

set(CPACK_PACKAGE_NAME "poma-vpn")
set(CPACK_PACKAGE_VENDOR "khromenokroman")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_CONTACT "khromenokroman <roma55592@yandex.ru>")
set(CPACK_PACKAGE_HOMEPAGE_URL "${PROJECT_HOMEPAGE_URL}")

set(CPACK_GENERATOR "DEB")
set(CPACK_DEB_COMPONENT_INSTALL ON)
set(CPACK_COMPONENTS_ALL server client)
set(CPACK_STRIP_FILES ON)
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "${CPACK_PACKAGE_CONTACT}")
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_SECTION "net")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_DEBIAN_SERVER_PACKAGE_DEPENDS "init-system-helpers, iproute2, iptables")
set(CPACK_DEBIAN_CLIENT_PACKAGE_DEPENDS "init-system-helpers, iproute2")
set(CPACK_COMPONENT_SERVER_DESCRIPTION "Personal VPN server: TUN over UDP with XChaCha20-Poly1305\nCreates a TUN interface, decrypts client packets and forwards them\nto the Internet through NAT (iptables MASQUERADE).")
set(CPACK_COMPONENT_CLIENT_DESCRIPTION "Personal VPN client: TUN over UDP with XChaCha20-Poly1305\nCreates a TUN interface and routes all traffic through the VPN server.")
set(CPACK_DEBIAN_PACKAGE_CONTROL_STRICT_PERMISSION ON)
set(CPACK_INSTALL_DEFAULT_DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

include(CPack)

if (BUILD_TESTS)
    enable_testing()
    find_package(GTest REQUIRED)

    add_executable(vpn_tests
            tests/test_crypto.cpp
            tests/test_key_file.cpp
            tests/test_net.cpp
            tests/test_stop_event.cpp
    )
    target_link_libraries(vpn_tests PRIVATE vpn_share GTest::gtest_main GTest::gmock)
    add_test(NAME vpn_tests COMMAND vpn_tests)
endif ()
