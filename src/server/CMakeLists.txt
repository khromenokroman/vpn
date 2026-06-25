set(APP_NAME vpn-server)

add_executable(${APP_NAME}
        server.hpp
        server.cpp
        ../share/device.cpp
        ../share/os.cpp
        ../share/crypto.cpp
)
target_include_directories(${APP_NAME}
        PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${Boost_INCLUDE_DIRS}
)
target_link_libraries(${APP_NAME}
        PRIVATE
        fmt::fmt
        Boost::program_options
        ${SODIUM_LIBRARY}
        pthread
)