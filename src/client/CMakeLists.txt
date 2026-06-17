set(APP_NAME vpn-client)

add_executable(${APP_NAME} client.cpp)
target_include_directories(${APP_NAME}
        PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${Boost_INCLUDE_DIRS}
)
target_link_libraries(${APP_NAME}
        PRIVATE
        Boost::system
        fmt::fmt
)
