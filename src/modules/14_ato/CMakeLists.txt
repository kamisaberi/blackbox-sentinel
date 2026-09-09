add_library(sentinel_module_ato STATIC
    ato_module.cpp
    login_velocity.cpp
    geo_velocity_check.cpp
)

target_include_directories(sentinel_module_ato PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    /usr/local/include
)

target_link_libraries(sentinel_module_ato PUBLIC
    blackbox::blackbox
    Threads::Threads
)