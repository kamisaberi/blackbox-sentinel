add_library(sentinel_module_ddos STATIC
    ddos_module.cpp
    syn_flood_guard.cpp
    udp_rate_limiter.cpp
)

target_include_directories(sentinel_module_ddos PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    /usr/local/include
)

target_link_libraries(sentinel_module_ddos PUBLIC
    blackbox::blackbox
    Threads::Threads
)