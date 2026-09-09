add_library(sentinel_module_ngfw STATIC
    ngfw_module.cpp
    dpi_engine.cpp
    stateful_firewall.cpp
)

target_include_directories(sentinel_module_ngfw PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    /usr/local/include
)

target_link_libraries(sentinel_module_ngfw PUBLIC
    blackbox::blackbox
    Threads::Threads
)