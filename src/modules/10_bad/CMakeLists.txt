add_library(sentinel_module_bad STATIC
    bad_module.cpp
    mouse_keystroke_nn.cpp
    tcp_fingerprinter.cpp
)

target_include_directories(sentinel_module_bad PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    /usr/local/include
)

target_link_libraries(sentinel_module_bad PUBLIC
    blackbox::blackbox
    Threads::Threads
)