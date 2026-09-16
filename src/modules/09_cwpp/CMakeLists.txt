add_library(sentinel_module_cwpp STATIC
    cwpp_module.cpp
    syscall_evaluator.cpp
    container_watcher.cpp
)

target_include_directories(sentinel_module_cwpp PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    /usr/local/include
)

target_link_libraries(sentinel_module_cwpp PUBLIC
    blackbox::blackbox
    Threads::Threads
)