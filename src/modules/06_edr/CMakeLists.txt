add_library(sentinel_module_edr STATIC
    edr_module.cpp
    process_tracker.cpp
    memory_scanner.cpp
)

target_include_directories(sentinel_module_edr PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    /usr/local/include
)

target_link_libraries(sentinel_module_edr PUBLIC
    blackbox::blackbox
    Threads::Threads
)