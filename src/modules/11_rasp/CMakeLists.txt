add_library(sentinel_module_rasp STATIC
    rasp_module.cpp
    memory_hook_guard.cpp
    sql_interceptor.cpp
)

target_include_directories(sentinel_module_rasp PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    /usr/local/include
)

target_link_libraries(sentinel_module_rasp PUBLIC
    blackbox::blackbox
    Threads::Threads
)