add_library(sentinel_module_ai_trism STATIC
    ai_trism_module.cpp
    prompt_sanitizer.cpp
    data_leak_guard.cpp
)

target_include_directories(sentinel_module_ai_trism PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    /usr/local/include
)

target_link_libraries(sentinel_module_ai_trism PUBLIC
    blackbox::blackbox
    Threads::Threads
)