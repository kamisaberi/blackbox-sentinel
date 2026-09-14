add_library(sentinel_module_waf STATIC
    waf_module.cpp
    http_payload_eval.cpp
    api_logic_inspector.cpp
)

target_include_directories(sentinel_module_waf PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    /usr/local/include
)

target_link_libraries(sentinel_module_waf PUBLIC
    blackbox::blackbox
    Threads::Threads
)