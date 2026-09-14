add_library(sentinel_module_ndr STATIC
    ndr_module.cpp
    flow_analyzer.cpp
    eta_fingerprinter.cpp
)

target_include_directories(sentinel_module_ndr PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    /usr/local/include
)

target_link_libraries(sentinel_module_ndr PUBLIC
    blackbox::blackbox
    Threads::Threads
)