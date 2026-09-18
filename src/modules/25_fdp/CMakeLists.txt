add_library(sentinel_module_fdp STATIC
    fdp_module.cpp
    transaction_graph.cpp
    synthetic_id_filter.cpp
)

target_include_directories(sentinel_module_fdp PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    /usr/local/include
)

target_link_libraries(sentinel_module_fdp PUBLIC
    blackbox::blackbox
    Threads::Threads
)