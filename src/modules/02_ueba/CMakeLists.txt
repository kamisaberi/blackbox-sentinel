add_library(sentinel_module_ueba STATIC
    ueba_module.cpp
    behavior_matrix.cpp
    baseline_scorer.cpp
)

target_include_directories(sentinel_module_ueba PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    /usr/local/include
)

target_link_libraries(sentinel_module_ueba PUBLIC
    blackbox::blackbox
    Threads::Threads
)