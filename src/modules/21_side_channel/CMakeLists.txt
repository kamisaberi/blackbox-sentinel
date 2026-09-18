add_library(sentinel_module_side_channel STATIC
    side_channel_module.cpp
    power_trace_eval.cpp
    em_noise_detector.cpp
)

target_include_directories(sentinel_module_side_channel PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    /usr/local/include
)

target_link_libraries(sentinel_module_side_channel PUBLIC
    blackbox::blackbox
    Threads::Threads
)