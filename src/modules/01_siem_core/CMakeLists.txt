add_library(sentinel_module_siem_core STATIC
    siem_module.cpp
    log_correlator.cpp
    time_series_engine.cpp
)

target_include_directories(sentinel_module_siem_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    /usr/local/include
)

target_link_libraries(sentinel_module_siem_core PUBLIC
    blackbox::blackbox
    Threads::Threads
)