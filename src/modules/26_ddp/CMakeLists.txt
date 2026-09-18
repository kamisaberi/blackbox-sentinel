add_library(sentinel_module_ddp STATIC
    ddp_module.cpp
    decoy_plc_trap.cpp
    decoy_ssh_trap.cpp
    honey_token_monitor.cpp
)

target_include_directories(sentinel_module_ddp PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    /usr/local/include
)

target_link_libraries(sentinel_module_ddp PUBLIC
    blackbox::blackbox
    Threads::Threads
)