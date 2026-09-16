add_library(sentinel_module_nac STATIC
    nac_module.cpp
    device_fingerprinter.cpp
    vlan_isolator.cpp
)

target_include_directories(sentinel_module_nac PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    /usr/local/include
)

target_link_libraries(sentinel_module_nac PUBLIC
    blackbox::blackbox
    Threads::Threads
)