add_library(sentinel_module_ids_ips STATIC
    ids_ips_module.cpp
    signature_matcher.cpp
    xdp_packet_dropper.cpp
)

target_include_directories(sentinel_module_ids_ips PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    /usr/local/include
)

target_link_libraries(sentinel_module_ids_ips PUBLIC
    blackbox::blackbox
    Threads::Threads
)