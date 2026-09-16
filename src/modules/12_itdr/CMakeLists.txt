add_library(sentinel_module_itdr STATIC
    itdr_module.cpp
    kerberos_watcher.cpp
    ad_privilege_audit.cpp
)

target_include_directories(sentinel_module_itdr PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    /usr/local/include
)

target_link_libraries(sentinel_module_itdr PUBLIC
    blackbox::blackbox
    Threads::Threads
)