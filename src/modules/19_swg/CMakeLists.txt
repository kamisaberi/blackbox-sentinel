add_library(sentinel_module_swg STATIC
    swg_module.cpp
    url_classifier.cpp
    outbound_proxy.cpp
)

target_include_directories(sentinel_module_swg PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    /usr/local/include
)

target_link_libraries(sentinel_module_swg PUBLIC
    blackbox::blackbox
    Threads::Threads
)