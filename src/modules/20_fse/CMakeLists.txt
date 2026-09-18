add_library(sentinel_module_fse STATIC
    fse_module.cpp
    uefi_image_parser.cpp
    backdoor_scanner.cpp
)

target_include_directories(sentinel_module_fse PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    /usr/local/include
)

target_link_libraries(sentinel_module_fse PUBLIC
    blackbox::blackbox
    Threads::Threads
)