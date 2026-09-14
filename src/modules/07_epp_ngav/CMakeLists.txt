add_library(sentinel_module_epp_ngav STATIC
    epp_module.cpp
    file_entropy_calc.cpp
    binary_pe_parser.cpp
)

target_include_directories(sentinel_module_epp_ngav PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    /usr/local/include
)

target_link_libraries(sentinel_module_epp_ngav PUBLIC
    blackbox::blackbox
    Threads::Threads
)