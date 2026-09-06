add_library(sentinel_module_cdr STATIC
    cdr_module.cpp
    pdf_sanitizer.cpp
    docx_sanitizer.cpp
)

target_include_directories(sentinel_module_cdr PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    /usr/local/include
)

target_link_libraries(sentinel_module_cdr PUBLIC
    blackbox::blackbox
    Threads::Threads
)