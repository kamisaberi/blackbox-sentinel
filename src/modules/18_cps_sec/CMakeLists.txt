add_library(sentinel_module_cps_sec STATIC
    cps_module.cpp
    modbus_parser.cpp
    dnp3_parser.cpp
    physics_validator.cpp
)

target_include_directories(sentinel_module_cps_sec PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    /usr/local/include
)

target_link_libraries(sentinel_module_cps_sec PUBLIC
    blackbox::blackbox
    Threads::Threads
)