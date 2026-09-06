add_library(sentinel_module_iot_sec STATIC
    iot_module.cpp
    dicom_pacs_guard.cpp
    hl7_telemetry_audit.cpp
)

target_include_directories(sentinel_module_iot_sec PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    /usr/local/include
)

target_link_libraries(sentinel_module_iot_sec PUBLIC
    blackbox::blackbox
    Threads::Threads
)