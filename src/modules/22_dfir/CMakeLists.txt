find_package(OpenSSL REQUIRED)

add_library(sentinel_module_dfir STATIC
    dfir_module.cpp
    pcap_ring_buffer.cpp
    evidence_signer.cpp
)

target_include_directories(sentinel_module_dfir PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    /usr/local/include
)

target_link_libraries(sentinel_module_dfir PUBLIC
    blackbox::blackbox
    Threads::Threads
    OpenSSL::Crypto
)