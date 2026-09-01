# Install script for directory: /home/kami/blackbox-sentinel

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set path to fallback-tool for dependency-resolution.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/usr/bin/objdump")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/bin/sentinel")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/bin" TYPE EXECUTABLE FILES "/home/kami/blackbox-sentinel/build/sentinel")
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/sentinel" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/sentinel")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}/usr/local/bin/sentinel")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  include("/home/kami/blackbox-sentinel/build/CMakeFiles/sentinel.dir/install-cxx-module-bmi-noconfig.cmake" OPTIONAL)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_scada_modbus.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_scada_modbus.so")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_scada_modbus.so"
         RPATH "/usr/local/lib")
  endif()
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/bin/libsentinel_plugin_scada_modbus.so")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/bin" TYPE SHARED_LIBRARY FILES "/home/kami/blackbox-sentinel/build/libsentinel_plugin_scada_modbus.so")
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_scada_modbus.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_scada_modbus.so")
    file(RPATH_CHANGE
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_scada_modbus.so"
         OLD_RPATH "/usr/local/lib:"
         NEW_RPATH "/usr/local/lib")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_scada_modbus.so")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  include("/home/kami/blackbox-sentinel/build/CMakeFiles/sentinel_plugin_scada_modbus.dir/install-cxx-module-bmi-noconfig.cmake" OPTIONAL)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_active_deception.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_active_deception.so")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_active_deception.so"
         RPATH "/usr/local/lib")
  endif()
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/bin/libsentinel_plugin_active_deception.so")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/bin" TYPE SHARED_LIBRARY FILES "/home/kami/blackbox-sentinel/build/libsentinel_plugin_active_deception.so")
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_active_deception.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_active_deception.so")
    file(RPATH_CHANGE
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_active_deception.so"
         OLD_RPATH "/usr/local/lib:"
         NEW_RPATH "/usr/local/lib")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_active_deception.so")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  include("/home/kami/blackbox-sentinel/build/CMakeFiles/sentinel_plugin_active_deception.dir/install-cxx-module-bmi-noconfig.cmake" OPTIONAL)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_pcap_carver.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_pcap_carver.so")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_pcap_carver.so"
         RPATH "/usr/local/lib")
  endif()
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/bin/libsentinel_plugin_pcap_carver.so")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/bin" TYPE SHARED_LIBRARY FILES "/home/kami/blackbox-sentinel/build/libsentinel_plugin_pcap_carver.so")
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_pcap_carver.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_pcap_carver.so")
    file(RPATH_CHANGE
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_pcap_carver.so"
         OLD_RPATH "/usr/local/lib:"
         NEW_RPATH "/usr/local/lib")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_pcap_carver.so")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  include("/home/kami/blackbox-sentinel/build/CMakeFiles/sentinel_plugin_pcap_carver.dir/install-cxx-module-bmi-noconfig.cmake" OPTIONAL)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_dnp3_grid.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_dnp3_grid.so")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_dnp3_grid.so"
         RPATH "/usr/local/lib")
  endif()
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/bin/libsentinel_plugin_dnp3_grid.so")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/bin" TYPE SHARED_LIBRARY FILES "/home/kami/blackbox-sentinel/build/libsentinel_plugin_dnp3_grid.so")
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_dnp3_grid.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_dnp3_grid.so")
    file(RPATH_CHANGE
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_dnp3_grid.so"
         OLD_RPATH "/usr/local/lib:"
         NEW_RPATH "/usr/local/lib")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_dnp3_grid.so")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  include("/home/kami/blackbox-sentinel/build/CMakeFiles/sentinel_plugin_dnp3_grid.dir/install-cxx-module-bmi-noconfig.cmake" OPTIONAL)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_profinet.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_profinet.so")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_profinet.so"
         RPATH "/usr/local/lib")
  endif()
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/bin/libsentinel_plugin_profinet.so")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/bin" TYPE SHARED_LIBRARY FILES "/home/kami/blackbox-sentinel/build/libsentinel_plugin_profinet.so")
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_profinet.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_profinet.so")
    file(RPATH_CHANGE
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_profinet.so"
         OLD_RPATH "/usr/local/lib:"
         NEW_RPATH "/usr/local/lib")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_profinet.so")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  include("/home/kami/blackbox-sentinel/build/CMakeFiles/sentinel_plugin_profinet.dir/install-cxx-module-bmi-noconfig.cmake" OPTIONAL)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_s7comm.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_s7comm.so")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_s7comm.so"
         RPATH "/usr/local/lib")
  endif()
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/bin/libsentinel_plugin_s7comm.so")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/bin" TYPE SHARED_LIBRARY FILES "/home/kami/blackbox-sentinel/build/libsentinel_plugin_s7comm.so")
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_s7comm.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_s7comm.so")
    file(RPATH_CHANGE
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_s7comm.so"
         OLD_RPATH "/usr/local/lib:"
         NEW_RPATH "/usr/local/lib")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_s7comm.so")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  include("/home/kami/blackbox-sentinel/build/CMakeFiles/sentinel_plugin_s7comm.dir/install-cxx-module-bmi-noconfig.cmake" OPTIONAL)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_cef_forwarder.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_cef_forwarder.so")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_cef_forwarder.so"
         RPATH "/usr/local/lib")
  endif()
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/bin/libsentinel_plugin_cef_forwarder.so")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/bin" TYPE SHARED_LIBRARY FILES "/home/kami/blackbox-sentinel/build/libsentinel_plugin_cef_forwarder.so")
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_cef_forwarder.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_cef_forwarder.so")
    file(RPATH_CHANGE
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_cef_forwarder.so"
         OLD_RPATH "/usr/local/lib:"
         NEW_RPATH "/usr/local/lib")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_cef_forwarder.so")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  include("/home/kami/blackbox-sentinel/build/CMakeFiles/sentinel_plugin_cef_forwarder.dir/install-cxx-module-bmi-noconfig.cmake" OPTIONAL)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_firewall_sync.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_firewall_sync.so")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_firewall_sync.so"
         RPATH "/usr/local/lib")
  endif()
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/bin/libsentinel_plugin_firewall_sync.so")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/bin" TYPE SHARED_LIBRARY FILES "/home/kami/blackbox-sentinel/build/libsentinel_plugin_firewall_sync.so")
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_firewall_sync.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_firewall_sync.so")
    file(RPATH_CHANGE
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_firewall_sync.so"
         OLD_RPATH "/usr/local/lib:"
         NEW_RPATH "/usr/local/lib")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_firewall_sync.so")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  include("/home/kami/blackbox-sentinel/build/CMakeFiles/sentinel_plugin_firewall_sync.dir/install-cxx-module-bmi-noconfig.cmake" OPTIONAL)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_llm_summarizer.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_llm_summarizer.so")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_llm_summarizer.so"
         RPATH "/usr/local/lib")
  endif()
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/bin/libsentinel_plugin_llm_summarizer.so")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/bin" TYPE SHARED_LIBRARY FILES "/home/kami/blackbox-sentinel/build/libsentinel_plugin_llm_summarizer.so")
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_llm_summarizer.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_llm_summarizer.so")
    file(RPATH_CHANGE
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_llm_summarizer.so"
         OLD_RPATH "/usr/local/lib:"
         NEW_RPATH "/usr/local/lib")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_llm_summarizer.so")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  include("/home/kami/blackbox-sentinel/build/CMakeFiles/sentinel_plugin_llm_summarizer.dir/install-cxx-module-bmi-noconfig.cmake" OPTIONAL)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_mavlink.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_mavlink.so")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_mavlink.so"
         RPATH "/usr/local/lib")
  endif()
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/bin/libsentinel_plugin_mavlink.so")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/bin" TYPE SHARED_LIBRARY FILES "/home/kami/blackbox-sentinel/build/libsentinel_plugin_mavlink.so")
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_mavlink.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_mavlink.so")
    file(RPATH_CHANGE
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_mavlink.so"
         OLD_RPATH "/usr/local/lib:"
         NEW_RPATH "/usr/local/lib")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_mavlink.so")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  include("/home/kami/blackbox-sentinel/build/CMakeFiles/sentinel_plugin_mavlink.dir/install-cxx-module-bmi-noconfig.cmake" OPTIONAL)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_ais_maritime.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_ais_maritime.so")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_ais_maritime.so"
         RPATH "/usr/local/lib")
  endif()
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/bin/libsentinel_plugin_ais_maritime.so")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/bin" TYPE SHARED_LIBRARY FILES "/home/kami/blackbox-sentinel/build/libsentinel_plugin_ais_maritime.so")
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_ais_maritime.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_ais_maritime.so")
    file(RPATH_CHANGE
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_ais_maritime.so"
         OLD_RPATH "/usr/local/lib:"
         NEW_RPATH "/usr/local/lib")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_ais_maritime.so")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  include("/home/kami/blackbox-sentinel/build/CMakeFiles/sentinel_plugin_ais_maritime.dir/install-cxx-module-bmi-noconfig.cmake" OPTIONAL)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_rtsp_correlator.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_rtsp_correlator.so")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_rtsp_correlator.so"
         RPATH "/usr/local/lib")
  endif()
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/bin/libsentinel_plugin_rtsp_correlator.so")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/bin" TYPE SHARED_LIBRARY FILES "/home/kami/blackbox-sentinel/build/libsentinel_plugin_rtsp_correlator.so")
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_rtsp_correlator.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_rtsp_correlator.so")
    file(RPATH_CHANGE
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_rtsp_correlator.so"
         OLD_RPATH "/usr/local/lib:"
         NEW_RPATH "/usr/local/lib")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_rtsp_correlator.so")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  include("/home/kami/blackbox-sentinel/build/CMakeFiles/sentinel_plugin_rtsp_correlator.dir/install-cxx-module-bmi-noconfig.cmake" OPTIONAL)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_gpio_siren.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_gpio_siren.so")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_gpio_siren.so"
         RPATH "/usr/local/lib")
  endif()
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/bin/libsentinel_plugin_gpio_siren.so")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/bin" TYPE SHARED_LIBRARY FILES "/home/kami/blackbox-sentinel/build/libsentinel_plugin_gpio_siren.so")
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_gpio_siren.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_gpio_siren.so")
    file(RPATH_CHANGE
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_gpio_siren.so"
         OLD_RPATH "/usr/local/lib:"
         NEW_RPATH "/usr/local/lib")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_gpio_siren.so")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  include("/home/kami/blackbox-sentinel/build/CMakeFiles/sentinel_plugin_gpio_siren.dir/install-cxx-module-bmi-noconfig.cmake" OPTIONAL)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_dicom_medical.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_dicom_medical.so")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_dicom_medical.so"
         RPATH "/usr/local/lib")
  endif()
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/bin/libsentinel_plugin_dicom_medical.so")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/bin" TYPE SHARED_LIBRARY FILES "/home/kami/blackbox-sentinel/build/libsentinel_plugin_dicom_medical.so")
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_dicom_medical.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_dicom_medical.so")
    file(RPATH_CHANGE
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_dicom_medical.so"
         OLD_RPATH "/usr/local/lib:"
         NEW_RPATH "/usr/local/lib")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_dicom_medical.so")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  include("/home/kami/blackbox-sentinel/build/CMakeFiles/sentinel_plugin_dicom_medical.dir/install-cxx-module-bmi-noconfig.cmake" OPTIONAL)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_bacnet.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_bacnet.so")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_bacnet.so"
         RPATH "/usr/local/lib")
  endif()
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/bin/libsentinel_plugin_bacnet.so")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/bin" TYPE SHARED_LIBRARY FILES "/home/kami/blackbox-sentinel/build/libsentinel_plugin_bacnet.so")
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_bacnet.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_bacnet.so")
    file(RPATH_CHANGE
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_bacnet.so"
         OLD_RPATH "/usr/local/lib:"
         NEW_RPATH "/usr/local/lib")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_bacnet.so")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  include("/home/kami/blackbox-sentinel/build/CMakeFiles/sentinel_plugin_bacnet.dir/install-cxx-module-bmi-noconfig.cmake" OPTIONAL)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_ad_correlator.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_ad_correlator.so")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_ad_correlator.so"
         RPATH "/usr/local/lib")
  endif()
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/bin/libsentinel_plugin_ad_correlator.so")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/bin" TYPE SHARED_LIBRARY FILES "/home/kami/blackbox-sentinel/build/libsentinel_plugin_ad_correlator.so")
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_ad_correlator.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_ad_correlator.so")
    file(RPATH_CHANGE
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_ad_correlator.so"
         OLD_RPATH "/usr/local/lib:"
         NEW_RPATH "/usr/local/lib")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_ad_correlator.so")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  include("/home/kami/blackbox-sentinel/build/CMakeFiles/sentinel_plugin_ad_correlator.dir/install-cxx-module-bmi-noconfig.cmake" OPTIONAL)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_webhook.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_webhook.so")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_webhook.so"
         RPATH "/usr/local/lib")
  endif()
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/bin/libsentinel_plugin_webhook.so")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/bin" TYPE SHARED_LIBRARY FILES "/home/kami/blackbox-sentinel/build/libsentinel_plugin_webhook.so")
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_webhook.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_webhook.so")
    file(RPATH_CHANGE
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_webhook.so"
         OLD_RPATH "/usr/local/lib:"
         NEW_RPATH "/usr/local/lib")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_webhook.so")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  include("/home/kami/blackbox-sentinel/build/CMakeFiles/sentinel_plugin_webhook.dir/install-cxx-module-bmi-noconfig.cmake" OPTIONAL)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_plc_decoy.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_plc_decoy.so")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_plc_decoy.so"
         RPATH "/usr/local/lib")
  endif()
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/bin/libsentinel_plugin_plc_decoy.so")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/bin" TYPE SHARED_LIBRARY FILES "/home/kami/blackbox-sentinel/build/libsentinel_plugin_plc_decoy.so")
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_plc_decoy.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_plc_decoy.so")
    file(RPATH_CHANGE
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_plc_decoy.so"
         OLD_RPATH "/usr/local/lib:"
         NEW_RPATH "/usr/local/lib")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_plc_decoy.so")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  include("/home/kami/blackbox-sentinel/build/CMakeFiles/sentinel_plugin_plc_decoy.dir/install-cxx-module-bmi-noconfig.cmake" OPTIONAL)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_evidence_locker.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_evidence_locker.so")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_evidence_locker.so"
         RPATH "/usr/local/lib")
  endif()
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/bin/libsentinel_plugin_evidence_locker.so")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/bin" TYPE SHARED_LIBRARY FILES "/home/kami/blackbox-sentinel/build/libsentinel_plugin_evidence_locker.so")
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_evidence_locker.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_evidence_locker.so")
    file(RPATH_CHANGE
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_evidence_locker.so"
         OLD_RPATH "/usr/local/lib:"
         NEW_RPATH "/usr/local/lib")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_evidence_locker.so")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  include("/home/kami/blackbox-sentinel/build/CMakeFiles/sentinel_plugin_evidence_locker.dir/install-cxx-module-bmi-noconfig.cmake" OPTIONAL)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_memory_dump.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_memory_dump.so")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_memory_dump.so"
         RPATH "/usr/local/lib")
  endif()
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/bin/libsentinel_plugin_memory_dump.so")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/bin" TYPE SHARED_LIBRARY FILES "/home/kami/blackbox-sentinel/build/libsentinel_plugin_memory_dump.so")
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_memory_dump.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_memory_dump.so")
    file(RPATH_CHANGE
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_memory_dump.so"
         OLD_RPATH "/usr/local/lib:"
         NEW_RPATH "/usr/local/lib")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_memory_dump.so")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  include("/home/kami/blackbox-sentinel/build/CMakeFiles/sentinel_plugin_memory_dump.dir/install-cxx-module-bmi-noconfig.cmake" OPTIONAL)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_auditd_reconstructor.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_auditd_reconstructor.so")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_auditd_reconstructor.so"
         RPATH "/usr/local/lib")
  endif()
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/bin/libsentinel_plugin_auditd_reconstructor.so")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/bin" TYPE SHARED_LIBRARY FILES "/home/kami/blackbox-sentinel/build/libsentinel_plugin_auditd_reconstructor.so")
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_auditd_reconstructor.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_auditd_reconstructor.so")
    file(RPATH_CHANGE
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_auditd_reconstructor.so"
         OLD_RPATH "/usr/local/lib:"
         NEW_RPATH "/usr/local/lib")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_auditd_reconstructor.so")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  include("/home/kami/blackbox-sentinel/build/CMakeFiles/sentinel_plugin_auditd_reconstructor.dir/install-cxx-module-bmi-noconfig.cmake" OPTIONAL)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_admin_portal_trap.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_admin_portal_trap.so")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_admin_portal_trap.so"
         RPATH "/usr/local/lib")
  endif()
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/bin/libsentinel_plugin_admin_portal_trap.so")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/bin" TYPE SHARED_LIBRARY FILES "/home/kami/blackbox-sentinel/build/libsentinel_plugin_admin_portal_trap.so")
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_admin_portal_trap.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_admin_portal_trap.so")
    file(RPATH_CHANGE
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_admin_portal_trap.so"
         OLD_RPATH "/usr/local/lib:"
         NEW_RPATH "/usr/local/lib")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_admin_portal_trap.so")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  include("/home/kami/blackbox-sentinel/build/CMakeFiles/sentinel_plugin_admin_portal_trap.dir/install-cxx-module-bmi-noconfig.cmake" OPTIONAL)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_canary_file.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_canary_file.so")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_canary_file.so"
         RPATH "/usr/local/lib")
  endif()
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/bin/libsentinel_plugin_canary_file.so")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/bin" TYPE SHARED_LIBRARY FILES "/home/kami/blackbox-sentinel/build/libsentinel_plugin_canary_file.so")
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_canary_file.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_canary_file.so")
    file(RPATH_CHANGE
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_canary_file.so"
         OLD_RPATH "/usr/local/lib:"
         NEW_RPATH "/usr/local/lib")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_canary_file.so")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  include("/home/kami/blackbox-sentinel/build/CMakeFiles/sentinel_plugin_canary_file.dir/install-cxx-module-bmi-noconfig.cmake" OPTIONAL)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_stanag_link16.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_stanag_link16.so")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_stanag_link16.so"
         RPATH "/usr/local/lib")
  endif()
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/bin/libsentinel_plugin_stanag_link16.so")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/bin" TYPE SHARED_LIBRARY FILES "/home/kami/blackbox-sentinel/build/libsentinel_plugin_stanag_link16.so")
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_stanag_link16.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_stanag_link16.so")
    file(RPATH_CHANGE
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_stanag_link16.so"
         OLD_RPATH "/usr/local/lib:"
         NEW_RPATH "/usr/local/lib")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_stanag_link16.so")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  include("/home/kami/blackbox-sentinel/build/CMakeFiles/sentinel_plugin_stanag_link16.dir/install-cxx-module-bmi-noconfig.cmake" OPTIONAL)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_eta_traffic.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_eta_traffic.so")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_eta_traffic.so"
         RPATH "/usr/local/lib")
  endif()
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/bin/libsentinel_plugin_eta_traffic.so")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/bin" TYPE SHARED_LIBRARY FILES "/home/kami/blackbox-sentinel/build/libsentinel_plugin_eta_traffic.so")
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_eta_traffic.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_eta_traffic.so")
    file(RPATH_CHANGE
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_eta_traffic.so"
         OLD_RPATH "/usr/local/lib:"
         NEW_RPATH "/usr/local/lib")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_eta_traffic.so")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  include("/home/kami/blackbox-sentinel/build/CMakeFiles/sentinel_plugin_eta_traffic.dir/install-cxx-module-bmi-noconfig.cmake" OPTIONAL)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_ueba_analytics.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_ueba_analytics.so")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_ueba_analytics.so"
         RPATH "/usr/local/lib")
  endif()
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/bin/libsentinel_plugin_ueba_analytics.so")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/bin" TYPE SHARED_LIBRARY FILES "/home/kami/blackbox-sentinel/build/libsentinel_plugin_ueba_analytics.so")
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_ueba_analytics.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_ueba_analytics.so")
    file(RPATH_CHANGE
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_ueba_analytics.so"
         OLD_RPATH "/usr/local/lib:"
         NEW_RPATH "/usr/local/lib")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_ueba_analytics.so")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  include("/home/kami/blackbox-sentinel/build/CMakeFiles/sentinel_plugin_ueba_analytics.dir/install-cxx-module-bmi-noconfig.cmake" OPTIONAL)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_dns_tunneling.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_dns_tunneling.so")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_dns_tunneling.so"
         RPATH "/usr/local/lib")
  endif()
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/bin/libsentinel_plugin_dns_tunneling.so")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/bin" TYPE SHARED_LIBRARY FILES "/home/kami/blackbox-sentinel/build/libsentinel_plugin_dns_tunneling.so")
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_dns_tunneling.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_dns_tunneling.so")
    file(RPATH_CHANGE
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_dns_tunneling.so"
         OLD_RPATH "/usr/local/lib:"
         NEW_RPATH "/usr/local/lib")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_dns_tunneling.so")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  include("/home/kami/blackbox-sentinel/build/CMakeFiles/sentinel_plugin_dns_tunneling.dir/install-cxx-module-bmi-noconfig.cmake" OPTIONAL)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_onvif_tamper.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_onvif_tamper.so")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_onvif_tamper.so"
         RPATH "/usr/local/lib")
  endif()
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/bin/libsentinel_plugin_onvif_tamper.so")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/bin" TYPE SHARED_LIBRARY FILES "/home/kami/blackbox-sentinel/build/libsentinel_plugin_onvif_tamper.so")
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_onvif_tamper.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_onvif_tamper.so")
    file(RPATH_CHANGE
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_onvif_tamper.so"
         OLD_RPATH "/usr/local/lib:"
         NEW_RPATH "/usr/local/lib")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_onvif_tamper.so")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  include("/home/kami/blackbox-sentinel/build/CMakeFiles/sentinel_plugin_onvif_tamper.dir/install-cxx-module-bmi-noconfig.cmake" OPTIONAL)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_nmea_marine.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_nmea_marine.so")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_nmea_marine.so"
         RPATH "/usr/local/lib")
  endif()
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/bin/libsentinel_plugin_nmea_marine.so")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/bin" TYPE SHARED_LIBRARY FILES "/home/kami/blackbox-sentinel/build/libsentinel_plugin_nmea_marine.so")
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_nmea_marine.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_nmea_marine.so")
    file(RPATH_CHANGE
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_nmea_marine.so"
         OLD_RPATH "/usr/local/lib:"
         NEW_RPATH "/usr/local/lib")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_nmea_marine.so")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  include("/home/kami/blackbox-sentinel/build/CMakeFiles/sentinel_plugin_nmea_marine.dir/install-cxx-module-bmi-noconfig.cmake" OPTIONAL)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_hl7_hospital.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_hl7_hospital.so")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_hl7_hospital.so"
         RPATH "/usr/local/lib")
  endif()
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/bin/libsentinel_plugin_hl7_hospital.so")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/bin" TYPE SHARED_LIBRARY FILES "/home/kami/blackbox-sentinel/build/libsentinel_plugin_hl7_hospital.so")
  if(EXISTS "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_hl7_hospital.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_hl7_hospital.so")
    file(RPATH_CHANGE
         FILE "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_hl7_hospital.so"
         OLD_RPATH "/usr/local/lib:"
         NEW_RPATH "/usr/local/lib")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}/usr/local/bin/libsentinel_plugin_hl7_hospital.so")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  include("/home/kami/blackbox-sentinel/build/CMakeFiles/sentinel_plugin_hl7_hospital.dir/install-cxx-module-bmi-noconfig.cmake" OPTIONAL)
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
if(CMAKE_INSTALL_LOCAL_ONLY)
  file(WRITE "/home/kami/blackbox-sentinel/build/install_local_manifest.txt"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
endif()
if(CMAKE_INSTALL_COMPONENT)
  if(CMAKE_INSTALL_COMPONENT MATCHES "^[a-zA-Z0-9_.+-]+$")
    set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
  else()
    string(MD5 CMAKE_INST_COMP_HASH "${CMAKE_INSTALL_COMPONENT}")
    set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INST_COMP_HASH}.txt")
    unset(CMAKE_INST_COMP_HASH)
  endif()
else()
  set(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  file(WRITE "/home/kami/blackbox-sentinel/build/${CMAKE_INSTALL_MANIFEST}"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
endif()
