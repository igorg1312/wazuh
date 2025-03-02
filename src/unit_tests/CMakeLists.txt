# Copyright (C) 2015-2021, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.
cmake_minimum_required(VERSION 3.10)

PROJECT(UnitTests C)

set(CMAKE_C_STANDARD 11)
get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../ ABSOLUTE)

message(Source folder: ${SRC_FOLDER})
include_directories(${SRC_FOLDER}/headers)
include_directories(${SRC_FOLDER}/external/openssl/include)
include_directories(${SRC_FOLDER}/external/audit-userspace/lib)
include_directories(${SRC_FOLDER}/external/bzip2)
include_directories(${SRC_FOLDER}/external/cJSON)
include_directories(${SRC_FOLDER}/external/msgpack/include)
include_directories(${SRC_FOLDER}/shared_modules/common)
include_directories(${SRC_FOLDER})
add_definitions(-DWAZUH_UNIT_TESTING)

# Wazuh libraries
find_library(WAZUHLIB NAMES libwazuh.a HINTS "${SRC_FOLDER}")
if(NOT WAZUHLIB)
  message(FATAL_ERROR "libwazuh.a not found in ${SRC_FOLDER} Aborting...")
endif()

# Enable testing
enable_testing()

# Add target specific file
if(NOT TARGET)
  message(FATAL_ERROR "No TARGET specified. Aborting...")
elseif(${TARGET} STREQUAL "server")
  include("./server.cmake")
elseif(${TARGET} STREQUAL "agent")
  include("./agent.cmake")
elseif(${TARGET} STREQUAL "winagent")
  include("./winagent.cmake")
else()
  message(FATAL_ERROR "Invalid TARGET '${TARGET}'. Aborting...")
endif()

if(NOT WAZUHEXT)
  message(FATAL_ERROR "libwazuhext not found! Aborting...")
endif()

if((${uname} STREQUAL "Linux") OR (${uname} STREQUAL "Win32"))
  add_subdirectory(syscheckd)
  add_subdirectory(shared)
  add_subdirectory(os_xml)
  add_subdirectory(os_regex)
  add_subdirectory(os_zlib)
  endif()

if(${uname} STREQUAL "Linux")
  add_subdirectory(os_net)
  add_subdirectory(fluentd_forwarder)
  endif()

# Config files
if(${TARGET} STREQUAL "winagent")
  configure_file("config_files/test_syscheck_win.conf" "syscheckd/test_syscheck.conf" NEWLINE_STYLE WIN32)
  configure_file("config_files/test_syscheck_win2.conf" "syscheckd/test_syscheck2.conf" NEWLINE_STYLE WIN32)
  configure_file("config_files/test_syscheck_win3.conf" "syscheckd/test_syscheck3.conf" NEWLINE_STYLE WIN32)
  configure_file("config_files/test_syscheck_win.conf" "syscheckd/ossec.conf" NEWLINE_STYLE WIN32)
  configure_file("config_files/test_syscheck_win_max_dir.conf" "syscheckd/test_syscheck_max_dir.conf" COPYONLY)
  configure_file("config_files/test_empty_config.conf" "syscheckd/test_empty_config.conf" NEWLINE_STYLE WIN32)
  configure_file("config_files/test_internal_options.conf" "syscheckd/internal_options.conf" NEWLINE_STYLE WIN32)
  configure_file("config_files/test_local_internal_options.conf" "syscheckd/local_internal_options.conf" NEWLINE_STYLE WIN32)
  configure_file("config_files/test_syscheck_top_level_win.conf" "syscheckd/test_syscheck_top_level.conf" NEWLINE_STYLE WIN32)
  configure_file("config_files/test_syscheck_config_win.conf" "syscheckd/test_syscheck_config.conf" NEWLINE_STYLE WIN32)
else()
  configure_file("config_files/test_syscheck.conf" "syscheckd/test_syscheck.conf" COPYONLY)
  configure_file("config_files/test_syscheck_max_dir.conf" "syscheckd/test_syscheck_max_dir.conf" COPYONLY)
  configure_file("config_files/test_syscheck2.conf" "syscheckd/test_syscheck2.conf" COPYONLY)
  configure_file("config_files/test_syscheck3.conf" "syscheckd/test_syscheck3.conf" COPYONLY)
  configure_file("config_files/test_empty_config.conf" "syscheckd/test_empty_config.conf" COPYONLY)
  configure_file("config_files/test_internal_options.conf" "syscheckd/internal_options.conf" COPYONLY)
  configure_file("config_files/test_local_internal_options.conf" "syscheckd/local_internal_options.conf" COPYONLY)
  configure_file("config_files/test_syscheck_top_level.conf" "syscheckd/test_syscheck_top_level.conf" COPYONLY)
  configure_file("config_files/test_syscheck.conf" "syscheckd/test_syscheck_config.conf" COPYONLY)
endif()

# Coverage
find_program(LCOV_PATH lcov)
if(NOT LCOV_PATH)
  message(FATAL_ERROR "lcov not found! Aborting...")
endif()

find_program(GCOV_PATH gcov)
if(NOT GCOV_PATH)
  message(FATAL_ERROR "gcov not found! Aborting...")
endif()

find_program(GENHTML_PATH genhtml)
if(NOT GENHTML_PATH)
  message(FATAL_ERROR "genhtml not found! Aborting...")
endif()

add_custom_target(coverage
    # Cleanup lcov
    COMMAND ${LCOV_PATH} --gcov-tool ${GCOV_PATH} -directory ${SRC_FOLDER} --rc lcov_branch_coverage=1 --zerocounters

    # Create baseline to make sure untouched files show up in the report
    COMMAND ${LCOV_PATH} -q --gcov-tool ${GCOV_PATH} -c -i -d ${SRC_FOLDER} --rc lcov_branch_coverage=1 -o coverage.base

    # Run tests
    COMMAND ctest

    # Capturing lcov counters and generating report
    COMMAND ${LCOV_PATH} -q --gcov-tool ${GCOV_PATH} --directory ${SRC_FOLDER} --capture --rc lcov_branch_coverage=1 --output-file coverage.info

    # Add baseline counters
    COMMAND ${LCOV_PATH} -q --gcov-tool ${GCOV_PATH} -a coverage.base -a coverage.info --rc lcov_branch_coverage=1 --output-file coverage.total
    COMMAND ${LCOV_PATH} --gcov-tool ${GCOV_PATH} --remove coverage.total "*external/*" --remove coverage.total "*unit_tests/*" --remove coverage.total "*data_provider/*" --remove coverage.total "*shared_modules/*" --remove coverage.total "*syscollector/*" --rc lcov_branch_coverage=1 --output-file coverage.info.cleaned

    # Generate HTML report
    COMMAND ${GENHTML_PATH} -q --output-directory coverage-report --title "WAZUH unit-tests coverage" --rc lcov_branch_coverage=1 --legend coverage.info.cleaned

    # Clean counters
    COMMAND ${CMAKE_COMMAND} -E remove coverage.base coverage.total coverage.info.cleaned
)
