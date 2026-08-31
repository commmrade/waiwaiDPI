cmake_minimum_required(VERSION 3.15...3.23)

project(CmakeConfigPackageTests 
  VERSION ${PROJECT_VERSION}
  LANGUAGES CXX)

# ---- Test as standalone project the exported config package ----

if(PROJECT_IS_TOP_LEVEL OR TEST_INSTALLED_VERSION)
  enable_testing()

  find_package(waiwaiDPI CONFIG REQUIRED) # for intro, project_options, ...

  if(NOT TARGET waiwaiDPI_options)
    message(FATAL_ERROR "Required config package not found!")
    return() # be strictly paranoid for Template Janitor github action! CK
  endif()
endif()

# ---- Dependencies ----

include(${Catch2_SOURCE_DIR}/extras/Catch.cmake)

# Provide a simple smoke test to make sure that the CLI works and can display a --help message
add_test(NAME cli.has_help COMMAND intro --help)

# CMake-script regression tests for cmake/Sanitizers.cmake (issue #141).
add_test(
  NAME cmake.sanitizers.apple_excludes_leak
  COMMAND ${CMAKE_COMMAND} -P
          ${CMAKE_CURRENT_SOURCE_DIR}/cmake/test_sanitizers_apple_excludes_leak.cmake)
add_test(
  NAME cmake.sanitizers.non_apple_includes_leak
  COMMAND ${CMAKE_COMMAND} -P
          ${CMAKE_CURRENT_SOURCE_DIR}/cmake/test_sanitizers_non_apple_includes_leak.cmake)

# Provide a test to verify that the version being reported from the application
# matches the version given to CMake. This will be important once you package
# your program. Real world shows that this is the kind of simple mistake that is easy
# to make, but also easy to test for.
add_test(NAME cli.version_matches COMMAND intro --version)
set_tests_properties(cli.version_matches PROPERTIES PASS_REGULAR_EXPRESSION "${PROJECT_VERSION}")

add_executable(tests
        http_classifier_tests.cpp
        tls_classifier_tests.cpp
        common.hpp
        ../src/classifier.cpp
        ../src/conn_tracker.cpp
        ../src/packet_view.cpp
        ../src/classifiers/http_classifier.cpp
        ../src/classifiers/tls_classifier.cpp
        ../src/modifiers/http_host_modifier.cpp
        ../src/checksum.cpp
        ../src/modifiers/modifier.cpp
        tcp_state_tests.cpp
        http_modifier_tests.cpp
)
target_link_libraries(
  tests
  PRIVATE waiwaiDPI::waiwaiDPI_warnings
          waiwaiDPI::waiwaiDPI_options
          Catch2::Catch2WithMain)

waiwaiDPI_configure_linker(tests)

if(WIN32 AND BUILD_SHARED_LIBS)
  add_custom_command(
    TARGET tests
    PRE_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_RUNTIME_DLLS:tests> $<TARGET_FILE_DIR:tests>
    COMMAND_EXPAND_LISTS)
endif()

# automatically discover tests that are defined in catch based test files you can modify the unittests. Set TEST_PREFIX
# to whatever you want, or use different for different binaries
catch_discover_tests(
  tests
  TEST_PREFIX
  "unittests."
  REPORTER
  XML
  OUTPUT_DIR
  .
  OUTPUT_PREFIX
  "unittests."
  OUTPUT_SUFFIX
  .xml)

