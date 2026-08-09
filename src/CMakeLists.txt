add_executable(main main.cpp)

target_link_libraries(
  main
  PRIVATE waiwaiDPI::waiwaiDPI_options
          waiwaiDPI::waiwaiDPI_warnings
          spdlog::spdlog
          lefticus::tools)


waiwaiDPI_configure_linker(main)

target_include_directories(main PRIVATE "${CMAKE_BINARY_DIR}/configured_files/include")