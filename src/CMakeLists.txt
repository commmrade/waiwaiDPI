find_package(PkgConfig REQUIRED)
pkg_check_modules(MNL REQUIRED libmnl)
pkg_check_modules(NETFILTER_QUEUE REQUIRED libnetfilter_queue)

add_executable(main main.cpp
        classifier.hpp
        nfq.hpp
        nfq.cpp
        conn_tracker.hpp
        classifier.cpp
        conn_tracker.cpp
        protocol.hpp
        consts.hpp)

target_include_directories(main PUBLIC ${MNL_INCLUDE_DIRS} ${NETFILTER_QUEUE_INCLUDE_DIRS})
target_link_libraries(
  main
  PRIVATE waiwaiDPI::waiwaiDPI_options
          waiwaiDPI::waiwaiDPI_warnings
          spdlog::spdlog
          lefticus::tools
          ${MNL_LIBRARIES}
          ${NETFILTER_QUEUE_LIBRARIES})


waiwaiDPI_configure_linker(main)

target_include_directories(main PRIVATE "${CMAKE_BINARY_DIR}/configured_files/include")