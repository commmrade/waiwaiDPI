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
        consts.hpp
        packet_view.hpp
        packet_view.cpp
        classifiers/http_classifier.cpp
        classifiers/http_classifier.hpp
        classifiers/payload_classifier.hpp
        classifiers/tls_classifier.cpp
        classifiers/tls_classifier.hpp
        modifiers/modifier.hpp
        modifiers/http_host_modifier.cpp
        modifiers/http_host_modifier.hpp
        modifiers/dumbass_modifier.cpp
        modifiers/dumbass_modifier.hpp
        checksum.cpp
        checksum.hpp
        modifiers/modifier.cpp
        hash.hpp
)

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