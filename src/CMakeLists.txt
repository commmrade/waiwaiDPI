find_package(PkgConfig REQUIRED)
pkg_check_modules(MNL REQUIRED libmnl)
pkg_check_modules(NETFILTER_QUEUE REQUIRED libnetfilter_queue)

add_executable(main main.cpp
        classify/classifier.hpp
        sys/nfq.hpp
        sys/nfq.cpp
        conntrack/conn_tracker.hpp
        classify/classifier.cpp
        conntrack/conn_tracker.cpp
        net/protocol.hpp
        net/consts.hpp
        net/packet_view.hpp
        net/packet_view.cpp
        classify/http_classifier.cpp
        classify/http_classifier.hpp
        classify/tls_classifier.cpp
        classify/tls_classifier.hpp
        modify/modifier.hpp
        net/checksum.cpp
        net/checksum.hpp
        modify/modifier.cpp
        util/hash.hpp
        config/profile.cpp
        config/profile.hpp
        sys/iptables.cpp
        sys/iptables.hpp
        modify/args.hpp
        modify/splitter.cpp
        modify/splitter.hpp
        modify/algorithms/split.cpp
        modify/algorithms/split.hpp
        sys/iface.hpp
        sys/iface.cpp
        modify/disorder.cpp
        modify/disorder.hpp
        modify/args.cpp
        modify/algorithms/common.cpp
        modify/algorithms/common.hpp
        modify/markers.cpp
        modify/markers.hpp
)

target_include_directories(main PUBLIC ${MNL_INCLUDE_DIRS} ${NETFILTER_QUEUE_INCLUDE_DIRS})
target_link_libraries(
  main
  PRIVATE waiwaiDPI::waiwaiDPI_options
          waiwaiDPI::waiwaiDPI_warnings
          spdlog::spdlog
          lefticus::tools
          argh
          tomlplusplus
          ${MNL_LIBRARIES}
          ${NETFILTER_QUEUE_LIBRARIES})


waiwaiDPI_configure_linker(main)

target_include_directories(main PRIVATE "${CMAKE_BINARY_DIR}/configured_files/include" "${CMAKE_SOURCE_DIR}/src")