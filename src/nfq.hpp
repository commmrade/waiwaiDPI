//
// Created by klewy on 8/10/26.
//

#ifndef WAIWAIDPI_NFQ_HPP
#define WAIWAIDPI_NFQ_HPP
#include <libmnl/libmnl.h>
#include <cstdint>

constexpr int QUEUE_NUMBER = 1488;

int send_verdict(mnl_socket* sock, const std::uint32_t packet_id, int verd);

#endif// WAIWAIDPI_NFQ_HPP
