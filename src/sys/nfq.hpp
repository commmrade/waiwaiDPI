//
// Created by klewy on 8/10/26.
//

#ifndef WAIWAIDPI_NFQ_HPP
#define WAIWAIDPI_NFQ_HPP
#include <cstdint>
#include <libmnl/libmnl.h>

int send_verdict(mnl_socket *sock, const std::uint32_t queue_number, const std::uint32_t packet_id, int verd);

#endif// WAIWAIDPI_NFQ_HPP
