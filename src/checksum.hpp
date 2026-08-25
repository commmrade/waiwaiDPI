//
// Created by klewy on 8/25/26.
//

#ifndef WAIWAIDPI_CHECKSUM_HPP
#define WAIWAIDPI_CHECKSUM_HPP
#include "packet_view.hpp"
#include <cstdint>

std::uint16_t calc_tcp_checksum(const Packet& pkt);

#endif// WAIWAIDPI_CHECKSUM_HPP
