//
// Created by klewy on 10/12/26.
//

#ifndef WAIWAIDPI_COMMON_HPP
#define WAIWAIDPI_COMMON_HPP
#include <span>
#include "../../packet_view.hpp"

bool timestamp_val_offset(Packet &packet, const int offset);
std::vector<Packet>
    segmentize(std::span<const char> full_payload, unsigned long mss, const Packet &orig_packet, unsigned start_seq);

#endif// WAIWAIDPI_COMMON_HPP
