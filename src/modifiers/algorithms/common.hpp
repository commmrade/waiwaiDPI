//
// Created by klewy on 10/12/26.
//

#ifndef WAIWAIDPI_COMMON_HPP
#define WAIWAIDPI_COMMON_HPP
#include "packet_view.hpp"
#include <span>

bool timestamp_val_offset(Packet &packet, const int offset);
std::vector<Packet>
    segmentize(std::span<const char> full_payload, unsigned long mss, const Packet &orig_packet, unsigned start_seq);

std::vector<char> concat(std::vector<Packet> packets, const bool skip_fake = true);

#endif// WAIWAIDPI_COMMON_HPP
