//
// Created by klewy on 11/6/26.
//

#ifndef WAIWAIDPI_REASSEMBLER_HPP
#define WAIWAIDPI_REASSEMBLER_HPP
#include "net/packet_view.hpp"


#include <vector>


class Reassembler
{
    std::vector<Packet> segs_;

    bool is_duplicate(const PacketView& pkt);
    void sort();
public:

    void reset();
    void insert(const PacketView& pkt);
    [[nodiscard]] const std::vector<Packet> &get() const { return segs_; }
};


#endif// WAIWAIDPI_REASSEMBLER_HPP
