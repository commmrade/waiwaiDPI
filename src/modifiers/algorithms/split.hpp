//
// Created by klewy on 9/24/26.
//

#ifndef WAIWAIDPI_SPLIT_HPP
#define WAIWAIDPI_SPLIT_HPP
#include "../../conn_tracker.hpp"
#include "../../packet_view.hpp"
#include "../split.hpp"


#include <vector>

namespace split {
    bool split(std::vector<Packet>& packets, const Split& pos, const Connection& conn);

    bool split_http(std::vector<Packet>& packets, const Split& pos, const std::vector<char>& full_payload);
    bool split_tls(std::vector<Packet>& packets, const Split& pos, const std::vector<char>& full_payload);
    bool split_other(std::vector<Packet>& packets, const Split& pos, const std::vector<char>& full_payload);
}

#endif// WAIWAIDPI_SPLIT_HPP
