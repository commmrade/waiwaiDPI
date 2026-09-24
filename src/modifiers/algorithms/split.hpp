//
// Created by klewy on 9/24/26.
//

#ifndef WAIWAIDPI_SPLIT_HPP
#define WAIWAIDPI_SPLIT_HPP
#include "../../conn_tracker.hpp"
#include "../../packet_view.hpp"
#include "../split.hpp"


#include <unordered_set>
#include <vector>

namespace split {
    struct SplitConfig
    {
        const Split& pos;
        const std::optional<std::unordered_set<std::string>>& hosts;
    };

    bool split(std::vector<Packet>& packets, const SplitConfig& cfg, const Connection& conn);
    bool split(std::vector<Packet>& packets, const SplitConfig& cfg, const std::vector<char>& full_payload, const Connection& conn);

    bool split_http(std::vector<Packet>& packets, const std::vector<char>& full_payload, const SplitConfig& cfg);
    bool split_tls(std::vector<Packet>& packets, const std::vector<char>& full_payload, const SplitConfig& cfg);
    bool split_other(std::vector<Packet>& packets, const std::vector<char>& full_payload, const SplitConfig& cfg);
}

#endif// WAIWAIDPI_SPLIT_HPP
