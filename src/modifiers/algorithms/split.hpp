//
// Created by klewy on 9/24/26.
//

#ifndef WAIWAIDPI_SPLIT_HPP
#define WAIWAIDPI_SPLIT_HPP
#include "../../conn_tracker.hpp"
#include "../../packet_view.hpp"
#include "../split.hpp"


#include <expected>
#include <unordered_set>
#include <vector>

namespace split {
    struct SplitConfig
    {
        const Split& pos;
        const std::optional<std::unordered_set<std::string>>& hosts;
        bool handle_fake;
    };

    std::expected <bool, std::string> split(std::vector<Packet> &packets, const SplitConfig &cfg, const Connection &conn);
    std::expected<bool, std::string> split(std::vector<Packet>& packets, const SplitConfig& cfg, const std::vector<char>& full_payload, const Connection& conn);

    std::expected<bool, std::string> split_http(std::vector<Packet>& packets, const std::vector<char>& full_payload, const SplitConfig& cfg);
    std::expected<bool, std::string> split_tls(std::vector<Packet>& packets, const std::vector<char>& full_payload, const SplitConfig& cfg);
    std::expected<bool, std::string> split_other(std::vector<Packet>& packets, const std::vector<char>& full_payload, const SplitConfig& cfg);
}

#endif// WAIWAIDPI_SPLIT_HPP
