//
// Created by klewy on 9/24/26.
//

#ifndef WAIWAIDPI_SPLIT_HPP
#define WAIWAIDPI_SPLIT_HPP
#include "conntrack/conn_tracker.hpp"
#include "net/packet_view.hpp"
#include "modify/args.hpp"
#include <expected>
#include <vector>

namespace split {
    struct SplitConfig
    {
        std::reference_wrapper<const Position> pos;
        bool handle_fake;
    };

    std::expected <bool, std::string> split(std::vector<Packet> &packets, const SplitConfig &cfg, const Connection &conn);
    std::expected<bool, std::string> split(std::vector<Packet>& packets, const SplitConfig& cfg, const std::vector<char>& full_payload, const Connection& conn);

    std::expected<bool, std::string> split_http(std::vector<Packet>& packets, const std::vector<char>& full_payload, const SplitConfig& cfg);
    std::expected<bool, std::string> split_tls(std::vector<Packet>& packets, const std::vector<char>& full_payload, const SplitConfig& cfg);
    std::expected<bool, std::string> split_other(std::vector<Packet>& packets, const std::vector<char>& full_payload, const SplitConfig& cfg);
}

namespace helpers {
std::size_t do_operation(const std::size_t start, const Position::Operation oper, const std::size_t offset);

template<typename T>
static bool safe_subspan(std::span<const T> &span, const std::size_t offset)
{
    if (span.size() < offset) { return false; }
    span = span.subspan(offset);
    return true;
}

}

#endif// WAIWAIDPI_SPLIT_HPP
