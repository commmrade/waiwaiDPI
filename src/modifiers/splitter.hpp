//
// Created by klewy on 9/24/26.
//

#ifndef WAIWAIDPI_SPLITTER_HPP
#define WAIWAIDPI_SPLITTER_HPP
#include "modifier.hpp"
#include "split.hpp"

#include <unordered_set>

class Splitter : public IModifier
{
    std::vector<Split> splits_;
    std::optional<std::vector<char>> fake_blob_;
    std::optional<std::unordered_set<std::string>> allowed_hosts_; // if std::nullopt, then let everything through
    std::optional<std::unordered_set<std::uint32_t>> allowed_ips_; // if nullopt, then let everything through
    bool badcksum_{false};
    std::optional<int> seq_offset_;
    std::optional<int> ts_offset_;
    std::optional<std::uint8_t> ipv4_ttl_;
    std::optional<L7Proto> l7_payload_;
    std::optional<int> seqovl_;

    bool check_ip(const std::vector<Packet>& packets) const;
    void process(std::vector<Packet>& packets, const bool handle_fake, const Connection& conn);
public:
    void modify(std::vector<Packet> &vec, const Connection& conn) override;
    [[nodiscard]] bool matches(const std::vector<Packet>& packets, const Connection& conn) const override;
    void parse_config(const toml::table *table) override;

    [[nodiscard]] static constexpr std::string_view name()
    {
        return std::string_view{"splitter"};
    }
};


#endif// WAIWAIDPI_SPLITTER_HPP
