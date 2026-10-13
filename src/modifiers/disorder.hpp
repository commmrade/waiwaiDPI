//
// Created by klewy on 10/12/26.
//

#ifndef WAIWAIDPI_DISORDER_HPP
#define WAIWAIDPI_DISORDER_HPP

#include "args.hpp"
#include "modifier.hpp"

#include <unordered_set>

class Disorder : public IModifier
{
    // arguments
    struct
    {
        std::vector<Position> splits;
        std::optional<std::unordered_set<std::string>> allowed_hosts; // if std::nullopt, then let everything through
        std::optional<std::unordered_set<std::uint32_t>> allowed_ips; // if nullopt, then let everything through
        std::optional<std::vector<char>> fake_blob;
        bool badcksum{false};
        std::optional<int> seq_offset;
        std::optional<int> ts_offset;
        std::optional<std::uint8_t> ipv4_ttl;
        std::optional<L7Proto> l7_payload;
        std::optional<Position> seqovl;
        std::optional<std::vector<char>> seqovl_pat;
    } args_;

    void seqovl(std::vector<Packet>& packets, bool handle_fake, const Connection& conn);
    bool check_ip(const std::vector<Packet> &packets) const;
    bool check_host(const std::vector<Packet>& packets, const Connection& conn) const;
    void process(std::vector<Packet>& packets, const bool handle_fake, const Connection& conn);
public:
    void modify(std::vector<Packet> &vec, const Connection &conn) override;
    bool matches(const std::vector<Packet> &packets, const Connection &conn) const override;
    void parse_config(const toml::table *table) override;

    [[nodiscard]] static constexpr std::string_view name()
    {
        return std::string_view{"disorder"};
    }
};


#endif// WAIWAIDPI_DISORDER_HPP
