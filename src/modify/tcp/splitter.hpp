//
// Created by klewy on 9/24/26.
//

#ifndef WAIWAIDPI_SPLITTER_HPP
#define WAIWAIDPI_SPLITTER_HPP

#include "../args.hpp"
#include "../modifier.hpp"
#include <unordered_set>

class Splitter : public IModifier
{
    struct
    {
        std::vector<Position> splits;
        std::optional<std::vector<char>> fake_blob;
        bool badcksum{ false };
        std::optional<int> seq_offset;
        std::optional<int> ts_offset;
        std::optional<std::uint8_t> ipv4_ttl;
        std::optional<L7Proto> l7_payload;
        std::optional<int> seqovl;
        std::optional<std::vector<char>> seqovl_pat;
    } args_;

    void process_fake(std::vector<Packet> &packets, ModifyContext &ctx);
    void process_orig(std::vector<Packet> &packets, ModifyContext &ctx);

    void seqovl(std::vector<Packet> &packets, const Connection &conn);

public:
    void modify(std::vector<Packet> &packets, ModifyContext &ctx) override;
    [[nodiscard]] bool matches(const std::vector<Packet> &packets, const Connection &conn) const override;
    void parse_config(const toml::table *table) override;

    // For profile building
    [[nodiscard]] static constexpr std::string_view name() { return std::string_view{ "splitter" }; }
    [[nodiscard]] static constexpr int transport_protocol() { return IPPROTO_TCP; }
};


#endif// WAIWAIDPI_SPLITTER_HPP
