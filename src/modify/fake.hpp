//
// Created by klewy on 11/16/26.
//

#ifndef WAIWAIDPI_FAKE_HPP
#define WAIWAIDPI_FAKE_HPP

#include "modify/modifier.hpp"

class Fake : public IModifier
{
    struct
    {
        std::vector<char> fake_blob;
        std::optional<std::uint8_t> ipv4_ttl;
        bool badcksum{false};
        std::optional<int> seq_offset;
        std::optional<int> ts_offset;
        std::optional<int> repeats;
    } args_;

    void process_fake(std::vector<Packet> &packets, ModifyContext &ctx);
public:
    void modify(std::vector<Packet> &packets, ModifyContext &ctx) override;
    [[nodiscard]] bool matches(const std::vector<Packet> &packets, const Connection &conn) const override;
    void parse_config(const toml::table *table) override;

    // For profile building
    [[nodiscard]] static constexpr std::string_view name() { return std::string_view{ "fake" }; }
    [[nodiscard]] static constexpr int transport_protocol() { return IPPROTO_UDP | IPPROTO_TCP; }
};


#endif// WAIWAIDPI_FAKE_HPP
