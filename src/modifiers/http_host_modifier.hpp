//
// Created by klewy on 8/24/26.
//

#ifndef WAIWAIDPI_HTTP_HOST_MODIFIER_HPP
#define WAIWAIDPI_HTTP_HOST_MODIFIER_HPP

#include "modifier.hpp"
#include "split.hpp"

class HttpHostModifier final : public IModifier
{
    Split split_at_{};
public:
    void modify(std::vector<Packet> &vec, const Connection& conn) override;
    [[nodiscard]] bool matches(const std::vector<Packet>& packets, const Connection& conn) const override;
    [[nodiscard]] static constexpr std::string_view name()
    {
        return std::string_view{"http_host_modifier"};
    }
    void parse_config(const toml::table *table) override;
};



#endif// WAIWAIDPI_HTTP_HOST_MODIFIER_HPP
