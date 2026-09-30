//
// Created by klewy on 9/7/26.
//

#ifndef WAIWAIDPI_TLS_HANDSHAKE_MODIFIER_HPP
#define WAIWAIDPI_TLS_HANDSHAKE_MODIFIER_HPP
#include "modifier.hpp"
#include "split.hpp"

class TlsHandshakeModifier : public IModifier
{
    Split split_at_{};
    [[nodiscard]] static std::optional<std::string_view> get_sni(std::span<const char> payload);
public:
    void modify(std::vector<Packet> &vec, const Connection& conn) override;
    bool matches(const std::vector<Packet>& packets, const Connection& conn) const override;
    [[nodiscard]] static constexpr std::string_view name()
    {
        return std::string_view{"tls_handshake_modifier"};
    }
    void parse_config(const toml::table *table) override;
};


#endif// WAIWAIDPI_TLS_HANDSHAKE_MODIFIER_HPP
