//
// Created by klewy on 9/7/26.
//

#ifndef WAIWAIDPI_TLS_HANDSHAKE_MODIFIER_HPP
#define WAIWAIDPI_TLS_HANDSHAKE_MODIFIER_HPP
#include "modifier.hpp"


class TlsHandshakeModifier : public IModifier
{
    std::size_t split_at_pos_{0};
    [[nodiscard]] static std::optional<std::string_view> get_sni(std::span<const char> payload);
public:
    bool modify(std::vector<Packet> &vec) override;
    bool matches(const std::uint8_t l4_proto, const L7Proto l7_proto) const override;
    [[nodiscard]] static constexpr std::string_view name()
    {
        return std::string_view{"tls_handshake_modifier"};
    }
    void parse_config(const toml::table *table) override;
};


#endif// WAIWAIDPI_TLS_HANDSHAKE_MODIFIER_HPP
