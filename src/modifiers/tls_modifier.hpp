//
// Created by klewy on 9/7/26.
//

#ifndef WAIWAIDPI_TLS_HANDSHAKE_MODIFIER_HPP
#define WAIWAIDPI_TLS_HANDSHAKE_MODIFIER_HPP
#include "modifier.hpp"


class TlsHandshakeModifier : public IModifier
{
    [[nodiscard]] static std::optional<std::string_view> get_sni(std::span<const char> payload);
public:
    bool modify(std::vector<Packet> &vec) override;
    bool matches(const std::uint8_t l4_proto, const L7Proto l7_proto) const override;
};


#endif// WAIWAIDPI_TLS_HANDSHAKE_MODIFIER_HPP
