//
// Created by klewy on 8/24/26.
//

#ifndef WAIWAIDPI_DUMBASS_MODIFIER_HPP
#define WAIWAIDPI_DUMBASS_MODIFIER_HPP
#include "modifier.hpp"


class DumbassModifier final : public IModifier
{
public:
    bool modify(std::vector<Packet> &vec) override;
    [[nodiscard]] bool matches(const std::uint8_t l4_proto, const L7Proto l7_proto) const override;
};


#endif// WAIWAIDPI_DUMBASS_MODIFIER_HPP
