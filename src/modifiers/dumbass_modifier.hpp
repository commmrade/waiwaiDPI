//
// Created by klewy on 8/24/26.
//

#ifndef WAIWAIDPI_DUMBASS_MODIFIER_HPP
#define WAIWAIDPI_DUMBASS_MODIFIER_HPP
#include "modifier.hpp"


class DumbassModifier final : public Modifier
{
public:
    bool modify(std::vector<Packet> &vec) override;
    bool matches(const int l4_proto, const L7Proto l7_proto) const override;
};


#endif// WAIWAIDPI_DUMBASS_MODIFIER_HPP
