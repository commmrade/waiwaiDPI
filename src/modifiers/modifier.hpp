//
// Created by klewy on 8/24/26.
//

#ifndef WAIWAIDPI_MODIFIER_HPP
#define WAIWAIDPI_MODIFIER_HPP

#include "../packet_view.hpp"
#include <cstring>
#include <vector>



class Modifier
{
public:
    virtual ~Modifier() = default;
    virtual bool modify(std::vector<Packet>& vec) = 0; // true - successfully processed, false - did nothing
    [[nodiscard]] virtual bool matches(const std::uint8_t l4_proto, const L7Proto l7_proto) const = 0; // used to make sure that these packets can be processed by this modifier
};


#endif// WAIWAIDPI_MODIFIER_HPP
