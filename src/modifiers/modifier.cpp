//
// Created by klewy on 8/31/26.
//

#include "modifier.hpp"
void Modifier::modify(std::vector<Packet> &vec, const Connection &conn)
{
    for (auto &modifier : modifiers_) {
        if (!modifier->matches(vec, conn)) {
            continue;
        }

        modifier->modify(vec, conn);
    }
}