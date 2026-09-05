//
// Created by klewy on 8/31/26.
//

#include "modifier.hpp"
bool Modifier::modify(std::vector<Packet> &vec, const Connection &conn)
{
    bool updated = false;
    for (auto &modifier : modifiers_) {
        if (!modifier->matches(conn.get_l4_proto(), conn.payload_proto())) {
            continue;
        }

        if (modifier->modify(vec)) {
            updated = true;
        }
    }

    return updated;
}