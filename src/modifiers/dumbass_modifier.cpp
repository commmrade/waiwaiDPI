//
// Created by klewy on 8/24/26.
//

#include "dumbass_modifier.hpp"

bool DumbassModifier::modify(std::vector<Packet> &vec)
{
    auto pkt = construct_packet_from(parse_packet(vec.back()));
    iphdr* ip = reinterpret_cast<iphdr*>(pkt.packet.data());
    ip->ttl = 3;

    vec.push_back(std::move(pkt));

    return true;
}
bool DumbassModifier::matches([[maybe_unused]] const int l4_proto, [[maybe_unused]] const L7Proto l7_proto) const
{
    return true;
}