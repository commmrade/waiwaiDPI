//
// Created by klewy on 8/24/26.
//

#include "dumbass_modifier.hpp"

bool DumbassModifier::modify(std::vector<Packet> &vec)
{
    const auto pkt_view = parse_packet(vec.back().packet);
    auto pkt = construct_packet_from(pkt_view.payload, pkt_view);
    iphdr* ip = reinterpret_cast<iphdr*>(pkt.packet.data());
    ip->ttl = 3;

    vec.push_back(std::move(pkt));

    return true;
}
bool DumbassModifier::matches([[maybe_unused]] const int l4_proto, [[maybe_unused]] const L7Proto l7_proto) const
{
    return true;
}