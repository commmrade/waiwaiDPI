//
// Created by klewy on 8/24/26.
//

#include "dumbass_modifier.hpp"

bool DumbassModifier::modify(std::vector<Packet> &vec)
{
    const auto pkt_view = parse_packet(vec.back().packet);
    auto pkt = construct_packet_from(pkt_view.payload, pkt_view);
    pkt.action.action = PacketAction::Action::SEND;
    auto* ip = reinterpret_cast<iphdr*>(pkt.packet.data());
    ip->ttl = 1;
    auto* tcp = reinterpret_cast<tcphdr*>(pkt.packet.data() + (ip->ihl * 4));
    tcp->syn = false;
    tcp->ack = true;

    tcp->check = 0;
    tcp->check = tcp_calc_cksum(ip, tcp, pkt_view.payload);

    vec.push_back(std::move(pkt));

    return true;
}
bool DumbassModifier::matches([[maybe_unused]] const std::uint8_t l4_proto, [[maybe_unused]] const L7Proto l7_proto) const
{
    return true;
}