//
// Created by klewy on 8/24/26.
//

#include "dumbass_modifier.hpp"

#include "../../out/build/unixlike-gcc-debug/_deps/catch2-src/src/catch2/matchers/catch_matchers_floating_point.hpp"

bool DumbassModifier::modify(std::vector<Packet> &vec)
{
    const auto pkt_view = parse_packet_view(vec.back());
    auto pkt = construct_packet_from(pkt_view.payload, pkt_view);
    pkt.action.action = PacketAction::Action::SEND;
    pkt.network_hdr()->ttl = 1;
    auto* tcp = reinterpret_cast<tcphdr*>(pkt.transport_hdr());
    tcp->syn = false;
    tcp->ack = true;

    tcp->check = 0;
    tcp->check = tcp_calc_cksum(pkt.network_hdr(), tcp, pkt_view.payload);

    vec.push_back(std::move(pkt));

    return true;
}
bool DumbassModifier::matches([[maybe_unused]] const std::uint8_t l4_proto, [[maybe_unused]] const L7Proto l7_proto) const
{
    return true;
}