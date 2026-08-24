//
// Created by klewy on 8/24/26.
//

#include "http_host_modifier.hpp"

#include <cassert>
#include <cstring>
#include <print>


static bool host_list(const std::string_view hostname)
{
    return hostname == "httpforever.com" || hostname == "soundcloud.com";
}

bool HttpHostModifier::modify(std::vector<Packet> &vec)
{
    bool host_found = false;
    for (std::size_t i = 0; i < vec.size(); ++i) {
        const auto pkt_view = parse_packet(vec[i].packet);
        const std::string_view pkt_pl{pkt_view.payload};

        constexpr std::string_view HOST_HEADER_NAME = "Host:";
        const auto host_pos = pkt_pl.find(HOST_HEADER_NAME);
        if (host_pos == std::string_view::npos) {
            continue;
        }
        host_found = true;

        const std::string_view host_name{pkt_pl.begin() + host_pos + HOST_HEADER_NAME.size() + 1, pkt_pl.substr(host_pos + HOST_HEADER_NAME.size() + 1).find("\r\n")};
        if (!host_list(host_name)) {
            return false;
        }

        constexpr auto SPLIT_AT = 8;

        const std::span<const char> part1{pkt_pl.begin(), pkt_pl.begin() + host_pos + SPLIT_AT};
        const std::span<const char> part2{pkt_pl.begin() + host_pos + SPLIT_AT, pkt_pl.end()};


        Packet first_packet = construct_packet_from(part1, pkt_view);
        first_packet.packet_id = pkt_view.packet_id;

        auto* ip = reinterpret_cast<iphdr*>(first_packet.packet.data());
        auto* tcp = reinterpret_cast<tcphdr*>(first_packet.packet.data() + (ip->ihl * 4));

        tcp->check = 0;
        tcp->check = tcp_calc_cksum(ip, tcp, part1);

        Packet second_packet = construct_packet_from(part2, pkt_view);
        ip = reinterpret_cast<iphdr*>(second_packet.packet.data());
        tcp = reinterpret_cast<tcphdr*>(second_packet.packet.data() + (ip->ihl * 4));

        tcp->seq += htonl(part1.size());
        tcp->check = 0;
        tcp->check = tcp_calc_cksum(ip, tcp, part2);

        // TODO: might be best to choose a different data structure
        vec.erase(vec.begin() + i);

        vec.insert(vec.begin() + i, std::move(first_packet));
        vec.insert(vec.begin() + i + 1, std::move(second_packet));

        break;
    }

    if (!host_found) {
        return false;
    }

    return true;
}
bool HttpHostModifier::matches(const std::uint8_t l4_proto, const L7Proto l7_proto) const
{
    return l7_proto == L7Proto::HTTP && l4_proto == IPPROTO_TCP;
}
