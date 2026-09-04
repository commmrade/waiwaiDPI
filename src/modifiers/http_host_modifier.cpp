//
// Created by klewy on 8/24/26.
//

#include "http_host_modifier.hpp"

#include "../checksum.hpp"
#include <ranges>
#include <cassert>
#include <cstring>
#include <iostream>
#include <print>


static bool host_list(const std::string_view hostname)
{
    return hostname == "httpforever.com" || hostname == "soundcloud.com";
}

bool HttpHostModifier::modify(std::vector<Packet> &vec)
{
    // We could use
    std::vector<char> full_payload;
    // OPTIMIZATION: can i use something like concat_view and then do .find() on it?
    for (const auto& pkt : vec) {
        const auto payload = pkt.payload();
        full_payload.insert(full_payload.end(), payload.begin(), payload.end());
    }
    const std::string_view payload_str{full_payload};

    constexpr std::string_view HOST_HEADER_NAME = "Host:";

    const auto host_subrange = std::ranges::search(payload_str, HOST_HEADER_NAME, [](const auto ch1, const auto ch2) {
       return std::tolower(ch1) == std::tolower(ch2);
    });
    if (host_subrange.empty()) {
        std::println(std::cerr, "[http_modifier]: Host header is not found");
        return false;
    }
    const auto host_pos = std::distance(payload_str.begin(), host_subrange.begin());

    constexpr auto SPLIT_AT = HOST_HEADER_NAME.size() + 3;
    const auto split_at_global_pos = static_cast<std::size_t>(host_pos) + SPLIT_AT;
    assert(split_at_global_pos < payload_str.size());

    auto iter = vec.begin();
    std::size_t offset = 0;
    std::size_t split_pos_relative_to_packet = 0;
    for (; iter != vec.end(); ++iter) {
        offset += iter->payload().size();
        if (split_at_global_pos < offset) {
            split_pos_relative_to_packet = split_at_global_pos - (offset - iter->payload().size());
            break;
        }
    }
    assert(iter != vec.end());

    if (split_pos_relative_to_packet == 0) { // split is naturally at packet borders
        return true; // it is fine to just return
    }

    auto& pkt = *iter;
    const auto pkt_view = parse_packet_view(pkt);
    const auto pkt_payload = pkt.payload();
    const std::span<const char> part1{pkt_payload.begin(), std::next(pkt_payload.begin(), static_cast<std::ptrdiff_t>(split_pos_relative_to_packet))};
    const std::span<const char> part2{std::next(pkt_payload.begin(), static_cast<std::ptrdiff_t>(split_pos_relative_to_packet)), pkt_payload.end()};

    // second packet
    Packet second_packet = create_packet_from(pkt_view, part2);
    second_packet.action.action = PacketAction::Action::SEND;
    second_packet.action.packet_id = 0;

    tcphdr* tcp = static_cast<tcphdr*>(second_packet.transport_hdr());
    tcp->seq += htonl(part1.size());
    tcp->check = 0;
    tcp->check = calc_tcp_checksum(second_packet);

    // first packet
    pkt.action.action = PacketAction::Action::DROP_AND_SEND;
    pkt.packet.resize(pkt.packet.size() - part2.size());

    tcp = static_cast<tcphdr*>(pkt.transport_hdr());
    pkt.network_hdr()->tot_len = htons(static_cast<std::uint16_t>((pkt.network_hdr()->ihl * 4) + (tcp->doff * 4) + pkt.payload().size()));
    tcp->check = 0;
    tcp->check = calc_tcp_checksum(pkt);

    vec.insert(iter + 1, std::move(second_packet));
    return true;
}
bool HttpHostModifier::matches(const std::uint8_t l4_proto, const L7Proto l7_proto) const
{
    return l7_proto == L7Proto::HTTP && l4_proto == IPPROTO_TCP;
}
