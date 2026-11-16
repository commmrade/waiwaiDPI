//
// Created by klewy on 10/12/26.
//

#include "common.hpp"
#include "net/checksum.hpp"
#include <cassert>

std::vector<Packet>
    segmentize(std::span<const char> full_payload, unsigned long mss, const Packet &orig_packet, unsigned start_seq)
{
    auto packet_view = parse_packet_view(orig_packet);
    std::span<const char> payload{ full_payload };

    std::vector<Packet> splitted;
    splitted.reserve((full_payload.size() / mss) + 1);

    while (!payload.empty()) {
        const auto chunk_size = std::min<std::size_t>(payload.size(), mss);

        auto new_packet = create_packet_from(packet_view, payload.subspan(0, chunk_size));
        new_packet.is_fake_blob = orig_packet.is_fake_blob;
        new_packet.action.action = PacketAction::Action::SEND;
        new_packet.action.packet_id = 0;

        auto *tcp = static_cast<tcphdr *>(new_packet.transport_hdr());
        tcp->seq = htonl(start_seq);
        calc_packet_checksum(new_packet);

        splitted.push_back(std::move(new_packet));

        payload = payload.subspan(chunk_size);
        start_seq += chunk_size;
    }

    if (orig_packet.action.action == PacketAction::Action::SEND) {
        splitted.front().action.action = PacketAction::Action::SEND;
    } else {
        splitted.front().action.action = PacketAction::Action::DROP_AND_SEND;
        splitted.front().action.packet_id = orig_packet.action.packet_id;
    }

    return splitted;
}