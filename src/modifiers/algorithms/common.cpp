//
// Created by klewy on 10/12/26.
//

#include "common.hpp"
#include "checksum.hpp"
#include <algorithm>
#include <cassert>
#include <stdexcept>

bool timestamp_val_offset(Packet &packet, const int offset)
{
    auto *tcp = static_cast<tcphdr *>(packet.transport_hdr());
    std::span<char> tcp_bytes{ static_cast<char *>(packet.transport_hdr()), static_cast<std::size_t>(tcp->doff * 4) };
    if (tcp_bytes.size() <= sizeof(tcphdr)) {
        return false;// no TCP options
    }

    constexpr static std::uint8_t TS_OPT_KIND = 8;
    constexpr static std::uint8_t TS_OPT_SIZE = 10;

    tcp_bytes = tcp_bytes.subspan(sizeof(tcphdr));
    while (!tcp_bytes.empty()) {
        if (tcp_bytes.size() < 2) {
            return false;// not enough bytes to get KIND,LENGTH
        }

        const auto kind = static_cast<std::uint8_t>(tcp_bytes[0]);
        if (kind == 1) {// no-op
            tcp_bytes = tcp_bytes.subspan(1);
            continue;
        }

        const auto size = static_cast<std::uint8_t>(tcp_bytes[1]);
        if (kind != TS_OPT_KIND) {
            if (tcp_bytes.size() < size) { return false; }

            tcp_bytes = tcp_bytes.subspan(size);// size includes kind,length + payload
            continue;
        }

        if (size < TS_OPT_SIZE || size > TS_OPT_SIZE) { return false; }

        auto *tval = std::start_lifetime_as<std::uint32_t>(std::next(tcp_bytes.data(), 2));
        auto *tresp = std::start_lifetime_as<std::uint32_t>(std::next(tcp_bytes.data(), 2 + sizeof(*tval)));

        *tval = htonl(static_cast<std::uint32_t>(static_cast<int>(ntohl(*tval)) + offset));
        *tresp = htonl(static_cast<std::uint32_t>(static_cast<int>(ntohl(*tresp)) + offset));

        break;
    }

    return true;
}
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
std::vector<char> concat(std::vector<Packet> packets, const bool skip_fake)
{
    if (packets.front().network_hdr()->protocol == IPPROTO_TCP) {
        std::ranges::stable_sort(packets, [](const Packet &lhs, const Packet &rhs) {
            const auto *lhs_tcp = static_cast<const tcphdr *>(lhs.transport_hdr());
            const auto *rhs_tcp = static_cast<const tcphdr *>(rhs.transport_hdr());

            const uint32_t lhs_seq = ntohl(lhs_tcp->seq);
            const uint32_t rhs_seq = ntohl(rhs_tcp->seq);

            // Modular comparison (RFC 1982 / RFC 793 SEQ_LT): correct across wraparound
            return static_cast<int32_t>(lhs_seq - rhs_seq) < 0;
        });
    } else {
        throw std::logic_error("Cant concat non tcp segments yet");
    }

    std::vector<char> full_payload;
    for (const auto &pkt : packets) {
        if (skip_fake && pkt.is_fake_blob) {
            continue;// do not care about domains in fake blobs
        }

        const auto payload = pkt.payload();
        full_payload.insert(full_payload.end(), payload.begin(), payload.end());
    }

    return full_payload;
}