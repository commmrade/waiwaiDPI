//
// Created by klewy on 10/12/26.
//

#ifndef WAIWAIDPI_COMMON_HPP
#define WAIWAIDPI_COMMON_HPP

#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_TRACE
#include <spdlog/spdlog.h>
#include "net/packet_view.hpp"
#include <span>

bool timestamp_val_offset(Packet &packet, const int offset);
std::vector<Packet>
    segmentize(std::span<const char> full_payload, unsigned long mss, const Packet &orig_packet, unsigned start_seq);

std::vector<char> concat(std::span<const Packet> packets, const bool skip_fake = true);
std::vector<char> concat_sorted(std::span<const Packet> packets, const bool skip_fake = true);


template<std::ranges::range Range>
void ipv4_ttl(Range& packets, const std::uint8_t ttl)
{
    for (auto& packet : packets) {
        packet.network_hdr()->ttl = ttl;
    }
}

template<std::ranges::range Range>
void timestamp_offset(Range& packets, const int off)
{
    for (auto &packet : packets) {
        if (!timestamp_val_offset(packet, off)) {
            SPDLOG_WARN("Failed to offset timestamp");
        }

        auto *tcp = static_cast<tcphdr *>(packet.transport_hdr());
        calc_packet_checksum(packet);
    }
}

template<std::ranges::range Range>
void sequence_offset(Range& packets, const int off)
{
    for (auto &packet : packets) {
        auto *tcp = static_cast<tcphdr *>(packet.transport_hdr());
        tcp->seq =
            htonl(static_cast<std::uint32_t>(static_cast<int>(ntohl(tcp->seq)) + off));
        calc_packet_checksum(packet);
    }
}

template<std::ranges::range Range>
void badchecksum(Range& packets, const int l4_proto)
{
    if (l4_proto == IPPROTO_TCP) {
        for (auto &packet : packets) {
            auto *tcp = static_cast<tcphdr *>(packet.transport_hdr());
            tcp->check = 0;
            tcp->check = htonl(rand() % 256);
        }
    } else {
        SPDLOG_ERROR("Bad Checksum for protocols other than TCP hasn't been implemented yet");
    }
}


#endif// WAIWAIDPI_COMMON_HPP
