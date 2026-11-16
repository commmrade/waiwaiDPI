//
// Created by klewy on 11/17/26.
//

#ifndef WAIWAIDPI_FOOLINGS_HPP
#define WAIWAIDPI_FOOLINGS_HPP

#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_TRACE
#include "spdlog/spdlog.h"
#include "net/packet_view.hpp"
#include <ranges>

namespace fooling {
bool timestamp_val_offset(Packet &packet, const int offset);

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
        for (auto& packet : packets) {
            auto* udp = static_cast<udphdr*>(packet.transport_hdr());
            udp->check = 0;
            udp->check = htonl(rand() % 256);
        }
    }
}

template<std::ranges::range Range>
void tcp_md5(Range& packets)
{
    // Mind that when you add an option it should be padded (with EOL Kind 0) for the size of a packet to be at 32-bit word boundary
    // there may be padding between options to align values that are inside the options to 16-bit,32-bit boundary

    for (auto& packet : packets) {
        const auto tcp_opts_start = packet.transport_offset + sizeof(tcphdr);
        auto tcp_opts_end = packet.payload_offset;
        const auto tcp_opts_size = tcp_opts_end - tcp_opts_start;


        // i wanna modify it in-place
        // so first I should get rid of all the padding in the end
        // then i wanna insert the tcp_md5 options
        // and padd options again
        // as an optimizaion later, i might just extend the padding as a first step and then write over the padding, so it is less steps

        assert(tcp_opts_end <= packet.packet.size());
        std::span<const char> tcp_opts{packet.packet.data() + tcp_opts_start, tcp_opts_size};
        int zeros = 0;
        for (auto i = static_cast<int>(tcp_opts.size() - 1); i >= 0; --i) {
            zeros += static_cast<int>(tcp_opts[i]) == 0;
        }

        // extend TCP opts.
        constexpr auto TCP_MD5_OPT_SIZE = 18;
        const int extend_n = TCP_MD5_OPT_SIZE + (4 - (zeros % 4));
        auto md5_iter = packet.packet.insert(packet.packet.begin() + tcp_opts_end, extend_n, 0);
        tcp_opts_end += extend_n;

        // overwrite TCP opts

        constexpr auto TCP_MD5_OPT_KIND = 19;
        constexpr auto TCP_MD5_OPT_LEN = 18;

        *md5_iter = TCP_MD5_OPT_KIND; // Set Kind to TCP MD5
        ++md5_iter;

        *md5_iter = TCP_MD5_OPT_LEN;
        ++md5_iter;

        const auto end_opts_iter = packet.packet.begin() + tcp_opts_end;
        for (; md5_iter != end_opts_iter; ++md5_iter) {
            *md5_iter = 0;
        }

        auto* ip = static_cast<iphdr*>(packet.network_hdr());
        auto* tcp = static_cast<tcphdr *>(packet.transport_hdr());

        packet.payload_offset = tcp_opts_end;
        tcp->doff += extend_n / 4;
        SPDLOG_DEBUG("INSERTED {} EXTEND n", extend_n);
    }
}

} // namespace fooling

#endif// WAIWAIDPI_FOOLINGS_HPP
