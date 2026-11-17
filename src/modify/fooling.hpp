//
// Created by klewy on 11/17/26.
//

#ifndef WAIWAIDPI_FOOLINGS_HPP
#define WAIWAIDPI_FOOLINGS_HPP

#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_TRACE
#include "net/checksum.hpp"
#include "net/packet_view.hpp"
#include "spdlog/spdlog.h"
#include <cstring>
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

constexpr auto TCP_MD5_OPT_KIND = 19;
constexpr auto TCP_MD5_OPT_LEN = 18;
#pragma pack(push, 1)
struct TcpMd5Opt
{
    std::uint8_t kind{TCP_MD5_OPT_KIND};
    std::uint8_t length{TCP_MD5_OPT_LEN};
    std::array<char, TCP_MD5_OPT_LEN - 2> data{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
};
#pragma pack(pop)

static std::size_t count_eols(std::span<const char> opts)
{
    std::size_t ret = 0;
    while (!opts.empty()) {
        const auto kind = static_cast<std::uint8_t>(opts[0]);
        if (kind == 0) {
            ++ret;
            opts = opts.subspan(1);
            continue;
        } else if (kind == 1) {
            opts = opts.subspan(1);
            continue;
        }

        const auto len = static_cast<std::uint8_t>(opts[1]);
        if (opts.size() < len) {
            break;
        }

        opts = opts.subspan(len);
    }

    return ret;
}

template<std::ranges::range Range>
void tcp_md5(Range& packets)
{
    for (auto& packet : packets) {
        const auto tcp_opts_start = packet.transport_offset + sizeof(tcphdr);
        const auto tcp_opts_end = packet.payload_offset;
        const auto tcp_opts_size = tcp_opts_end - tcp_opts_start;
        std::span<const char> tcp_opts{std::next(packet.packet.data(), tcp_opts_start), tcp_opts_size};

        // Check how many EOL options
        const auto eol_count = count_eols(tcp_opts);
        constexpr std::size_t TCP_OPTIONS_MAX_SIZE = 40;

        const std::size_t used     = tcp_opts_size - eol_count;                  // real options, no padding
        const std::size_t new_size = (used + TCP_MD5_OPT_LEN + 3) & ~std::size_t{3};

        if (new_size > TCP_OPTIONS_MAX_SIZE) {
            SPDLOG_ERROR("TCP options too long to add MD5 option");
            continue;                                                            // not return
        }

        const std::size_t extend_n = new_size - tcp_opts_size;                   // always a multiple of 4

        // Extend the options by extend_n and go backwards EOL count bytes to get to the start of MD5 option, which is after the last non-EOL option
        auto md_iter = packet.packet.insert(std::next(packet.packet.begin(), packet.payload_offset), extend_n, 0);
        md_iter -= eol_count;

        TcpMd5Opt const opt{};
        std::memcpy(std::addressof(*md_iter), &opt, sizeof(opt));
        // Fill the MD5 option. Padding at the end stays there

        // Update all the fields
        packet.payload_offset += extend_n;
        packet.network_hdr()->tot_len = htons(ntohs(packet.network_hdr()->tot_len) + extend_n);
        auto* tcp = static_cast<tcphdr*>(packet.transport_hdr());
        tcp->doff += extend_n / 4;
        calc_packet_checksum(packet);
    }
}

} // namespace fooling

#endif// WAIWAIDPI_FOOLINGS_HPP
