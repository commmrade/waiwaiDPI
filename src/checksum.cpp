//
// Created by klewy on 8/25/26.
//

#include "checksum.hpp"

#include <cstring>

std::uint16_t calc_tcp_checksum(const Packet &pkt)
{
    struct pseudo_hdr
    {
        std::uint32_t src;
        std::uint32_t dst;
        std::uint8_t zero;
        std::uint8_t proto;
        std::uint16_t tcp_len;
    } __attribute__((packed));

    const auto* tcp = static_cast<const tcphdr*>(pkt.transport_hdr());
    const auto payload = pkt.payload();

    pseudo_hdr phdr{};
    phdr.src = pkt.network_hdr()->saddr;
    phdr.dst = pkt.network_hdr()->daddr;
    phdr.zero = 0;
    phdr.proto = IPPROTO_TCP;
    phdr.tcp_len = htons(static_cast<std::uint16_t>((tcp->doff * 4) + payload.size()));

    std::uint32_t sum = 0;

    auto add_bytes = [&sum](const char *data, std::size_t len) {
        std::size_t i = 0;
        for (; i + 1 < len; i += 2) {
            std::uint16_t word;
            std::memcpy(&word, data + i, 2);
            sum += ntohs(word);
        }
        if (i < len) {
            std::uint16_t word = static_cast<std::uint8_t>(data[i]) << 8;
            sum += word;
        }
    };

    add_bytes(reinterpret_cast<const char *>(&phdr), sizeof(phdr));
    add_bytes(reinterpret_cast<const char *>(tcp), tcp->doff * 4);
    add_bytes(payload.data(), payload.size());

    while (sum >> 16) { sum = (sum & 0xFFFF) + (sum >> 16); }

    return htons(static_cast<std::uint16_t>(~sum));
}