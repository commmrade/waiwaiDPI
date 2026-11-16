//
// Created by klewy on 8/25/26.
//

#include "checksum.hpp"
#include <cstring>
#include <stdexcept>

void calc_packet_checksum(Packet &pkt)
{
    if (pkt.network_hdr()->protocol == IPPROTO_TCP) {
        auto *tcp = static_cast<tcphdr *>(pkt.transport_hdr());
        tcp->check = 0;
        tcp->check = calc_transport_checksum(pkt);
    } else {
        auto* udp = static_cast<udphdr*>(pkt.transport_hdr());
        udp->check = 0;
        udp->check = calc_transport_checksum(pkt);
    }
}

std::uint16_t calc_transport_checksum(const Packet &pkt)
{
    struct pseudo_hdr
    {
        std::uint32_t src;
        std::uint32_t dst;
        std::uint8_t zero;
        std::uint8_t proto;
        std::uint16_t len;
    } __attribute__((packed));

    const auto pkt_hdr_size = static_cast<std::size_t>(pkt.payload_offset - pkt.transport_offset);
    const auto payload = pkt.payload();

    pseudo_hdr phdr{};
    phdr.src = pkt.network_hdr()->saddr;
    phdr.dst = pkt.network_hdr()->daddr;
    phdr.zero = 0;
    phdr.proto = pkt.network_hdr()->protocol;
    phdr.len = htons(static_cast<std::uint16_t>(pkt_hdr_size + payload.size()));

    std::uint32_t sum = 0;

    auto add_bytes = [&sum](const char *data, std::size_t len) {
        std::size_t i = 0;
        for (; i + 1 < len; i += 2) {
            std::uint16_t word = 0;
            std::memcpy(&word, data + i, 2);
            sum += ntohs(word);
        }
        if (i < len) {
            auto const word = static_cast<std::uint16_t>(static_cast<std::uint8_t>(data[i]) << 8);
            sum += word;
        }
    };

    add_bytes(reinterpret_cast<const char *>(&phdr), sizeof(phdr));
    add_bytes(reinterpret_cast<const char *>(pkt.transport_hdr()), pkt_hdr_size);
    add_bytes(payload.data(), payload.size());

    while (sum >> 16) { sum = (sum & 0xFFFF) + (sum >> 16); }

    return htons(static_cast<std::uint16_t>(~sum));
}