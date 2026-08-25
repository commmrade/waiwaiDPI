//
// Created by klewy on 8/24/26.
//

#ifndef WAIWAIDPI_MODIFIER_HPP
#define WAIWAIDPI_MODIFIER_HPP

#include "../packet_view.hpp"


#include <cstring>
#include <vector>

static std::uint16_t tcp_calc_cksum(const iphdr* ip, const tcphdr* tcp, std::span<const char> payload) {
    struct pseudo_hdr {
        std::uint32_t src;
        std::uint32_t dst;
        std::uint8_t zero;
        std::uint8_t proto;
        std::uint16_t tcp_len;
    } __attribute__((packed));

    pseudo_hdr phdr{};
    phdr.src = ip->saddr;
    phdr.dst = ip->daddr;
    phdr.zero = 0;
    phdr.proto = IPPROTO_TCP;
    phdr.tcp_len = htons(static_cast<std::uint16_t>((tcp->doff * 4) + payload.size()));

    std::uint32_t sum = 0;

    auto add_bytes = [&sum](const char* data, std::size_t len) {
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

    add_bytes(reinterpret_cast<const char*>(&phdr), sizeof(phdr));
    add_bytes(reinterpret_cast<const char*>(tcp), tcp->doff * 4);
    add_bytes(payload.data(), payload.size());

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return htons(static_cast<std::uint16_t>(~sum));
}

static Packet construct_packet_from(std::span<const char> payload, const PacketView& pkt) {
    Packet res = create_packet(pkt);
    res.packet.resize(res.payload_offset + payload.size());
    std::memcpy(res.packet.data() + res.payload_offset, payload.data(), payload.size());
    res.network_hdr()->tot_len = htons(pkt.network_hdr->ihl * 4 + pkt.transport_hdr_len() + payload.size());
    return res;
}

class Modifier
{
public:
    virtual ~Modifier() = default;
    virtual bool modify(std::vector<Packet>& vec) = 0; // true - successfully processed, false - did nothing
    [[nodiscard]] virtual bool matches(const std::uint8_t l4_proto, const L7Proto l7_proto) const = 0; // used to make sure that these packets can be processed by this modifier
};


#endif// WAIWAIDPI_MODIFIER_HPP
