//
// Created by klewy on 8/15/26.
//

#ifndef WAIWAIDPI_PACKET_HPP
#define WAIWAIDPI_PACKET_HPP
#include "protocol.hpp"


#include <cstdint>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <optional>
#include <span>
#include <stdexcept>
#include <variant>


struct PacketView
{
    std::span<const char> packet;
    std::span<const char> payload;

    const iphdr *network_hdr{ nullptr };
    std::variant<const tcphdr *, const udphdr *> transport_hdr;

    L7Proto payload_proto{ L7Proto::UNKNOWN };
    bool is_payload_reasm{
        false
    };// that means payload is incomplete, complete payload is fragmented inside Connection class

    [[nodiscard]] std::uint16_t get_source_port() const;
    [[nodiscard]] std::uint16_t get_dest_port() const;
    [[nodiscard]] std::optional<std::uint32_t> get_seq() const;
    [[nodiscard]] std::size_t transport_hdr_len() const;
};

[[nodiscard]] PacketView parse_packet(std::span<const char> packet);

#endif// WAIWAIDPI_PACKET_HPP
