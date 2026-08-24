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
#include <vector>


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

    std::uint32_t packet_id;

    [[nodiscard]] std::uint16_t get_source_port() const;
    [[nodiscard]] std::uint16_t get_dest_port() const;
    [[nodiscard]] std::optional<std::uint32_t> get_seq() const;
    [[nodiscard]] std::size_t transport_hdr_len() const;
};

struct PacketAction
{
    std::uint32_t packet_id;
    enum class Action : std::uint8_t {
        ACCEPT,// NF_ACCEPT(packet_id)
        DROP,// NF_DROP(packet_id)
        DROP_AND_SEND,// NF_DROP(packet_id) + send(raw_sock, ...)
        SEND// send(raw_sock, ...)
    } action;
};

/// A struct for Owned packets. Heavily used with modifiers
struct Packet
{
    std::vector<char> packet;

    PacketAction action{ .packet_id = 0, .action = PacketAction::Action::SEND };

    Packet() = default;
    explicit Packet(const PacketView &view)
        : packet(view.packet.begin(), view.packet.end()), action(view.packet_id, PacketAction::Action::ACCEPT)
    {}
};

[[nodiscard]] PacketView parse_packet(std::span<const char> packet);
[[nodiscard]] PacketView parse_packet(const Packet &packet);

#endif// WAIWAIDPI_PACKET_HPP
