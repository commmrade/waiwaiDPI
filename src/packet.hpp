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
#include <span>
#include <stdexcept>
#include <variant>


struct Packet
{
    std::span<const char> packet;
    const iphdr* network_hdr{nullptr};
    int transport_proto{IPPROTO_TCP};
    std::variant<const tcphdr *, const udphdr *> transport_hdr;
    std::size_t headers_len;
    L7Proto payload_proto{L7Proto::UNKNOWN};
    std::span<const char> payload;

    Packet() = default;
    explicit Packet(std::span<const char> packet)
    {
        this->packet = packet;

        const auto* iph = reinterpret_cast<const iphdr*>(packet.data()); //NOLINT
        network_hdr = iph;
        transport_proto = iph->protocol;

        switch (iph->protocol) {
            case IPPROTO_TCP: {
                const auto* tcph = reinterpret_cast<const tcphdr*>(std::next(packet.data(), iph->ihl * 4)); //NOLINT
                transport_hdr.emplace<const tcphdr*>(tcph);

                headers_len = iph->ihl * 4 + tcph->doff * 4;
                break;
            }
            case IPPROTO_UDP: {
                const auto* udph = reinterpret_cast<const udphdr*>(std::next(packet.data(), iph->ihl * 4)); //NOLINT
                transport_hdr.emplace<const udphdr*>(udph);

                headers_len = iph->ihl * 4 + sizeof(*udph);
                break;
            }
            default: {
                throw std::runtime_error("This transport layer protocol is not supported. How?");
            }
        }

        payload = std::span<const char>{std::next(packet.data(), static_cast<std::ptrdiff_t>(headers_len)), packet.size() - headers_len};
    }

    [[nodiscard]] std::uint16_t get_source_port() const
    {
        switch (transport_proto) {
        case IPPROTO_TCP: {
            const auto* tcph = std::get<const tcphdr*>(transport_hdr);
            return ntohs(tcph->source);
            break;
        }
        case IPPROTO_UDP: {
            const auto* udph = std::get<const udphdr*>(transport_hdr);
            return ntohs(udph->source);
            break;
        }
        default: {
            throw std::runtime_error("This transport layer protocol is not supported");
        }
        }
    }

    [[nodiscard]] std::uint16_t get_dest_port() const
    {
        switch (transport_proto) {
        case IPPROTO_TCP: {
            const auto* tcph = std::get<const tcphdr*>(transport_hdr);
            return ntohs(tcph->dest);
            break;
        }
        case IPPROTO_UDP: {
            const auto* udph = std::get<const udphdr*>(transport_hdr);
            return ntohs(udph->dest);
            break;
        }
        default: {
            throw std::runtime_error("This transport layer protocol is not supported");
        }
        }
    }
};

#endif// WAIWAIDPI_PACKET_HPP
