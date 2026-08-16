//
// Created by klewy on 8/15/26.
//

#include "packet_view.hpp"

std::uint16_t PacketView::get_source_port() const
{
    switch (transport_proto) {
    case IPPROTO_TCP: {
        const auto *tcph = std::get<const tcphdr *>(transport_hdr);
        return ntohs(tcph->source);
        break;
    }
    case IPPROTO_UDP: {
        const auto *udph = std::get<const udphdr *>(transport_hdr);
        return ntohs(udph->source);
        break;
    }
    default: {
        throw std::runtime_error("This transport layer protocol is not supported");
    }
    }
}
std::uint16_t PacketView::get_dest_port() const
{
    switch (transport_proto) {
    case IPPROTO_TCP: {
        const auto *tcph = std::get<const tcphdr *>(transport_hdr);
        return ntohs(tcph->dest);
        break;
    }
    case IPPROTO_UDP: {
        const auto *udph = std::get<const udphdr *>(transport_hdr);
        return ntohs(udph->dest);
        break;
    }
    default: {
        throw std::runtime_error("This transport layer protocol is not supported");
    }
    }
}
std::uint32_t PacketView::get_seq() const
{
    switch (transport_proto) {
    case IPPROTO_TCP: {
        const auto *tcph = std::get<const tcphdr *>(transport_hdr);
        return ntohl(tcph->seq);
        break;
    }
    default: {
        return 0;
    }
    }
}

PacketView parse_packet(std::span<const char> packet)
{
    PacketView pkt;
    pkt.packet = packet;

    const auto *iph = reinterpret_cast<const iphdr *>(packet.data());// NOLINT
    pkt.network_hdr = iph;
    pkt.transport_proto = iph->protocol;

    switch (iph->protocol) {
    case IPPROTO_TCP: {
        const auto *tcph = reinterpret_cast<const tcphdr *>(std::next(packet.data(), iph->ihl * 4));// NOLINT
        pkt.transport_hdr.emplace<const tcphdr *>(tcph);

        pkt.headers_len = iph->ihl * 4 + tcph->doff * 4;
        break;
    }
    case IPPROTO_UDP: {
        const auto *udph = reinterpret_cast<const udphdr *>(std::next(packet.data(), iph->ihl * 4));// NOLINT
        pkt.transport_hdr.emplace<const udphdr *>(udph);

        pkt.headers_len = iph->ihl * 4 + sizeof(*udph);
        break;
    }
    default: {
        throw std::runtime_error("This transport layer protocol is not supported. How?");
    }
    }

    pkt.payload = std::span<const char>{ std::next(packet.data(), static_cast<std::ptrdiff_t>(pkt.headers_len)),
        packet.size() - pkt.headers_len };

    return pkt;
}