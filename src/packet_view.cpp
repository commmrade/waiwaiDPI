//
// Created by klewy on 8/15/26.
//

#include "packet_view.hpp"

#include <cstring>

std::uint16_t PacketView::get_source_port() const
{
    switch (network_hdr->protocol) {
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
    switch (network_hdr->protocol) {
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
std::optional<std::uint32_t> PacketView::get_seq() const
{
    switch (network_hdr->protocol) {
    case IPPROTO_TCP: {
        const auto *tcph = std::get<const tcphdr *>(transport_hdr);
        return ntohl(tcph->seq);
        break;
    }
    default: {
        return std::nullopt;
    }
    }
}
std::size_t PacketView::transport_hdr_len() const
{
    switch (network_hdr->protocol) {
    case IPPROTO_TCP: {
        const auto *tcph = std::get<const tcphdr *>(transport_hdr);
        return tcph->doff * 4;
        break;
    }
    case IPPROTO_UDP: {
        return sizeof(udphdr);
    }
    default: {
        return 0;
    }
    }
}
Packet create_packet(const PacketView &view)
{
    Packet pkt;
    pkt.packet.insert(pkt.packet.end(), view.packet.begin(), view.packet.end());

    auto *iph = reinterpret_cast<iphdr *>(pkt.packet.data());// NOLINT
    pkt.network_offset = 0;
    pkt.transport_offset = iph->ihl * 4;
    switch (iph->protocol) {
    case IPPROTO_TCP: {
        const auto* tcp = reinterpret_cast<const tcphdr*>(std::next(pkt.packet.data(), pkt.transport_offset));
        pkt.payload_offset = (iph->ihl * 4) + (tcp->doff * 4);
        break;
    }
    case IPPROTO_UDP: {
        const auto *udph = reinterpret_cast<const udphdr *>(std::next(pkt.packet.data(), pkt.transport_offset));// NOLINT
        pkt.payload_offset = (iph->ihl * 4) + sizeof(udphdr);
        break;
    }
    default: {
        throw std::runtime_error("This transport layer protocol is not supported. How?");
    }
    }

    pkt.payload_proto = view.payload_proto;
    pkt.action.packet_id = view.packet_id;

    return pkt;
}

Packet create_packet_from(const PacketView& pkt, std::span<const char> new_payload) {
    Packet res = create_packet(pkt);
    res.packet.resize(static_cast<std::size_t>(res.payload_offset) + new_payload.size());
    std::memcpy(std::next(res.packet.data(), res.payload_offset), new_payload.data(), new_payload.size());
    res.network_hdr()->tot_len = htons(static_cast<std::uint16_t>(pkt.network_hdr->ihl * 4 + pkt.transport_hdr_len() + new_payload.size()));
    return res;
}

PacketView parse_packet_view(std::span<const char> packet)
{
    PacketView pkt;
    pkt.packet = packet;

    const auto *iph = reinterpret_cast<const iphdr *>(packet.data());// NOLINT
    pkt.network_hdr = iph;

    switch (iph->protocol) {
    case IPPROTO_TCP: {
        const auto *tcph = reinterpret_cast<const tcphdr *>(std::next(packet.data(), iph->ihl * 4));// NOLINT
        pkt.transport_hdr.emplace<const tcphdr *>(tcph);
        break;
    }
    case IPPROTO_UDP: {
        const auto *udph = reinterpret_cast<const udphdr *>(std::next(packet.data(), iph->ihl * 4));// NOLINT
        pkt.transport_hdr.emplace<const udphdr *>(udph);
        break;
    }
    default: {
        throw std::runtime_error("This transport layer protocol is not supported. How?");
    }
    }

    const auto headers_len = (pkt.network_hdr->ihl * 4) + (pkt.transport_hdr_len());
    pkt.payload = std::span<const char>{ std::next(packet.data(), static_cast<std::ptrdiff_t>(headers_len)),
        packet.size() - headers_len };

    return pkt;
}

PacketView parse_packet_view(const Packet &packet)
{
    PacketView pkt;
    pkt.packet = packet.packet;
    pkt.packet_id = packet.action.packet_id;

    pkt.network_hdr = packet.network_hdr();

    switch (pkt.network_hdr->protocol) {
    case IPPROTO_TCP: {
        pkt.transport_hdr.emplace<const tcphdr *>(static_cast<const tcphdr*>(packet.transport_hdr()));
        break;
    }
    case IPPROTO_UDP: {
        pkt.transport_hdr.emplace<const udphdr *>(static_cast<const udphdr*>(packet.transport_hdr()));
        break;
    }
    default: {
        throw std::runtime_error("This transport layer protocol is not supported. How?");
    }
    }

    const auto headers_len = (pkt.network_hdr->ihl * 4) + (pkt.transport_hdr_len());
    pkt.payload_proto = packet.payload_proto;
    pkt.payload = packet.payload();

    return pkt;
}