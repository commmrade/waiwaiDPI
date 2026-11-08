//
// Created by klewy on 10/12/26.
//

#ifndef WAIWAIDPI_COMMON_HPP
#define WAIWAIDPI_COMMON_HPP

#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_TRACE
#include "net/packet_view.hpp"
#include "net/protocol.hpp"
#include "net/quic.hpp"
#include <spdlog/spdlog.h>
#include <algorithm>
#include <span>

bool timestamp_val_offset(Packet &packet, const int offset);
std::vector<Packet>
    segmentize(std::span<const char> full_payload, unsigned long mss, const Packet &orig_packet, unsigned start_seq);


template<std::ranges::range Range>
std::vector<char> concat_sorted(Range& packets)
{
    std::vector<char> full_payload;

    std::size_t payload_size = 0;
    for (const auto& pkt : packets) {
        payload_size += pkt.payload().size();
    }

    full_payload.reserve(payload_size);

    for (const auto pkt : packets) {
        const auto& payload = pkt.payload();
        full_payload.insert(full_payload.end(), payload.begin(), payload.end());
    }

    return full_payload;
}

template<std::ranges::range Range>
std::vector<char> concat_quic(Range& packets)
{
    const auto full_payload = concat_sorted(packets);
    std::span<const std::uint8_t> quic_packets{ reinterpret_cast<const std::uint8_t *>(full_payload.data()),
            full_payload.size(), };

    std::map<std::uint64_t, std::vector<std::uint8_t>> tls;

    std::span<const std::uint8_t> quic;
    while (!(quic = extract_quic(quic_packets)).empty()) { //NOLINT
        const auto decrypted_vec = decrypt_quic(quic);
        const auto decrypted = std::span<const std::uint8_t>{decrypted_vec};
        const auto hdr = parse_quic(decrypted);

        auto payload = decrypted.subspan(hdr.payload_offset);
        if (!parse_payload_quic(payload, tls)) {
            break;
        }
    }

    const auto client_hello = quic_reassemble(tls);
    std::vector<char> ret(client_hello.begin(), client_hello.end());
    return ret;
}

template<std::ranges::range Range>
std::vector<char> concat_tcp(Range& packets)
{
    bool is_empty = false;
    if constexpr (requires { packets.empty(); }) {
        is_empty = packets.empty();
    } else {
        const auto &base = packets.base();
        is_empty = base.empty();
    }

    if (is_empty) { return {}; }

    struct Segment
    {
        std::uint32_t seq{};
        std::span<const char> data;
    };

    std::vector<Segment> segs;
    segs.reserve(std::distance(packets.begin(), packets.end()));
    for (const auto &pkt : packets) {
        segs.push_back({ parse_packet_view(pkt).get_seq().value(), pkt.payload() });
    }
    if (segs.empty()) { return {}; }

    const auto seq_lt = [](const std::uint32_t lhs, const std::uint32_t rhs) {
        return static_cast<std::int32_t>(lhs - rhs) < 0;
    };
    std::uint32_t base = segs.front().seq;
    std::size_t payload_size = 0;
    for (const auto &seg : segs) {
        if (seq_lt(seg.seq, base)) { base = seg.seq; }
        payload_size += seg.data.size();
    }

    std::ranges::stable_sort(segs, {}, [base](const Segment &seg) { return seg.seq - base; });

    std::vector<char> full_payload;
    full_payload.reserve(payload_size);

    for (const auto &seg : segs) {
        const std::size_t rel = seg.seq - base;
        auto data = seg.data;

        if (rel + data.size() <= full_payload.size()) { continue; }// целиком перекрыт (или пустой)
        if (rel > full_payload.size()) { break; }// дырка в потоке
        data = data.subspan(full_payload.size() - rel);// срезаем перекрытие спереди

        full_payload.insert(full_payload.end(), data.begin(), data.end());
    }

    return full_payload;
}

template<std::ranges::range Range>
std::vector<char> concat(Range& packets, const L7Proto payload_proto)
{
    if (packets.front().network_hdr()->protocol == IPPROTO_TCP) {
        return concat_tcp(packets);
    } else if (payload_proto == L7Proto::QUIC) {
        return concat_quic(packets);
    } else {
        SPDLOG_DEBUG("Did not concat anything");
        return {};
    }
}

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
        SPDLOG_ERROR("Bad Checksum for protocols other than TCP hasn't been implemented yet");
    }
}


#endif// WAIWAIDPI_COMMON_HPP
