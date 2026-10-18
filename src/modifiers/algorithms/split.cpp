//
// Created by klewy on 9/24/26.
//

#include "split.hpp"
#include "checksum.hpp"
#include "modifiers/markers.hpp"
#include <algorithm>
#include <cstring>
#include <iostream>
#include <print>
#include <ranges>
#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_TRACE
#include <spdlog/spdlog.h>

namespace helpers {

std::size_t do_operation(const std::size_t start, const Position::Operation oper, const std::size_t offset)
{
    std::size_t ret = start;
    switch (oper) {
    case Position::Operation::Add: {
        ret += offset;
        break;
    }
    case Position::Operation::Subtract: {
        ret -= offset;
        break;
    }
    default:
        break;
    }

    return ret;
};


static bool seq_lt(const Packet &lhs, const Packet &rhs)
{
    const auto sa_val = ntohl(static_cast<const tcphdr *>(lhs.transport_hdr())->seq);
    const auto sb_val = ntohl(static_cast<const tcphdr *>(rhs.transport_hdr())->seq);
    return static_cast<int32_t>(sa_val - sb_val) < 0;
}

static std::pair<std::vector<Packet>::iterator, std::size_t>
    find_packet_by_offset(std::vector<Packet> &packets, std::size_t split_pos, bool handle_fake)
{
    std::vector<std::size_t> idx;
    for (std::size_t i = 0; i < packets.size(); ++i) {
        if (packets[i].is_fake_blob == handle_fake) {
            idx.push_back(i);
        }
    }

    std::ranges::stable_sort(idx, [&](std::size_t lhs, std::size_t rhs) { return seq_lt(packets[lhs], packets[rhs]); });

    std::size_t acc = 0;
    for (auto i : idx) {
        const auto sz = packets[i].payload().size();
        if (split_pos < acc + sz) {
            return { std::next(packets.begin(), static_cast<std::ptrdiff_t>(i)), split_pos - acc };
        }
        acc += sz;
    }
    return { packets.end(), 0 };
}

static void split_and_insert_packets_tcp(std::vector<Packet>::iterator iter,
    const std::size_t split_pos_relative_to_packet,
    std::vector<Packet> &packets)
{
    auto &pkt = *iter;
    const auto pkt_view = parse_packet_view(pkt);
    const auto pkt_payload = pkt.payload();
    // const std::span<const char> part1{pkt_payload.begin(), std::next(pkt_payload.begin(),
    // static_cast<std::ptrdiff_t>(split_pos_relative_to_packet))};
    const std::span<const char> part2{
        std::next(pkt_payload.begin(), static_cast<std::ptrdiff_t>(split_pos_relative_to_packet)), pkt_payload.end()
    };

    // Second packet
    Packet second = create_packet_from(pkt_view, part2);
    second.is_fake_blob = pkt.is_fake_blob;
    second.action.action = PacketAction::Action::SEND;
    second.action.packet_id = 0;

    auto *tcp = static_cast<tcphdr *>(second.transport_hdr());
    tcp->seq = htonl(ntohl(tcp->seq) + static_cast<std::uint32_t>(split_pos_relative_to_packet));
    calc_packet_checksum(second);

    // First packet
    // ACCEPT -> DROP_AND_SEND
    // DROP_AND_SEND -> DROP_AND_SEND
    // SEND -> SEND
    pkt.packet.resize(pkt.packet.size() - part2.size());
    if (pkt.action.action == PacketAction::Action::ACCEPT) { pkt.action.action = PacketAction::Action::DROP_AND_SEND; }

    tcp = static_cast<tcphdr *>(pkt.transport_hdr());
    auto *iph = pkt.network_hdr();

    iph->tot_len = htons((iph->ihl * 4) + (tcp->doff * 4) + static_cast<std::uint16_t>(pkt.payload().size()));
    calc_packet_checksum(pkt);

    packets.insert(iter + 1, std::move(second));
}

}// namespace helpers


std::expected<bool, std::string>
    split::split(std::vector<Packet> &packets, const SplitConfig &cfg, const Connection &conn)
{
    std::vector<char> full_payload;

    auto filtered_packets = std::ranges::views::filter(packets, [handle_fake = cfg.handle_fake](const Packet &packet) {
        return (handle_fake && packet.is_fake_blob) || (!handle_fake && !packet.is_fake_blob);
    });

    for (const auto &pkt : filtered_packets) {
        const auto payload = pkt.payload();
        full_payload.insert(full_payload.end(), payload.begin(), payload.end());
    }

    // split based on application protocol, each protocol have a unique set of usable markers
    return split(packets, cfg, full_payload, conn);
}

std::expected<bool, std::string> split::split(std::vector<Packet> &packets,
    const SplitConfig &cfg,
    const std::vector<char> &full_payload,
    const Connection &conn)
{
    // split based on application protocol, each protocol have a unique set of usable markers
    switch (const auto pl_proto = conn.payload_proto()) {
    case L7Proto::HTTP: {
        return split_http(packets, full_payload, cfg);
    }
    case L7Proto::TLS: {
        return split_tls(packets, full_payload, cfg);
    }
    default: {
        return split_other(packets, full_payload, cfg);
    }
    }
}

std::expected<bool, std::string>
    split::split_http(std::vector<Packet> &packets, const std::vector<char> &full_payload, const SplitConfig &cfg)
{
    const auto markers_res = find_markers(full_payload, L7Proto::HTTP);
    if (!markers_res.has_value()) { return std::unexpected{ "Could not parse markers" }; }
    const auto &marks = markers_res.value();

    std::size_t split_pos = 0;

    if (cfg.pos.get().arg == Markers::HOSTSTART_STR) {
        if (!marks.hoststart.has_value()) { return std::unexpected{ "Could not find 'hoststart'" }; }

        split_pos = helpers::do_operation(marks.hoststart.value(), cfg.pos.get().operation, cfg.pos.get().offset);
    } else if (cfg.pos.get().arg == Markers::HOSTEND_STR) {
        if (!marks.hostend.has_value()) { return std::unexpected{ "Could not find 'hostend'" }; }

        split_pos = helpers::do_operation(marks.hostend.value(), cfg.pos.get().operation, cfg.pos.get().offset);
    } else if (cfg.pos.get().arg == Markers::HOSTMID_STR) {
        if (!marks.hostmid.has_value()) { return std::unexpected{ "Could not find 'hostmid'" }; }

        split_pos = helpers::do_operation(marks.hostmid.value(), cfg.pos.get().operation, cfg.pos.get().offset);
    } else {
        const auto offset = cfg.pos.get().offset;
        split_pos = offset;
    }

    auto [iter, split_pos_relative_to_packet] = helpers::find_packet_by_offset(packets, split_pos, cfg.handle_fake);
    // split iter packet at split_pos_relative_to_packet
    if (split_pos_relative_to_packet == 0) {
        // already split naturally
        return { true };
    }

    helpers::split_and_insert_packets_tcp(iter, split_pos_relative_to_packet, packets);
    return { true };
}

std::expected<bool, std::string>
    split::split_tls(std::vector<Packet> &packets, const std::vector<char> &full_payload, const SplitConfig &cfg)
{
    const auto markers_res = find_markers(full_payload, L7Proto::TLS);
    if (!markers_res.has_value()) { return std::unexpected{ "Could not parse markers" }; }
    const auto &marks = markers_res.value();

    std::size_t split_pos = 0;
    if (cfg.pos.get().arg == Markers::HOSTSTART_STR) {
        if (!marks.hoststart.has_value()) { return std::unexpected{ "Could not find 'hoststart'" }; }

        split_pos = helpers::do_operation(marks.hoststart.value(), cfg.pos.get().operation, cfg.pos.get().offset);
    } else if (cfg.pos.get().arg == Markers::HOSTEND_STR) {
        if (!marks.hostend.has_value()) { return std::unexpected{ "Could not find 'hostend'" }; }

        split_pos = helpers::do_operation(marks.hostend.value(), cfg.pos.get().operation, cfg.pos.get().offset);
    } else if (cfg.pos.get().arg == Markers::HOSTMID_STR) {
        if (!marks.hostmid.has_value()) { return std::unexpected{ "Could not find 'hostmid'" }; }

        split_pos = helpers::do_operation(marks.hostmid.value(), cfg.pos.get().operation, cfg.pos.get().offset);
    } else if (cfg.pos.get().arg == Markers::SNIEXT_STR) {
        if (!marks.sniext.has_value()) { return std::unexpected{ "Could not find 'sniext'" }; }

        split_pos = helpers::do_operation(marks.sniext.value(), cfg.pos.get().operation, cfg.pos.get().offset);
    } else {
        const auto offset = cfg.pos.get().offset;
        split_pos = offset;
    }

    auto [iter, rel] = helpers::find_packet_by_offset(packets, split_pos, cfg.handle_fake);
    // split iter packet at split_pos_relative_to_packet
    if (rel == 0) {
        // already split naturally
        return { true };
    }

    helpers::split_and_insert_packets_tcp(iter, rel, packets);
    return { true };
}

std::expected<bool, std::string>
    split::split_other(std::vector<Packet> &packets, [[maybe_unused]] const std::vector<char> &full_payload, const SplitConfig &cfg)
{
    const auto split_pos = cfg.pos.get().offset;

    auto [iter, split_pos_relative_to_packet] = helpers::find_packet_by_offset(packets, split_pos, cfg.handle_fake);
    if (iter == packets.end()) { return { false }; }

    if (split_pos_relative_to_packet == 0) {
        // already split naturally
        return { true };
    }

    if (packets.front().network_hdr()->protocol == IPPROTO_TCP) {
        helpers::split_and_insert_packets_tcp(iter, split_pos_relative_to_packet, packets);
    } else {
        return std::unexpected{ "Wasn't able to split packets because other protocols besides TCP are not supported" };
    }
    return { true };
}