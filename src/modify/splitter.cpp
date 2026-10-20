//
// Created by klewy on 9/24/26.
//

#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_TRACE
#include "splitter.hpp"
#include "net/checksum.hpp"
#include "algorithms/common.hpp"
#include "algorithms/split.hpp"
#include "markers.hpp"
#include "spdlog/spdlog.h"
#include <arpa/inet.h>
#include <filesystem>
#include <fstream>
#include <ranges>

void Splitter::process_fake(std::vector<Packet> &packets, ModifyContext &ctx)
{
    auto filtered_packets = std::ranges::views::filter(packets, [](const Packet &packet) {
        return packet.is_fake_blob;
    });

    if (args_.ipv4_ttl.has_value()) {
        ipv4_ttl(filtered_packets, args_.ipv4_ttl.value());
    }

    if (args_.ts_offset.has_value()) {
        if (ctx.conn.get().get_l4_proto() == IPPROTO_TCP) {
            timestamp_offset(filtered_packets, args_.ts_offset.value());
        } else {
            SPDLOG_WARN("TS Offset is defined but the protocol is not TCP");
        }
    }

    if (args_.seq_offset.has_value()) {
        if (ctx.conn.get().get_l4_proto() == IPPROTO_TCP) {
            sequence_offset(filtered_packets, args_.seq_offset.value());
        } else {
            SPDLOG_ERROR("Seq. Offset is defined but the L4 protocol is not TCP");
        }
    }

    if (args_.badcksum) {
        badchecksum(filtered_packets, ctx.conn.get().get_l4_proto());
    }
}

void Splitter::process_orig(std::vector<Packet> &packets, ModifyContext &ctx)
{
    auto filtered_packets = std::ranges::views::filter(packets, [](const Packet &packet) {
        return !packet.is_fake_blob;
    });

    if (!args_.splits.empty()) {
        for (const auto &split_pos : args_.splits) {
            auto res = split::split(packets, split_pos, ctx.markers, ctx.conn.get().payload_proto());
            if (!res) {
                SPDLOG_WARN(
                    "Wasn't able to split packet at {}:{}, because: {}", split_pos.arg, split_pos.offset, res.error());
            }
        }
    }

    if (args_.ipv4_ttl.has_value()) {
        ipv4_ttl(filtered_packets, args_.ipv4_ttl.value());
    }

    if (args_.ts_offset.has_value()) {
        if (ctx.conn.get().get_l4_proto() == IPPROTO_TCP) {
            timestamp_offset(filtered_packets, args_.ts_offset.value());
        } else {
            SPDLOG_WARN("TS Offset is defined but the protocol is not TCP");
        }
    }

    if (args_.seqovl.has_value()) {
        if (ctx.conn.get().get_l4_proto() == IPPROTO_TCP) {
            seqovl(packets, ctx.conn.get());
        } else {
            SPDLOG_WARN("Seqovl is defined but the protocol is not TCP");
        }
    }

    if (args_.seq_offset.has_value()) {
        if (ctx.conn.get().get_l4_proto() == IPPROTO_TCP) {
            sequence_offset(filtered_packets, args_.seq_offset.value());
        } else {
            SPDLOG_ERROR("Seq. Offset is defined but the L4 protocol is not TCP");
        }
    }

    if (args_.badcksum) {
        badchecksum(filtered_packets, ctx.conn.get().get_l4_proto());
    }
}

void Splitter::seqovl(std::vector<Packet> &packets, const Connection &conn)
{
    auto iter = std::ranges::find_if(packets, [](const Packet &packet) {
        return !packet.is_fake_blob;
    });

    if (iter == packets.end()) { return; }

    auto &packet = *iter;
    const auto packet_view = parse_packet_view(packet);
    const auto packet_pl = packet.payload();

    std::vector<char> new_payload(packet.payload().size() + static_cast<std::size_t>(args_.seqovl.value()), 0);

    if (args_.seqovl_pat.has_value()) {
        std::span<char> full_payload{ new_payload.data(), static_cast<std::size_t>(args_.seqovl.value()) };

        while (!full_payload.empty()) {
            const auto chunk_size = std::min(args_.seqovl_pat.value().size(), full_payload.size());
            auto chunk = full_payload.subspan(0, chunk_size);
            std::memcpy(chunk.data(), args_.seqovl_pat.value().data(), chunk_size);
            full_payload = full_payload.subspan(chunk_size);
        }
    }

    std::memcpy(std::next(new_payload.data(), static_cast<std::ptrdiff_t>(args_.seqovl.value())),
        packet_pl.data(),
        packet_pl.size());

    auto *tcp = static_cast<tcphdr *>(packet.transport_hdr());
    auto *ip = packet.network_hdr();

    const auto mss =
        static_cast<std::size_t>(conn.get_mss()) - (ip->ihl * 4 - sizeof(iphdr)) - (tcp->doff * 4 - sizeof(tcp));

    if (new_payload.size() > mss) {
        auto start_seq = ntohl(tcp->seq) - static_cast<std::uint32_t>(args_.seqovl.value());
        auto splitted = segmentize(new_payload, mss, packet, start_seq);

        iter = packets.erase(iter);
        packets.insert(iter, std::make_move_iterator(splitted.begin()), std::make_move_iterator(splitted.end()));
    } else {
        auto new_packet = create_packet_from(packet_view, new_payload);

        new_packet.is_fake_blob = packet.is_fake_blob;

        if (packet.action.action == PacketAction::Action::SEND) {
            new_packet.action.action = PacketAction::Action::SEND;
        } else {
            new_packet.action.action = PacketAction::Action::DROP_AND_SEND;
            new_packet.action.packet_id = packet.action.packet_id;
        }

        auto *tcp = static_cast<tcphdr *>(new_packet.transport_hdr());// NOLINT
        tcp->seq = htonl(ntohl(tcp->seq) - static_cast<std::uint32_t>(args_.seqovl.value()));
        calc_packet_checksum(new_packet);

        std::swap(packet, new_packet);
    }
}

void Splitter::modify(std::vector<Packet> &packets, ModifyContext& ctx)
{
    if (args_.fake_blob.has_value()) {
        const auto front_view = parse_packet_view(packets.front());

        Packet new_packet = create_packet_from(front_view, args_.fake_blob.value());
        new_packet.action.action = PacketAction::Action::SEND;
        new_packet.action.packet_id = 0;

        std::vector<Packet> blob_packets;
        blob_packets.push_back(std::move(new_packet));
        blob_packets.front().is_fake_blob = true;
        calc_packet_checksum(blob_packets.front());

        process_fake(blob_packets, ctx);

        for (auto &packet : blob_packets) { packet.is_fake_blob = true; }

        packets.insert(
            packets.begin(), std::make_move_iterator(blob_packets.begin()), std::make_move_iterator(blob_packets.end()));
    } else {
        process_orig(packets, ctx);
    }
}

bool Splitter::matches([[maybe_unused]] const std::vector<Packet> &packets, const Connection &conn) const
{
    if (args_.l7_payload.has_value()) { return conn.payload_proto() == args_.l7_payload.value(); }
    return true;
}

void Splitter::parse_config(const toml::table *table)
{
    const auto *split_node = table->get("split_at");
    if (split_node != nullptr) {
        if (!split_node->is_array()) {
            throw std::runtime_error(std::format("split_at must be an array for '{}'", Splitter::name()));
        }

        for (const auto &node : *split_node->as_array()) {
            Position new_split{};
            if (node.is_number()) {
                new_split.offset = static_cast<std::size_t>(node.as_integer()->get());
            } else {
                const auto split_str = node.as_string()->get();
                new_split = parse_position(split_str);
            }
            args_.splits.push_back(std::move(new_split));
        }
    }

    const auto *blob_node = table->get("fake_blob");
    if (blob_node != nullptr) {
        if (!blob_node->is_string()) { throw std::runtime_error("fake_blob must be a string"); }

        auto buf = parse_blob(blob_node->as_string()->get());
        args_.fake_blob.emplace(std::move(buf));
    }

    const auto *cksum_node = table->get("badcksum");
    if (cksum_node != nullptr) {
        if (!cksum_node->is_boolean()) { throw std::runtime_error("badcksum must be a bool"); }

        srand(static_cast<unsigned int>(time(nullptr)));
        args_.badcksum = cksum_node->as_boolean()->get();
    }

    const auto seq_node = table->get("seq_off");
    if (seq_node != nullptr) {
        if (!seq_node->is_number()) { throw std::runtime_error("seq_off must be a number"); }

        args_.seq_offset.emplace(seq_node->as_integer()->get());
    }

    const auto *ts_node = table->get("ts_off");
    if (ts_node != nullptr) {
        if (!ts_node->is_number()) { throw std::runtime_error("ts_off must be a number"); }

        args_.ts_offset.emplace(ts_node->as_integer()->get());
    }

    const auto *ipv4_ttl_node = table->get("ipv4_ttl");
    if (ipv4_ttl_node != nullptr) {
        if (!ipv4_ttl_node->is_number()) { throw std::runtime_error("ipv4_ttl must be a number"); }

        args_.ipv4_ttl.emplace(ipv4_ttl_node->as_integer()->get());
    }

    const auto *l7_proto_node = table->get("l7_payload");
    if (l7_proto_node != nullptr) {
        if (!l7_proto_node->is_string()) { throw std::runtime_error("l7_payload must be a string"); }

        const auto proto_str = l7_proto_node->as_string()->get();
        args_.l7_payload.emplace(string_to_proto(proto_str));
    }

    const auto *seqovl_node = table->get("seqovl");
    if (seqovl_node != nullptr) {
        if (!seqovl_node->is_integer()) { throw std::runtime_error("seqovl must be an integer"); }

        args_.seqovl.emplace(seqovl_node->as_integer()->get());
    }

    const auto *seqovl_ptrn_node = table->get("seqovl_pattern");
    if (seqovl_ptrn_node != nullptr) {
        if (!seqovl_ptrn_node->is_string()) { throw std::runtime_error("seqovl_pattern must be a string"); }

        auto buf = parse_blob(seqovl_ptrn_node->as_string()->get());
        args_.seqovl_pat.emplace(std::move(buf));
    }
}