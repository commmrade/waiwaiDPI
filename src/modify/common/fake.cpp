//
// Created by klewy on 11/16/26.
//

#include "fake.hpp"
#include "modify/args.hpp"
#include "modify/fooling.hpp"
#include "net/checksum.hpp"
#include <algorithm>
#include <ranges>

void Fake::process_fake(std::vector<Packet> &packets, ModifyContext &ctx)
{
    auto filtered_packets = std::ranges::views::filter(packets, [](const Packet &packet) {
       return packet.is_fake_blob;
   });

    if (args_.ipv4_ttl.has_value()) {
        fooling::ipv4_ttl(filtered_packets, args_.ipv4_ttl.value());
    }

    if (args_.ts_offset.has_value()) {
        if (ctx.conn.get().get_l4_proto() == IPPROTO_TCP) {
            fooling::timestamp_offset(filtered_packets, args_.ts_offset.value());
        } else {
            SPDLOG_WARN("TS Offset is defined but the protocol is not TCP");
        }
    }

    if (args_.seq_offset.has_value()) {
        if (ctx.conn.get().get_l4_proto() == IPPROTO_TCP) {
            fooling::sequence_offset(filtered_packets, args_.seq_offset.value());
        } else {
            SPDLOG_ERROR("Seq. Offset is defined but the L4 protocol is not TCP");
        }
    }

    if (args_.badcksum) {
        fooling::badchecksum(filtered_packets, ctx.conn.get().get_l4_proto());
    }

    if (args_.tcp_md5) {
        if (ctx.conn.get().get_l4_proto() == IPPROTO_TCP) {
            fooling::tcp_md5(filtered_packets);

            for (auto& packet : packets) {
                calc_packet_checksum(packet);
            }
        } else {
            SPDLOG_ERROR("TCP MD5 is used only for TCP");
        }
    }
}

void Fake::modify(std::vector<Packet> &packets, ModifyContext &ctx)
{
    const auto front_view = parse_packet_view(packets.front());

    Packet new_packet = create_packet_from(front_view, args_.fake_blob);
    new_packet.action.action = PacketAction::Action::SEND;
    new_packet.action.packet_id = 0;

    std::vector<Packet> blob_packets;
    for (auto i = 0; i < args_.repeats.value_or(1); ++i) {
        blob_packets.push_back(new_packet);
        blob_packets.back().is_fake_blob = true;
        calc_packet_checksum(blob_packets.back());
    }

    process_fake(blob_packets, ctx);

    packets.insert(
        packets.begin(), std::make_move_iterator(blob_packets.begin()), std::make_move_iterator(blob_packets.end()));
}
bool Fake::matches(const std::vector<Packet> &packets, const Connection &conn) const
{
    return true;
}
void Fake::parse_config(const toml::table *table)
{
    const auto *blob_node = table->get("fake_blob");
    if (blob_node == nullptr) {
        throw std::runtime_error("Fake modifier must have a fake_blob argument");
    }

    if (!blob_node->is_string()) { throw std::runtime_error("fake_blob must be a string"); }
    auto buf = parse_blob(blob_node->as_string()->get());
    args_.fake_blob = std::move(buf);


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

    const auto* repeats_node = table->get("repeats");
    if (repeats_node != nullptr) {
        if (!repeats_node->is_number()) {
            throw std::runtime_error("'repeats' must be a number");
        }

        args_.repeats.emplace(repeats_node->as_integer()->get());
    }

    const auto* tcp_md5_node = table->get("tcp_md5");
    if (tcp_md5_node != nullptr) {
        if (!tcp_md5_node->is_boolean()) {
            throw std::runtime_error("tcp_md5 must be a boolean");
        }

        args_.tcp_md5 = tcp_md5_node->as_boolean()->get();
    }
}