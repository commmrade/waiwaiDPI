//
// Created by klewy on 9/24/26.
//

#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_TRACE
#include "splitter.hpp"
#include "spdlog/spdlog.h"

#include "../checksum.hpp"
#include "algorithms/split.hpp"
#include <arpa/inet.h>
#include <filesystem>
#include <fstream>
#include <ranges>

bool Splitter::check_ip(const std::vector<Packet> &packets) const
{
    assert(!packets.empty());
    if (allowed_ips_.has_value()) {
        const auto addr = packets.front().network_hdr()->daddr;
        if (!allowed_ips_.value().contains(addr)) { return false; }
    }

    return true;
}

static bool timestamp_val_offset(Packet &packet, const int offset)
{
    auto *tcp = static_cast<tcphdr *>(packet.transport_hdr());
    std::span<char> tcp_bytes{ static_cast<char *>(packet.transport_hdr()), static_cast<std::size_t>(tcp->doff * 4) };
    if (tcp_bytes.size() <= sizeof(tcphdr)) {
        return false;// no TCP options
    }

    constexpr static std::uint8_t TS_OPT_KIND = 8;
    constexpr static std::uint8_t TS_OPT_SIZE = 10;

    tcp_bytes = tcp_bytes.subspan(sizeof(tcphdr));
    while (!tcp_bytes.empty()) {
        if (tcp_bytes.size() < 2) {
            return false;// not enough bytes to get KIND,LENGTH
        }

        const std::uint8_t kind = tcp_bytes[0];
        if (kind == 1) {// no-op
            tcp_bytes = tcp_bytes.subspan(1);
            continue;
        }

        const std::uint8_t size = tcp_bytes[1];
        if (kind != TS_OPT_KIND) {
            if (tcp_bytes.size() < size) { return false; }

            assert(size > 0);
            tcp_bytes = tcp_bytes.subspan(size);// size includes kind,length + payload
            continue;
        }

        if (size < TS_OPT_SIZE || size > TS_OPT_SIZE) { return false; }

        auto *tv = std::start_lifetime_as<std::uint32_t>(std::next(tcp_bytes.data(), 2));
        auto *tr = std::start_lifetime_as<std::uint32_t>(std::next(tcp_bytes.data(), 2 + sizeof(*tv)));

        *tv = htonl(static_cast<std::uint32_t>(static_cast<int>(ntohl(*tv)) + offset));
        *tr = htonl(static_cast<std::uint32_t>(static_cast<int>(ntohl(*tr)) + offset));

        break;
    }

    return true;
}

void Splitter::process(std::vector<Packet> &packets, const bool handle_fake, const Connection &conn)
{
    auto filtered_packets = std::ranges::views::filter(packets, [handle_fake](const Packet &packet) {
        return (handle_fake && packet.is_fake_blob) || (!handle_fake && !packet.is_fake_blob);
    });
    if (!splits_.empty()) {
        std::vector<char> full_payload;

        for (const auto &pkt : filtered_packets) {
            const auto payload = pkt.payload();
            full_payload.insert(full_payload.end(), payload.begin(), payload.end());
        }

        for (const auto &split_pos : splits_) {
            auto res = split::split(packets,
                split::SplitConfig{ .pos = split_pos, .hosts = allowed_hosts_, .handle_fake = handle_fake },
                full_payload,
                conn);
            if (!res) {
                SPDLOG_WARN(
                    "Wasn't able to split packet at {}:{}, because: {}", split_pos.arg, split_pos.offset, res.error());
            }
        }
    }

    if (ipv4_ttl_.has_value()) {
        for (auto &packet : filtered_packets) { packet.network_hdr()->ttl = ipv4_ttl_.value(); }
    }

    if (ts_offset_.has_value()) {
        if (conn.get_l4_proto() == IPPROTO_TCP) {
            for (auto &packet : filtered_packets) {
                if (!timestamp_val_offset(packet, ts_offset_.value())) { SPDLOG_WARN("Failed to offset timestamp"); }

                auto *tcp = static_cast<tcphdr *>(packet.transport_hdr());
                tcp->check = 0;
                tcp->check = calc_tcp_checksum(packet);
            }
        } else {
            SPDLOG_WARN("TS Offset is defined but the protocol is not TCP");
        }
    }

    if (seqovl_.has_value()) {
        if (conn.get_l4_proto() == IPPROTO_TCP) {
            auto iter = std::ranges::find_if(packets, [handle_fake](const Packet &packet) {
                return (handle_fake && packet.is_fake_blob) || (!handle_fake && !packet.is_fake_blob);
            });
            if (iter != packets.end()) {
                auto &packet = *iter;
                const auto packet_view = parse_packet_view(packet);
                const auto packet_pl = packet.payload();

                std::vector<char> new_payload(
                    packet.payload().size() + static_cast<std::size_t>(seqovl_.value()), 0);// TODO: set seqovl-pattern
                std::memcpy(std::next(new_payload.data(), static_cast<std::ptrdiff_t>(seqovl_.value())),
                    packet_pl.data(),
                    packet_pl.size());

                auto *tcp = static_cast<tcphdr *>(packet.transport_hdr());
                auto *ip = packet.network_hdr();

                const auto mss = static_cast<std::size_t>(conn.get_mss()) - (ip->ihl * 4 - sizeof(iphdr))
                                 - (tcp->doff * 4 - sizeof(tcp));


                if (new_payload.size() > mss) {
                    std::span<const char> payload{ new_payload };

                    std::vector<Packet> splitted;
                    splitted.reserve((new_payload.size() / mss) + 1);

                    auto start_seq = ntohl(tcp->seq) - static_cast<std::uint32_t>(seqovl_.value());

                    while (!payload.empty()) {
                        const auto chunk_size = std::min(payload.size(), mss);

                        auto new_packet = create_packet_from(packet_view, payload.subspan(0, chunk_size));
                        new_packet.is_fake_blob = packet.is_fake_blob;
                        new_packet.action.action = PacketAction::Action::SEND;
                        new_packet.action.packet_id = 0;

                        tcp = static_cast<tcphdr *>(new_packet.transport_hdr());
                        tcp->seq = htonl(start_seq);
                        tcp->check = 0;
                        tcp->check = calc_tcp_checksum(new_packet);

                        splitted.push_back(std::move(new_packet));

                        payload = payload.subspan(chunk_size);
                        start_seq += chunk_size;
                    }

                    if (packet.action.action == PacketAction::Action::SEND) {
                        splitted.front().action.action = PacketAction::Action::SEND;
                    } else {
                        splitted.front().action.action = PacketAction::Action::DROP_AND_SEND;
                        splitted.front().action.packet_id = packet.action.packet_id;
                    }

                    iter = packets.erase(iter);
                    packets.insert(
                        iter, std::make_move_iterator(splitted.begin()), std::make_move_iterator(splitted.end()));
                } else {
                    auto new_packet = create_packet_from(packet_view, new_payload);
                    new_packet.is_fake_blob = packet.is_fake_blob;
                    new_packet.action.action = PacketAction::Action::DROP_AND_SEND;

                    auto *tcp = static_cast<tcphdr *>(new_packet.transport_hdr());
                    tcp->seq = htonl(ntohl(tcp->seq) - static_cast<std::uint32_t>(seqovl_.value()));
                    tcp->check = 0;
                    tcp->check = calc_tcp_checksum(new_packet);

                    std::swap(packet, new_packet);
                }
            }
        } else {
            SPDLOG_ERROR("Seqovl is defined but the L4 protocol is not TCP");
        }
    }

    if (seq_offset_.has_value()) {
        if (conn.get_l4_proto() == IPPROTO_TCP) {
            for (auto &packet : filtered_packets) {
                auto *tcp = static_cast<tcphdr *>(packet.transport_hdr());
                tcp->seq = htonl(static_cast<std::uint32_t>(static_cast<int>(ntohl(tcp->seq)) + seq_offset_.value()));
                tcp->check = 0;
                tcp->check = calc_tcp_checksum(packet);
            }
        } else {
            SPDLOG_ERROR("Seq. Offset is defined but the L4 protocol is not TCP");
        }
    }

    if (badcksum_) {
        if (conn.get_l4_proto() == IPPROTO_TCP) {
            for (auto &packet : filtered_packets) {
                auto *tcp = static_cast<tcphdr *>(packet.transport_hdr());
                tcp->check = 0;
                tcp->check = htonl(rand() % 256);
            }
        } else {
            SPDLOG_ERROR("Bad Checksum for protocols other than TCP hasn't been implemented yet");
        }
    }
}

void Splitter::modify(std::vector<Packet> &vec, const Connection &conn)
{
    if (!check_ip(vec)) { return; }

    if (fake_blob_.has_value()) {
        const auto front_view = parse_packet_view(vec.front());

        Packet new_packet = create_packet_from(front_view, fake_blob_.value());
        new_packet.action.action = PacketAction::Action::SEND;
        new_packet.action.packet_id = 0;

        std::vector<Packet> blob_packets;
        blob_packets.push_back(std::move(new_packet));
        blob_packets.front().is_fake_blob = true;

        process(blob_packets, true, conn);

        if (!badcksum_) {
            for (auto &packet : blob_packets) {
                auto *tcp = static_cast<tcphdr *>(packet.transport_hdr());
                tcp->check = 0;
                tcp->check = calc_tcp_checksum(packet);
            }
        }

        for (auto &packet : blob_packets) { packet.is_fake_blob = true; }

        vec.insert(
            vec.begin(), std::make_move_iterator(blob_packets.begin()), std::make_move_iterator(blob_packets.end()));
    } else {
        process(vec, false, conn);
    }
}

bool Splitter::matches(const std::vector<Packet> &packets, const Connection &conn) const
{
    if (l7_payload_.has_value()) { return conn.payload_proto() == l7_payload_.value(); }
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
            Split new_split{};
            if (node.is_number()) {
                new_split.offset = static_cast<std::size_t>(node.as_integer()->get());
            } else {
                const auto split_str = node.as_string()->get();
                new_split = parse_split(split_str);
            }
            splits_.push_back(std::move(new_split));
        }
    }

    const auto *hosts_node = table->get("allowed_hosts");
    if (hosts_node != nullptr) {
        auto &allowed_hosts = allowed_hosts_.emplace();

        if (!hosts_node->is_array()) { throw std::runtime_error("allowed_hosts must be an array"); }

        const auto *hosts_array = hosts_node->as_array();
        allowed_hosts.reserve(hosts_array->size());
        for (const auto &node : *hosts_array) {
            if (!node.is_string()) { throw std::runtime_error("All hosts must be strings"); }

            allowed_hosts.insert(node.as_string()->get());
        }
    }

    const auto *ips_node = table->get("allowed_ips");
    if (ips_node != nullptr) {
        auto &allowed_ips = allowed_ips_.emplace();

        if (!ips_node->is_array()) { throw std::runtime_error("allowed_ips must be an array"); }

        const auto *ips_array = ips_node->as_array();
        allowed_ips.reserve(ips_array->size());
        for (const auto &node : *ips_array) {
            if (!node.is_string()) { throw std::runtime_error("All ips must be strings"); }

            const auto addr_str = node.as_string()->get();
            std::uint32_t addr = 0;
            int ret = inet_pton(AF_INET, addr_str.data(), &addr);
            if (ret != 1) { throw std::runtime_error(std::format("Could not convert address '{}'", addr_str)); }

            allowed_ips.insert(addr);
        }
    }

    const auto *blob_node = table->get("fake_blob");
    if (blob_node != nullptr) {
        if (!blob_node->is_string()) { throw std::runtime_error("fake_blob must be a string"); }

        const auto blob_path = blob_node->as_string()->get();
        if (!std::filesystem::exists(blob_path)) {
            throw std::runtime_error(std::format("Blob at filepath '{}' does not exist", blob_path));
        }

        auto *fp = std::fopen(blob_path.c_str(), "rb");
        if (!fp) { throw std::runtime_error(std::format("Could not open file '{}'", blob_path)); }
        int ret = std::fseek(fp, 0U, SEEK_END);
        if (ret < 0) { throw std::runtime_error(std::strerror(errno)); }
        const auto size = std::ftell(fp);
        if (size < 0) { throw std::runtime_error(std::strerror(errno)); }
        ret = std::fseek(fp, 0U, SEEK_SET);
        if (ret < 0) { throw std::runtime_error(std::strerror(errno)); }
        std::vector<char> buf;
        buf.resize(size);
        const auto rd = std::fread(buf.data(), 1U, static_cast<std::size_t>(size), fp);
        if (rd < 0) { throw std::runtime_error(std::strerror(errno)); }
        ret = std::fclose(fp);

        fake_blob_.emplace(std::move(buf));
    }

    const auto *cksum_node = table->get("badcksum");
    if (cksum_node != nullptr) {
        if (!cksum_node->is_boolean()) { throw std::runtime_error("badcksum must be a bool"); }

        srand(time(nullptr));
        badcksum_ = cksum_node->as_boolean()->get();
    }

    const auto seq_node = table->get("seq_off");
    if (seq_node != nullptr) {
        if (!seq_node->is_number()) { throw std::runtime_error("seq_off must be a number"); }

        seq_offset_.emplace(seq_node->as_integer()->get());
    }

    const auto *ts_node = table->get("ts_off");
    if (ts_node != nullptr) {
        if (!ts_node->is_number()) { throw std::runtime_error("ts_off must be a number"); }

        ts_offset_.emplace(ts_node->as_integer()->get());
    }

    const auto *ipv4_ttl_node = table->get("ipv4_ttl");
    if (ipv4_ttl_node != nullptr) {
        if (!ipv4_ttl_node->is_number()) { throw std::runtime_error("ipv4_ttl must be a number"); }

        ipv4_ttl_.emplace(ipv4_ttl_node->as_integer()->get());
    }

    const auto *l7_proto_node = table->get("l7_payload");
    if (l7_proto_node != nullptr) {
        if (!l7_proto_node->is_string()) { throw std::runtime_error("l7_payload must be a string"); }

        const auto proto_str = l7_proto_node->as_string()->get();
        l7_payload_.emplace(string_to_proto(proto_str));
    }

    const auto *seqovl_node = table->get("seqovl");
    if (seqovl_node != nullptr) {
        if (!seqovl_node->is_integer()) { throw std::runtime_error("seqovl must be an integer"); }

        seqovl_.emplace(seqovl_node->as_integer()->get());
    }
}