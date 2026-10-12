//
// Created by klewy on 10/12/26.
//


#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_TRACE
#include "disorder.hpp"
#include "../checksum.hpp"
#include "algorithms/common.hpp"
#include "algorithms/split.hpp"
#include "args.hpp"
#include "spdlog/spdlog.h"
#include <arpa/inet.h>
#include <iostream>
#include <ranges>

static bool safe_subspan(std::span<const char> &span, const std::size_t offset)
{
    if (span.size() < offset) { return false; }
    span = span.subspan(offset);
    return true;
}

bool Disorder::find_markers_http(std::span<const char> payload)
{
    const std::string_view payload_str{ payload };

    constexpr std::string_view HOST_HEADER_NAME = "Host:";
    const auto host_subrange = std::ranges::search(payload_str, HOST_HEADER_NAME, [](const auto ch1, const auto ch2) {
        return std::tolower(ch1) == std::tolower(ch2);
    });
    if (host_subrange.empty()) {
        return false;
    }
    const auto host_pos = std::distance(payload_str.begin(), host_subrange.begin());
    const auto host_end = payload_str.find("\r\n", static_cast<std::size_t>(host_pos));
    if (host_end == std::string::npos) {
        return false;
    }

    std::string_view const host{ payload_str.data() + host_pos + HOST_HEADER_NAME.size() + 1,
        payload_str.data() + host_end };
    marks_.hoststart.emplace(std::distance(payload_str.data(), host.data()));
    marks_.hostend.emplace(marks_.hoststart.value() + host.size());
    marks_.hostmid.emplace(marks_.hoststart.value() + host.size() / 2);

    return true;
}

bool Disorder::find_markers_tls(std::span<const char> payload)
{
    // it is guaranteed to be a tls handshake (because of the classifier), nothing else is guaranteed besides that
    constexpr auto tls_handshake_type = 0x16;
    assert(payload.size() >= 5);
    assert(payload[0] == tls_handshake_type);
    assert(payload[1] == 0x03 && (payload[2] == 0x03 || payload[2] == 0x01));

    const auto initial = payload;

    // content stuff
    payload = payload.subspan(5);// skip header bytes, get to content

    // from now on i need to do all the checks, because classifier checks just the header (first 5 bytes)
    if (payload[0] != 0x01) {// content type is not clienthello
        // std::println(std::cerr, "content type is not clienthello");
        return false;
    }

    if (!safe_subspan(payload, 38)) {// skip type(1) + length(3) + legacyversion(2) + random(32) fields
        std::println(std::cerr, "ill-formed tls");
        return false;
    }

    const auto legacy_session_id_len = static_cast<std::uint8_t>(payload[0]);
    if (!safe_subspan(payload, sizeof(legacy_session_id_len) + legacy_session_id_len)) {
        std::println(std::cerr, "ill-formed tls");
        return false;
    }

    std::uint16_t cipher_suites_len = 0;
    if (payload.size() < sizeof(cipher_suites_len)) {
        std::println(std::cerr, "ill-formed tls");
        return false;
    }
    std::memcpy(&cipher_suites_len, payload.data(), sizeof(cipher_suites_len));
    cipher_suites_len = ntohs(cipher_suites_len);

    if (!safe_subspan(payload, sizeof(cipher_suites_len) + cipher_suites_len + 2)) {
        std::println(std::cerr, "ill-formed tls");
        return false;
    }

    // parse extensions (sni is here) (loop)
    std::uint16_t exts_len = 0;
    if (payload.size() < sizeof(exts_len)) {
        std::println(std::cerr, "ill-formed tls");
        return false;
    }
    std::memcpy(&exts_len, payload.data(), sizeof(exts_len));
    exts_len = ntohs(exts_len);
    payload = payload.subspan(sizeof(exts_len));

    while (!payload.empty()) {
        std::uint16_t ext_type = 0;
        if (payload.size() < sizeof(ext_type)) {
            std::println(std::cerr, "ill-formed tls");
            return false;
        }

        marks_.sniext.emplace(static_cast<std::size_t>(std::distance(initial.data(), payload.data())));
        std::memcpy(&ext_type, payload.data(), sizeof(ext_type));
        ext_type = ntohs(ext_type);

        payload = payload.subspan(sizeof(ext_type));

        std::uint16_t ext_len = 0;
        if (payload.size() < sizeof(ext_len)) {
            std::println(std::cerr, "ill-formed tls");
            return false;
        }
        std::memcpy(&ext_len, payload.data(), sizeof(ext_len));
        ext_len = ntohs(ext_len);

        constexpr auto ext_sni_type = 0x00;
        if (ext_type != ext_sni_type) {

            if (!safe_subspan(payload, sizeof(ext_len) + ext_len)) {
                std::println(std::cerr, "ill-formed tls");
                return false;
            }
            continue;
        }

        payload = payload.subspan(sizeof(ext_len));

        std::uint16_t serv_name_list_len = 0;
        if (payload.size() < sizeof(serv_name_list_len) + 1) {
            std::println(std::cerr, "ill-formed tls");
            return false;
        }
        std::memcpy(&serv_name_list_len, payload.data(), sizeof(serv_name_list_len));
        serv_name_list_len = ntohs(serv_name_list_len);

        if (payload[2] != 0x00) {// well acyually servname list is a list, but it is always 1 element so idc
            return false;
        }

        payload = payload.subspan(sizeof(serv_name_list_len) + 1);

        std::uint16_t hostname_len = 0;
        if (payload.size() < sizeof(hostname_len)) {
            std::println(std::cerr, "ill-formed tls");
            return false;
        }
        std::memcpy(&hostname_len, payload.data(), sizeof(hostname_len));
        hostname_len = ntohs(hostname_len);

        if (payload.size() < sizeof(hostname_len) + hostname_len) {
            std::println(std::cerr, "ill-formed tls");
            return false;
        }

        const auto hoststart = static_cast<std::size_t>(std::distance(initial.data(), payload.data()));
        marks_.hoststart.emplace(hoststart);
        marks_.hostend.emplace(hoststart + hostname_len);
        marks_.hostmid.emplace(hoststart + hostname_len / 2);

        return true;
    }

    return false;
}

bool Disorder::find_markers(std::span<const char> payload, const L7Proto payload_proto)
{
    switch (payload_proto) {
    case L7Proto::TLS: {
        return find_markers_tls(payload);
    }
    case L7Proto::HTTP: {
        return find_markers_http(payload);
    }
    default:
        return false;
    };
}

void Disorder::seqovl(std::vector<Packet> &packets, bool handle_fake, const Connection &conn)
{
    if (!args_.seqovl.value().arg.empty()) {
        auto filtered_packets = std::ranges::views::filter(packets, [handle_fake](const Packet &packet) {
            return (handle_fake && packet.is_fake_blob) || (!handle_fake && !packet.is_fake_blob);
        });

        std::vector<char> full_payload;

        for (const auto &pkt : filtered_packets) {
            const auto payload = pkt.payload();
            full_payload.insert(full_payload.end(), payload.begin(), payload.end());
        }

        if (!find_markers(full_payload, conn.payload_proto())) {
            SPDLOG_WARN("Was unable to find markers for seqovl");
            return;
        }
    }

    auto seqovl_num = [&]() -> std::size_t {
        const auto &pos = args_.seqovl.value();
        std::size_t ret = 0;
        if (pos.arg == "hoststart") {
            ret = helpers::do_operation(marks_.hoststart.value(), pos.operation, pos.offset);
        } else if (pos.arg == "hostend") {
            ret = helpers::do_operation(marks_.hostend.value(), pos.operation, pos.offset);
        } else if (pos.arg == "hostmid") {
            ret = helpers::do_operation(marks_.hostmid.value(), pos.operation, pos.offset);
        } else if (pos.arg == "sniext") {
            ret = helpers::do_operation(marks_.sniext.value(), pos.operation, pos.offset);
        } else {
            ret = pos.offset;
        }

        return ret;
    };

    if (conn.get_l4_proto() == IPPROTO_TCP) {
        auto iter = packets.begin() + 1;
        if (static_cast<std::size_t>(seqovl_num()) >= packets.front().payload().size()) {
            SPDLOG_WARN("Seqovl is too big");
            return;
        }

        if (iter == packets.end()) { return; }

        auto &packet = *iter;
        const auto packet_view = parse_packet_view(packet);
        const auto packet_pl = packet.payload();

        std::vector<char> new_payload(packet.payload().size() + seqovl_num(), 0);

        if (args_.seqovl_pat.has_value()) {
            std::span<char> full_payload{ new_payload.data(), seqovl_num() };

            while (!full_payload.empty()) {
                const auto chunk_size = std::min(args_.seqovl_pat.value().size(), full_payload.size());
                auto chunk = full_payload.subspan(0, chunk_size);
                std::memcpy(chunk.data(), args_.seqovl_pat.value().data(), chunk_size);
                full_payload = full_payload.subspan(chunk_size);
            }
        }

        std::memcpy(std::next(new_payload.data(), static_cast<std::ptrdiff_t>(seqovl_num())),
            packet_pl.data(),
            packet_pl.size());

        auto *tcp = static_cast<tcphdr *>(packet.transport_hdr());
        auto *ip = packet.network_hdr();

        const auto mss =
            static_cast<std::size_t>(conn.get_mss()) - (ip->ihl * 4 - sizeof(iphdr)) - (tcp->doff * 4 - sizeof(tcp));

        auto start_seq = ntohl(tcp->seq) - static_cast<std::uint32_t>(seqovl_num());
        if (new_payload.size() > mss) {
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
            tcp->seq = htonl(start_seq);
            calc_packet_checksum(new_packet);

            std::swap(packet, new_packet);
        }
    } else {
        SPDLOG_ERROR("Seqovl is defined but the L4 protocol is not TCP");
    }
}

bool Disorder::check_ip(const std::vector<Packet> &packets) const
{
    assert(!packets.empty());
    if (args_.allowed_ips.has_value()) {
        const auto addr = packets.front().network_hdr()->daddr;
        if (!args_.allowed_ips.value().contains(addr)) { return false; }
    }

    return true;
}
void Disorder::process(std::vector<Packet> &packets, const bool handle_fake, const Connection &conn)
{
    auto filtered_packets = std::ranges::views::filter(packets, [handle_fake](const Packet &packet) {
        return (handle_fake && packet.is_fake_blob) || (!handle_fake && !packet.is_fake_blob);
    });

    if (!args_.splits.empty()) {
        std::vector<char> full_payload;

        for (const auto &pkt : filtered_packets) {
            const auto payload = pkt.payload();
            full_payload.insert(full_payload.end(), payload.begin(), payload.end());
        }

        for (const auto &split_pos : args_.splits) {
            auto res = split::split(packets,
                split::SplitConfig{ .pos = split_pos, .hosts = args_.allowed_hosts, .handle_fake = handle_fake },
                full_payload,
                conn);
            if (!res) {
                SPDLOG_WARN(
                    "Wasn't able to split packet at {}:{}, because: {}", split_pos.arg, split_pos.offset, res.error());
            }
        }
    }

    if (args_.seq_offset.has_value()) {
        if (conn.get_l4_proto() == IPPROTO_TCP) {
            for (auto &packet : filtered_packets) {
                auto *tcp = static_cast<tcphdr *>(packet.transport_hdr());
                tcp->seq = htonl(static_cast<std::uint32_t>(static_cast<int>(ntohl(tcp->seq)) + args_.seq_offset.value()));
                calc_packet_checksum(packet);
            }
        } else {
            SPDLOG_ERROR("Seq. Offset is defined but the L4 protocol is not TCP");
        }
    }

    if (args_.ts_offset.has_value()) {
        if (conn.get_l4_proto() == IPPROTO_TCP) {
            for (auto &packet : filtered_packets) {
                if (!timestamp_val_offset(packet, args_.ts_offset.value())) { SPDLOG_WARN("Failed to offset timestamp"); }

                auto *tcp = static_cast<tcphdr *>(packet.transport_hdr());
                calc_packet_checksum(packet);
            }
        } else {
            SPDLOG_WARN("TS Offset is defined but the protocol is not TCP");
        }
    }

    if (args_.ipv4_ttl.has_value()) {
        for (auto &packet : filtered_packets) { packet.network_hdr()->ttl = args_.ipv4_ttl.value(); }
    }

    if (args_.seqovl.has_value()) { seqovl(packets, handle_fake, conn); }

    if (args_.badcksum) {
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

    auto reversible = std::ranges::views::filter(packets, [handle_fake](const Packet &packet) {
        return (handle_fake && packet.is_fake_blob) || (!handle_fake && !packet.is_fake_blob);
    });
    std::reverse(reversible.begin(), reversible.end()); //NOLINT
}

void Disorder::modify(std::vector<Packet> &vec, const Connection &conn)
{
    if (!check_ip(vec)) { return; }

    if (args_.fake_blob.has_value()) {
        const auto front_view = parse_packet_view(vec.front());

        Packet new_packet = create_packet_from(front_view, args_.fake_blob.value());
        new_packet.action.action = PacketAction::Action::SEND;
        new_packet.action.packet_id = 0;

        std::vector<Packet> blob_packets;
        blob_packets.push_back(std::move(new_packet));
        blob_packets.front().is_fake_blob = true;

        if (blob_packets.front().network_hdr()->protocol == IPPROTO_TCP) {
            auto* tcp = static_cast<tcphdr*>(blob_packets.front().transport_hdr());
            calc_packet_checksum(blob_packets.front());
        }

        process(blob_packets, true, conn);

        for (auto &packet : blob_packets) { packet.is_fake_blob = true; }

        vec.insert(
            vec.begin(), std::make_move_iterator(blob_packets.begin()), std::make_move_iterator(blob_packets.end()));
    } else {
        process(vec, false, conn);
    }
}

bool Disorder::matches(const std::vector<Packet> &packets, const Connection &conn) const
{
    if (args_.l7_payload.has_value()) { return conn.payload_proto() == args_.l7_payload.value(); }
    return true;
}

void Disorder::parse_config(const toml::table *table)
{
    const auto *split_node = table->get("split_at");
    if (split_node != nullptr) {
        if (!split_node->is_array()) {
            throw std::runtime_error(std::format("split_at must be an array for '{}'", Disorder::name()));
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

    const auto *hosts_node = table->get("allowed_hosts");
    if (hosts_node != nullptr) {
        auto &allowed_hosts = args_.allowed_hosts.emplace();

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
        auto &allowed_ips = args_.allowed_ips.emplace();

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

        auto buf = parse_blob(blob_node->as_string()->get());
        args_.fake_blob.emplace(std::move(buf));
    }

    const auto *cksum_node = table->get("badcksum");
    if (cksum_node != nullptr) {
        if (!cksum_node->is_boolean()) { throw std::runtime_error("badcksum must be a bool"); }

        srand(time(nullptr));
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
        Position new_pos{};
        if (seqovl_node->is_number()) {
            new_pos.offset = static_cast<std::size_t>(seqovl_node->as_integer()->get());
        } else {
            const auto split_str = seqovl_node->as_string()->get();
            new_pos = parse_position(split_str);
        }
        args_.seqovl.emplace(new_pos);
    }

    const auto *seqovl_ptrn_node = table->get("seqovl_pattern");
    if (seqovl_ptrn_node != nullptr) {
        if (!seqovl_ptrn_node->is_string()) { throw std::runtime_error("seqovl_pattern must be a string"); }

        auto buf = parse_blob(seqovl_ptrn_node->as_string()->get());
        args_.seqovl_pat.emplace(std::move(buf));
    }
}