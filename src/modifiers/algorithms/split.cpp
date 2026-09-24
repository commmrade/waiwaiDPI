//
// Created by klewy on 9/24/26.
//

#include "split.hpp"
#include "../../checksum.hpp"
#include <cstring>
#include <iostream>
#include <spdlog/spdlog.h>
#include <print>

namespace helpers {
static std::size_t do_operation(const std::size_t start, const Split::Operation oper, const std::size_t offset) {
    std::size_t ret = start;
    switch (oper) {
    case Split::Operation::Add: {
        ret += offset;
        break;
    }
    case Split::Operation::Subtract: {
        ret -= offset;
        break;
    }
    default:
        break;
    }

    return ret;
};

static std::pair<std::vector<Packet>::iterator, std::size_t> find_packet_by_offset(std::vector<Packet>& packets, const std::size_t split_pos)
{
    auto iter = packets.begin();
    std::size_t offset = 0;
    std::size_t split_pos_relative_to_packet = 0;
    for (; iter != packets.end(); ++iter) {
        offset += iter->payload().size();
        if (split_pos < offset) {
            split_pos_relative_to_packet = split_pos - (offset - iter->payload().size());
            break;
        }
    }
    assert(iter != packets.end());

    return {iter, split_pos_relative_to_packet};
}

// <new span, success>
static bool safe_subspan(std::span<const char>& span, const std::size_t offset)
{
    if (span.size() < offset) {
        return false;
    }
    span = span.subspan(offset);
    return true;
}

static std::optional<std::pair<std::string_view, std::size_t>> get_sni(std::span<const char> payload)
{
    // It is guaranteed to be a TLS handshake (because of the classifier), nothing else is guaranteed besides that
    constexpr auto TLS_HANDSHAKE_TYPE = 0x16;
    assert(payload.size() >= 5);
    assert(payload[0] == TLS_HANDSHAKE_TYPE);
    assert(payload[1] == 0x03 && (payload[2] == 0x03 || payload[2] == 0x01));

    const auto initial = payload;

    // content stuff
    payload = payload.subspan(5); // skip header bytes, get to content

    // From now on I need to do all the checks, because Classifier checks just the header (first 5 bytes)
    if (payload[0] != 0x01) { // content type is not ClientHello
        // std::println(std::cerr, "Content type is not ClientHello");
        return std::nullopt;
    }

    if (!safe_subspan(payload, 38)) { // skip type(1) + length(3) + legacyVersion(2) + random(32) fields
        std::println(std::cerr, "Ill-formed TLS");
        return std::nullopt;
    }

    const auto legacy_session_id_len = static_cast<std::uint8_t>(payload[0]);
    if (!safe_subspan(payload, sizeof(legacy_session_id_len) + legacy_session_id_len)) {
        std::println(std::cerr, "Ill-formed TLS");
        return std::nullopt;
    }

    std::uint16_t cipher_suites_len = 0;
    if (payload.size() < sizeof(cipher_suites_len)) {
        std::println(std::cerr, "Ill-formed TLS");
        return std::nullopt;
    }
    std::memcpy(&cipher_suites_len, payload.data(), sizeof(cipher_suites_len));
    cipher_suites_len = ntohs(cipher_suites_len);

    if (!safe_subspan(payload, sizeof(cipher_suites_len) + cipher_suites_len + 2)) {
        std::println(std::cerr, "Ill-formed TLS");
        return std::nullopt;
    }

    // parse extensions (sni is here) (loop)
    std::uint16_t exts_len = 0;
    if (payload.size() < sizeof(exts_len)) {
        std::println(std::cerr, "Ill-formed TLS");
        return std::nullopt;
    }
    std::memcpy(&exts_len, payload.data(), sizeof(exts_len));
    exts_len = ntohs(exts_len);
    payload = payload.subspan(sizeof(exts_len));

    while (!payload.empty()) {
        std::uint16_t ext_type = 0;
        if (payload.size() < sizeof(ext_type)) {
            std::println(std::cerr, "Ill-formed TLS");
            return std::nullopt;
        }

        const auto ext_offset = static_cast<std::size_t>(std::distance(initial.data(), payload.data()));
        std::memcpy(&ext_type, payload.data(), sizeof(ext_type));
        ext_type = ntohs(ext_type);

        payload = payload.subspan(sizeof(ext_type));

        std::uint16_t ext_len = 0;
        if (payload.size() < sizeof(ext_len)) {
            std::println(std::cerr, "Ill-formed TLS");
            return std::nullopt;
        }
        std::memcpy(&ext_len, payload.data(), sizeof(ext_len));
        ext_len = ntohs(ext_len);

        constexpr auto EXT_SNI_TYPE = 0x00;
        if (ext_type != EXT_SNI_TYPE) {

            if (!safe_subspan(payload, sizeof(ext_len) + ext_len)) {
                std::println(std::cerr, "Ill-formed TLS");
                return std::nullopt;
            }
            continue;
        }

        payload = payload.subspan(sizeof(ext_len));

        std::uint16_t serv_name_list_len = 0;
        if (payload.size() < sizeof(serv_name_list_len) + 1) {
            std::println(std::cerr, "Ill-formed TLS");
            return std::nullopt;
        }
        std::memcpy(&serv_name_list_len, payload.data(), sizeof(serv_name_list_len));
        serv_name_list_len = ntohs(serv_name_list_len);

        if (payload[2] != 0x00) { // well acyually servname list is a list, but it is ALWAYS 1 element so idc
            return std::nullopt;
        }

        payload = payload.subspan(sizeof(serv_name_list_len) + 1);

        std::uint16_t hostname_len = 0;
        if (payload.size() < sizeof(hostname_len)) {
            std::println(std::cerr, "Ill-formed TLS");
            return std::nullopt;
        }
        std::memcpy(&hostname_len, payload.data(), sizeof(hostname_len));
        hostname_len = ntohs(hostname_len);

        if (payload.size() < sizeof(hostname_len) + hostname_len) {
            std::println(std::cerr, "Ill-formed TLS");
            return std::nullopt;
        }

        return std::pair{std::string_view{std::next(payload.data(), sizeof(hostname_len)), static_cast<std::size_t>(hostname_len)}, ext_offset};
    }

    return std::nullopt;
}

void split_and_insert_packets(std::vector<Packet>::iterator iter, const std::size_t split_pos_relative_to_packet, std::vector<Packet>& packets)
{
    auto& pkt = *iter;
    const auto pkt_view = parse_packet_view(pkt);
    const auto pkt_payload = pkt.payload();
    // const std::span<const char> part1{pkt_payload.begin(), std::next(pkt_payload.begin(), static_cast<std::ptrdiff_t>(split_pos_relative_to_packet))};
    const std::span<const char> part2{std::next(pkt_payload.begin(), static_cast<std::ptrdiff_t>(split_pos_relative_to_packet)), pkt_payload.end()};

    // Second packet
    Packet second = create_packet_from(pkt_view, part2);
    second.action.action = PacketAction::Action::SEND;
    second.action.packet_id = 0;

    auto* tcp = static_cast<tcphdr*>(second.transport_hdr());
    tcp->seq = htonl(ntohl(tcp->seq) + static_cast<std::uint32_t>(split_pos_relative_to_packet));
    tcp->check = 0;
    tcp->check = calc_tcp_checksum(second);

    // First packet
    // ACCEPT -> DROP_AND_SEND
    // DROP_AND_SEND -> DROP_AND_SEND
    // SEND -> SEND
    pkt.packet.resize(pkt.packet.size() - part2.size());
    if (pkt.action.action == PacketAction::Action::ACCEPT) {
        pkt.action.action = PacketAction::Action::DROP_AND_SEND;
    }

    tcp = static_cast<tcphdr*>(pkt.transport_hdr());
    auto* ip = pkt.network_hdr();

    ip->tot_len = htons((ip->ihl * 4) + (tcp->doff * 4) + static_cast<std::uint16_t>(pkt.payload().size()));
    tcp->check = 0;
    tcp->check = calc_tcp_checksum(pkt);

    packets.insert(iter + 1, std::move(second));
}

}


bool split::split(std::vector<Packet> &packets, const Split &pos, const Connection& conn)
{
    std::vector<char> full_payload;
    for (const auto& pkt : packets) {
        const auto payload = pkt.payload();
        full_payload.insert(full_payload.end(), payload.begin(), payload.end());
    }

    // split based on application protocol, each protocol have a unique set of usable markers
    switch (const auto pl_proto = conn.payload_proto()) {
    case L7Proto::HTTP: {
        return split_http(packets, pos, full_payload);
    }
    case L7Proto::TLS_HANDSHAKE: {
        return split_tls(packets, pos, full_payload);
    }
    default: {
        return split_other(packets, pos, full_payload);
    }
    }
}

bool split::split_http(std::vector<Packet> &packets, const Split &pos, const std::vector<char>& full_payload)
{
    const std::string_view payload_str{full_payload};

    constexpr std::string_view HOST_HEADER_NAME = "Host:";
    const auto host_subrange = std::ranges::search(payload_str, HOST_HEADER_NAME, [](const auto ch1, const auto ch2) {
       return std::tolower(ch1) == std::tolower(ch2);
    });
    if (host_subrange.empty()) {
        SPDLOG_ERROR("Did not find 'Host' in HTTP headers");
        return false;
    }
    const auto host_pos = std::distance(payload_str.begin(), host_subrange.begin());
    const auto host_end = payload_str.find("\r\n", static_cast<std::size_t>(host_pos));
    if (host_end == std::string::npos) {
        SPDLOG_ERROR("Did not find 'Host' header end in HTTP headers");
        return false;
    }

    std::string_view const host{payload_str.data() + host_pos + HOST_HEADER_NAME.size() + 1, payload_str.data() + host_end};
    std::size_t split_pos = 0;

    if (pos.arg == "hoststart") {
        const auto offset = helpers::do_operation(0, pos.operation, pos.offset);
        split_pos = static_cast<std::size_t>(host_pos) + HOST_HEADER_NAME.size() + 1 + offset;
    } else if (pos.arg == "hostend") {
        const auto offset = helpers::do_operation(host.size(), pos.operation, pos.offset);
        split_pos = static_cast<std::size_t>(host_pos) + HOST_HEADER_NAME.size() + 1 + offset;
    } else if (pos.arg == "hostmid") {
        const auto offset = helpers::do_operation(host.size() / 2, pos.operation, pos.offset);
        split_pos = static_cast<std::size_t>(host_pos) + HOST_HEADER_NAME.size() + 1 + offset;
    } else {
        const auto offset = pos.offset;
        split_pos = offset;
    }

    auto [iter, split_pos_relative_to_packet] = helpers::find_packet_by_offset(packets, split_pos);
    // split iter packet at split_pos_relative_to_packet
    if (split_pos_relative_to_packet == 0) {
        // already split naturally
        return true;
    }

    helpers::split_and_insert_packets(iter, split_pos_relative_to_packet, packets);
    return true;
}

bool split::split_tls(std::vector<Packet> &packets, const Split &pos, const std::vector<char>& full_payload)
{
    const auto sni_opt = helpers::get_sni(full_payload);
    if (!sni_opt.has_value()) {
        std::println(std::cerr, "SNI Extension was not found in this handshake");
        return false;
    }

    const auto& [sni_str, sniext_offset] = sni_opt.value();
    const auto sni_str_pos = static_cast<std::size_t>(std::distance(static_cast<const char*>(full_payload.data()), sni_str.data()));

    std::size_t split_pos = 0;

    if (pos.arg == "hoststart") {
        const auto offset = helpers::do_operation(0, pos.operation, pos.offset);
        split_pos = sni_str_pos + offset;
    } else if (pos.arg == "hostend") {
        const auto offset = helpers::do_operation(sni_str.size(), pos.operation, pos.offset);
        split_pos = sni_str_pos + offset;
    } else if (pos.arg == "hostmid") {
        const auto offset = helpers::do_operation(sni_str.size() / 2, pos.operation, pos.offset);
        split_pos = sni_str_pos + offset;
    } else if (pos.arg == "sniext") {
        split_pos = helpers::do_operation(sniext_offset, pos.operation, pos.offset);
    } else {
        const auto offset = pos.offset;
        split_pos = offset;
    }

    auto [iter, split_pos_relative_to_packet] = helpers::find_packet_by_offset(packets, split_pos);
    // split iter packet at split_pos_relative_to_packet
    if (split_pos_relative_to_packet == 0) {
        // already split naturally
        return true;
    }

    helpers::split_and_insert_packets(iter, split_pos_relative_to_packet, packets);
    return true;
}

bool split::split_other(std::vector<Packet> &packets, const Split &pos, const std::vector<char>& full_payload)
{
    const auto split_pos = pos.offset;

    auto [iter, split_pos_relative_to_packet] = helpers::find_packet_by_offset(packets, split_pos);
    // split iter packet at split_pos_relative_to_packet
    if (split_pos_relative_to_packet == 0) {
        // already split naturally
        return true;
    }

    helpers::split_and_insert_packets(iter, split_pos_relative_to_packet, packets);
    return true;
}