//
// Created by klewy on 9/7/26.
//

#include "tls_modifier.hpp"
#include <cassert>
#include <iostream>
#include <print>
#include "../checksum.hpp"

std::optional<std::string_view> TlsHandshakeModifier::get_sni(std::span<const char> payload)
{
    assert(payload.size() >= 5);

    // header checks
    constexpr auto TLS_HANDSHAKE_TYPE = 0x16;
    if (payload[0] != TLS_HANDSHAKE_TYPE) {
        // std::println(std::cerr, "TLS handshake type is wrong");
        return std::nullopt;
    }

    if (payload[1] != 0x03 && payload[2] != 0x03) { // legacy field, almost always 0303
        return std::nullopt;
    }

    // content stuff
    payload = payload.subspan(5); // skip header bytes, get to content

    if (payload[0] != 0x01) { // content type is not ClientHello
        // std::println(std::cerr, "Content type is not ClientHello");
        return std::nullopt;
    }

    payload = payload.subspan(38); // skip type(1) + length(3) + legacyVersion(2) + random(32) fields

    const auto legacy_session_id_len = static_cast<std::uint8_t>(payload[0]);
    payload = payload.subspan(sizeof(legacy_session_id_len) + legacy_session_id_len);

    std::uint16_t cipher_suites_len = 0;
    std::memcpy(&cipher_suites_len, payload.data(), sizeof(cipher_suites_len));
    cipher_suites_len = ntohs(cipher_suites_len);

    payload = payload.subspan(sizeof(cipher_suites_len) + cipher_suites_len + 2); // + 2 for "LegacyCompressionMethods" field

    // parse extensions (sni is here) (loop)
    std::uint16_t exts_len = 0;
    std::memcpy(&exts_len, payload.data(), sizeof(exts_len));
    exts_len = ntohs(exts_len);

    payload = payload.subspan(sizeof(exts_len));

    while (!payload.empty()) {
        std::uint16_t ext_type = 0;
        std::memcpy(&ext_type, payload.data(), sizeof(ext_type));
        ext_type = ntohs(ext_type);

        payload = payload.subspan(sizeof(ext_type));

        std::uint16_t ext_len = 0;
        std::memcpy(&ext_len, payload.data(), sizeof(ext_len));
        ext_len = ntohs(ext_len);

        constexpr auto EXT_SNI_TYPE = 0x00;
        if (ext_type != EXT_SNI_TYPE) {
            payload = payload.subspan(sizeof(ext_len) + ext_len);
            continue;
        }

        payload = payload.subspan(sizeof(ext_len));

        std::uint16_t serv_name_list_len = 0;
        std::memcpy(&serv_name_list_len, payload.data(), sizeof(serv_name_list_len));
        serv_name_list_len = ntohs(serv_name_list_len);

        assert(payload[2] == 0x00); // name type is a host name

        payload = payload.subspan(sizeof(serv_name_list_len) + 1); // +1 for name type

        std::uint16_t hostname_len = 0;
        std::memcpy(&hostname_len, payload.data(), sizeof(hostname_len));
        hostname_len = ntohs(hostname_len);

        return std::string_view{std::next(payload.data(), sizeof(hostname_len)), static_cast<std::size_t>(hostname_len)};
    }

    // std::println(std::cerr, "Haven't found a SNI extension");

    return std::nullopt;
}

bool TlsHandshakeModifier::modify(std::vector<Packet> &vec)
{
    std::vector<char> full_payload;
    for (const auto& pkt : vec) {
        const auto payload = pkt.payload();
        full_payload.insert(full_payload.end(), payload.begin(), payload.end());
    }

    // Parse and find the SNI extension
    const auto sni_opt = get_sni(full_payload);
    if (!sni_opt.has_value()) {
        std::println(std::cerr, "SNI Extension was not found in this handshake");
        return false;
    }

    const auto& sni_str = sni_opt.value();
    const auto sni_str_pos = std::distance(static_cast<const char*>(full_payload.data()), sni_str.data());

    constexpr auto SPLIT_POS = 3;
    const auto split_at_global_pos = static_cast<std::size_t>(sni_str_pos) + SPLIT_POS;
    if (split_at_global_pos >= full_payload.size()) {
        std::print(std::cerr, "Split pos is really wrong, reduce it.");
        return false;
    }

    auto iter = vec.begin();
    std::size_t offset = 0;
    std::size_t split_pos_relative_to_packet = 0;
    for (; iter != vec.end(); ++iter) {
        offset += iter->payload().size();
        if (split_at_global_pos < offset) {
            split_pos_relative_to_packet = split_at_global_pos - (offset - iter->payload().size());
            break;
        }
    }
    assert(iter != vec.end());

    if (split_pos_relative_to_packet == 0) { // split is naturally at packet borders
        return false;
    }

    auto& pkt = *iter;
    const auto pkt_view = parse_packet_view(pkt);
    const auto pkt_payload = pkt.payload();
    const std::span<const char> part1{pkt_payload.begin(), std::next(pkt_payload.begin(), static_cast<std::ptrdiff_t>(split_pos_relative_to_packet))};
    const std::span<const char> part2{std::next(pkt_payload.begin(), static_cast<std::ptrdiff_t>(split_pos_relative_to_packet)), pkt_payload.end()};

    Packet first_packet = create_packet_from(pkt_view, part1);
    first_packet.action.action = PacketAction::Action::DROP_AND_SEND;

    auto* tcp = static_cast<tcphdr*>(first_packet.transport_hdr());
    tcp->check = 0;
    tcp->check = calc_tcp_checksum(first_packet);

    Packet second_packet = create_packet_from(pkt_view, part2);
    second_packet.action.action = PacketAction::Action::SEND;
    second_packet.action.packet_id = 0;

    tcp = static_cast<tcphdr*>(second_packet.transport_hdr());
    tcp->seq = htonl(ntohl(tcp->seq) + static_cast<std::uint32_t>(part1.size()));
    tcp->check = 0;
    tcp->check = calc_tcp_checksum(second_packet);

    iter = vec.erase(iter);
    iter = vec.insert(iter, std::move(first_packet));
    vec.insert(iter + 1, std::move(second_packet));

    return true;
}

bool TlsHandshakeModifier::matches(const std::uint8_t l4_proto, const L7Proto l7_proto) const
{
    return l4_proto == IPPROTO_TCP && l7_proto == L7Proto::TLS_HANDSHAKE;
}