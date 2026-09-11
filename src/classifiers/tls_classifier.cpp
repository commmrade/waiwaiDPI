//
// Created by klewy on 8/15/26.
//

#include "tls_classifier.hpp"
#include "../packet_view.hpp"
#include "../conn_tracker.hpp"
#include <print>
#include <cstring>

ParseResult TlsHandshakeClassifier::buffer_pkt(Connection &conn, const PacketView &pkt, std::optional<std::size_t> tls_len)
{
    constexpr auto TLS_RECORD_MAX_SIZE = 1 << 14;
    if (conn.get_reasm_frags().empty() && tls_len.has_value()) {
        if (tls_len.value() > TLS_RECORD_MAX_SIZE) {
            return ParseResult::ERROR;
        }

        conn.set_reasm_total_size(tls_len.value());
        conn.set_payload_proto(L7Proto::TLS_HANDSHAKE);
    }

    conn.add_reasm_frag(pkt);
    conn.set_reasm_pos(conn.get_reasm_pos() + pkt.payload.size());

    if (auto seq_opt = pkt.get_seq(); seq_opt.has_value()) {
        conn.set_reasm_expected_seq(seq_opt.value() + static_cast<std::uint32_t>(pkt.payload.size()));
    }

    if (!conn.get_reasm_frags().empty()) {
        if (conn.get_reasm_pos() >= conn.get_reasm_total_size()) {
            return ParseResult::SUCCESS_REASSEMBLED;// we got the whole TLS client hello, hooray
        }
    }

    return ParseResult::REASSEMBLING;
}

ParseResult TlsHandshakeClassifier::classify(const PacketView &pkt, ConnTracker& tracker)
{
    auto &conn =
       tracker.get_conn(pkt.network_hdr->saddr, pkt.get_source_port(), pkt.network_hdr->daddr, pkt.get_dest_port(), pkt.network_hdr->protocol);
    if (conn.payload_proto() == L7Proto::TLS_HANDSHAKE
        && conn.get_reasm_pos() > 0 && pkt.get_seq() == conn.get_reasm_expected_seq()) {
        return buffer_pkt(conn, pkt, std::nullopt);
    }

    constexpr auto TLS_HDR_LEN = 5;
    if (pkt.payload.size() < TLS_HDR_LEN) {
        return ParseResult::ERROR;// weird shit, packet is probably broken
    }

    constexpr auto TLS_HANDSHAKE_TYPE = 0x16;
    constexpr auto TLS_VERSION_MAJOR = 0x03;

    if (pkt.payload[0] != TLS_HANDSHAKE_TYPE ||
        pkt.payload[1] != TLS_VERSION_MAJOR ||
        (pkt.payload[2] != 0x01 && pkt.payload[2] != 0x03))
    {
        return ParseResult::ERROR; // not a TLS handshake
    }

    std::uint16_t tls_len{};
    std::memcpy(&tls_len, pkt.payload.data() + 3, sizeof(std::uint16_t));
    tls_len = ntohs(tls_len);

    if (pkt.payload.size() < tls_len + TLS_HDR_LEN) {// fragmented, fuck
        return buffer_pkt(conn, pkt, std::optional{tls_len + TLS_HDR_LEN});
    }

    conn.set_payload_proto(L7Proto::TLS_HANDSHAKE);

    return ParseResult::SUCCESS;
}
