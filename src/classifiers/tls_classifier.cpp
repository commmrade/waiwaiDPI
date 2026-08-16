//
// Created by klewy on 8/15/26.
//

#include "tls_classifier.hpp"
#include "../packet_view.hpp"
#include "../conn_tracker.hpp"

#include <cstring>

ParseResult TlsHandshakeClassifier::classify(const PacketView &pkt, ConnTracker *tracker)
{
    auto &conn =
       tracker->get_conn(pkt.network_hdr->saddr, pkt.get_source_port(), pkt.network_hdr->daddr, pkt.get_dest_port());
    if (conn.payload_proto() == L7Proto::TLS_HANDSHAKE
        && conn.get_reasm_pos() > 0 /* && conn.tcp_next_expected == tcph->seq */) {
        conn.add_reasm_frag(pkt.packet);
        conn.set_reasm_pos(conn.get_reasm_pos() + pkt.payload.size());

        if (pkt.transport_proto == IPPROTO_TCP) {
            const auto *tcph = std::get<const tcphdr *>(pkt.transport_hdr);
            conn.set_reasm_expected_seq(static_cast<std::uint32_t>(ntohl(tcph->seq) + pkt.payload.size()));
        }

        if (conn.get_reasm_pos() == conn.get_reasm_total_size()) {
            return ParseResult::SUCCESS_REASSEMBLED;// we got the whole TLS client hello, hooray
        }

        return ParseResult::REASSEMBLING;
        }

    if (pkt.payload.size() < 5) {
        return ParseResult::ERROR;// weird shit, packet is probably broken
    }

    constexpr auto TLS_HANDSHAKE_TYPE = 0x16;
    if (pkt.payload[0] != TLS_HANDSHAKE_TYPE && pkt.payload[1] != 0x03 && pkt.payload[2] != 0x03) {
        return ParseResult::ERROR;// it is not TLS handshake
    }

    std::uint16_t tls_len{};
    std::memcpy(&tls_len, pkt.payload.data() + 3, sizeof(std::uint16_t));
    tls_len = ntohs(tls_len);

    if (pkt.payload.size() < tls_len) {// fragmented, fuck
        conn.add_reasm_frag(pkt.packet);
        conn.set_reasm_pos(conn.get_reasm_pos() + pkt.payload.size());

        if (pkt.transport_proto == IPPROTO_TCP) {
            const auto *tcph = std::get<const tcphdr *>(pkt.transport_hdr);
            conn.set_reasm_expected_seq(static_cast<std::uint32_t>(ntohl(tcph->seq) + pkt.payload.size()));
        }
        conn.set_reasm_total_size(tls_len + 5);
        conn.set_payload_proto(L7Proto::TLS_HANDSHAKE);

        return ParseResult::REASSEMBLING;// this way packet won't be sent to modifier
    }

    return ParseResult::SUCCESS;
}
