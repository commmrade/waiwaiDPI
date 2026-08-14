//
// Created by klewy on 8/10/26.
//
#include "classifier.hpp"

#include "conn_tracker.hpp"
#include "consts.hpp"

#include <cassert>
#include <cstdint>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <print>
#include <string_view>

ParseResult Classifier::try_http(const Packet& pkt)
{
    auto& conn = tracker_->get_conn(pkt.network_hdr->saddr, pkt.get_source_port(), pkt.network_hdr->daddr, pkt.get_dest_port());
    if (conn.payload_proto() == L7Proto::HTTP && conn.get_reasm_pos() > 0 /* && conn.tcp_next_expected == tcph->seq */) {
        conn.add_reasm_frag(pkt.packet);
        conn.set_reasm_pos(conn.get_reasm_pos() + pkt.payload.size());

        if (pkt.transport_proto == IPPROTO_TCP) {
            const auto* tcph = std::get<const tcphdr*>(pkt.transport_hdr);
            conn.set_reasm_expected_seq(static_cast<std::uint32_t>(ntohl(tcph->seq) + pkt.payload.size()));
        }

        if (conn.get_reasm_pos() >= conn.get_reasm_total_size()) {
            // Drop conn? or it is fine
            return ParseResult::ERROR;
        }

        std::string full_http;
        full_http.reserve(conn.get_reasm_pos());
        for (const auto& frag : conn.get_reasm_frags()) {
            const Packet pkt_frag{frag};
            full_http.insert(full_http.end(), frag.begin() + static_cast<std::ptrdiff_t>(pkt_frag.headers_len), frag.end());
        }

        if (full_http.contains("\r\n\r\n")) {
            return ParseResult::SUCCESS;
        }

        return ParseResult::REASSEMBLING;
    }

    std::string_view payload_str{pkt.payload};
    // First, try to find \r\n (the status line)
    const auto crln_pos = payload_str.find("\r\n");
    if (crln_pos == std::string_view::npos) {
        return ParseResult::ERROR;
    }

    payload_str = payload_str.substr(0, crln_pos);

    // Now, try to search for "HTTP/"
    const auto http_pos = payload_str.find("HTTP/");
    if (http_pos == std::string_view::npos) {
        return ParseResult::ERROR; // HTTP string not found => not HTTP
    }

    std::string_view const full_req{pkt.payload};
    const auto header_end_pos = full_req.find("\r\n\r\n");
    if (header_end_pos == std::string_view::npos) {
        conn.add_reasm_frag(pkt.packet);
        conn.set_reasm_pos(conn.get_reasm_pos() + pkt.payload.size());

        if (pkt.transport_proto == IPPROTO_TCP) {
            const auto* tcph = std::get<const tcphdr*>(pkt.transport_hdr);
            conn.set_reasm_expected_seq(static_cast<std::uint32_t>(ntohl(tcph->seq) + pkt.payload.size()));
        }
        conn.set_reasm_total_size(HTTP_PARSE_LIMIT);
        conn.set_payload_proto(L7Proto::HTTP);

        return ParseResult::REASSEMBLING;
    }

    return ParseResult::SUCCESS;
}


ParseResult Classifier::try_tls_handshake(const Packet& pkt)
{
    auto& conn = tracker_->get_conn(pkt.network_hdr->saddr, pkt.get_source_port(), pkt.network_hdr->daddr, pkt.get_dest_port());
    if (conn.payload_proto() == L7Proto::TLS_HANDSHAKE && conn.get_reasm_pos() > 0 /* && conn.tcp_next_expected == tcph->seq */) {
        conn.add_reasm_frag(pkt.packet);
        conn.set_reasm_pos(conn.get_reasm_pos() + pkt.payload.size());

        if (pkt.transport_proto == IPPROTO_TCP) {
            const auto* tcph = std::get<const tcphdr*>(pkt.transport_hdr);
            conn.set_reasm_expected_seq(static_cast<std::uint32_t>(ntohl(tcph->seq) + pkt.payload.size()));
        }

        if (conn.get_reasm_pos() == conn.get_reasm_total_size()) {
            return ParseResult::SUCCESS; // we got the whole TLS client hello, hooray
        }

        return ParseResult::REASSEMBLING;
    }

    if (pkt.payload.size() < 5) {
        return ParseResult::ERROR; // weird shit, packet is probably broken
    }

    constexpr auto TLS_HANDSHAKE_TYPE = 0x16;
    if (pkt.payload[0] != TLS_HANDSHAKE_TYPE && pkt.payload[1] != 0x03 && pkt.payload[2] != 0x03) {
        return ParseResult::ERROR; // it is not TLS handshake
    }

    std::uint16_t tls_len{};
    std::memcpy(&tls_len, pkt.payload.data() + 3, sizeof(std::uint16_t));
    tls_len = ntohs(tls_len);

    if (pkt.payload.size() < tls_len) { // fragmented, fuck
        conn.add_reasm_frag(pkt.packet);
        conn.set_reasm_pos(conn.get_reasm_pos() + pkt.payload.size());

        if (pkt.transport_proto == IPPROTO_TCP) {
            const auto* tcph = std::get<const tcphdr*>(pkt.transport_hdr);
            conn.set_reasm_expected_seq(static_cast<std::uint32_t>(ntohl(tcph->seq) + pkt.payload.size()));
        }
        conn.set_reasm_total_size(tls_len + 5);
        conn.set_payload_proto(L7Proto::TLS_HANDSHAKE);

        return ParseResult::REASSEMBLING; // this way packet won't be sent to modifier
    }

    return ParseResult::SUCCESS;
}
L7Proto Classifier::try_payload(const Packet& pkt)
{
    assert(!pkt.payload.empty()); //NOLINT

    { // HTTP Block
        switch (try_http(pkt)) {
            case ParseResult::SUCCESS: {
                return L7Proto::HTTP;
            }
            case ParseResult::REASSEMBLING: {
                return L7Proto::REASSEMBLING;
            }
            default: {}
        }
    }

    { // TLS Block
        switch (try_tls_handshake(pkt)) {
            case ParseResult::SUCCESS: {
                return L7Proto::TLS_HANDSHAKE;
            }
            case ParseResult::REASSEMBLING: {
                return L7Proto::REASSEMBLING;
            }
            default: {}
        }
    }

    return L7Proto::UNKNOWN;
}

Packet Classifier::classify(Packet& pkt)
{
    if (pkt.payload.empty()) {
        return pkt;
    }

    pkt.payload_proto = try_payload(pkt);
    return pkt;
}