//
// Created by klewy on 8/15/26.
//

#include "http_classifier.hpp"

#include <netinet/in.h>
#include "../packet_view.hpp"
#include "../conn_tracker.hpp"
#include "../consts.hpp"

ParseResult HttpClassifier::buffer_pkt(Connection &conn, const PacketView &pkt)
{
    if (conn.get_reasm_frags().empty()) { // if first fragment
        conn.set_reasm_total_size(HTTP_PARSE_LIMIT);
        conn.set_payload_proto(L7Proto::HTTP);
    }

    conn.add_reasm_frag(pkt.packet);
    conn.set_reasm_pos(conn.get_reasm_pos() + pkt.payload.size());

    if (auto seq_opt = pkt.get_seq(); seq_opt.has_value()) {
        conn.set_reasm_expected_seq(seq_opt.value() + static_cast<std::uint32_t>(pkt.payload.size()));
    }

    if (!conn.get_reasm_frags().empty()) { // if not the first fragment
        if (conn.get_reasm_pos() >= conn.get_reasm_total_size()) {
            return ParseResult::ERROR;
        }

        std::string full_http;
        full_http.reserve(conn.get_reasm_pos());
        for (const auto &frag : conn.get_reasm_frags()) {
            const PacketView pkt_frag = parse_packet(frag);
            full_http.insert(
                full_http.end(), frag.begin() + static_cast<std::ptrdiff_t>(pkt_frag.headers_len), frag.end());
        }

        if (full_http.contains("\r\n\r\n")) {
            return ParseResult::SUCCESS_REASSEMBLED;
        }
    }

    return ParseResult::REASSEMBLING;
}

ParseResult HttpClassifier::classify(const PacketView &pkt, ConnTracker *tracker)
{
    auto &conn =
        tracker->get_conn(pkt.network_hdr->saddr, pkt.get_source_port(), pkt.network_hdr->daddr, pkt.get_dest_port());
    if (conn.payload_proto() == L7Proto::HTTP
        && conn.get_reasm_pos() > 0 && (pkt.get_seq() == conn.get_reasm_expected_seq())) {
        return buffer_pkt(conn, pkt);
    }

    std::string_view payload_str{ pkt.payload };
    // First, try to find \r\n (the status line)
    const auto crln_pos = payload_str.find("\r\n");
    if (crln_pos == std::string_view::npos) { return ParseResult::ERROR; }

    payload_str = payload_str.substr(0, crln_pos);

    // Now, try to search for "HTTP/"
    const auto http_pos = payload_str.find("HTTP/");
    if (http_pos == std::string_view::npos) {
        return ParseResult::ERROR;// HTTP string not found => not HTTP
    }

    std::string_view const full_req{ pkt.payload };
    const auto header_end_pos = full_req.find("\r\n\r\n");
    if (header_end_pos == std::string_view::npos) {
        return buffer_pkt(conn, pkt);
    }

    return ParseResult::SUCCESS;
}
