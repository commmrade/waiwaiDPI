//
// Created by klewy on 9/5/26.
//

#include "empty_classifier.hpp"
#include "../packet_view.hpp"
#include "../conn_tracker.hpp"

ParseResult EmptyClassifier::classify(const PacketView &pkt, ConnTracker &tracker)
{
    auto &conn =
        tracker.get_conn(pkt.network_hdr->saddr, pkt.get_source_port(), pkt.network_hdr->daddr, pkt.get_dest_port(), pkt.network_hdr->protocol);
    if (pkt.payload.empty() && conn.payload_proto() == L7Proto::UNKNOWN) {
        conn.set_payload_proto(L7Proto::EMPTY);
        return ParseResult::SUCCESS;
    }

    return ParseResult::ERROR;
}
L7Proto EmptyClassifier::protocol() const
{
    return L7Proto::EMPTY;
}