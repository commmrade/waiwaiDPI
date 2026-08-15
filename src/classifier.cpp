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






std::expected<L7Proto, ParseResult> Classifier::try_payload(const PacketView &pkt)
{
    assert(!pkt.payload.empty());// NOLINT

    for (const auto& classifier : classifiers_) {
        switch (classifier->classify(pkt, tracker_)) {
            case ParseResult::SUCCESS: {
                return { classifier->protocol() };
            }
            case ParseResult::REASSEMBLING: {
                return std::unexpected{ ParseResult::REASSEMBLING };
            }
            default: {
            }
        }
    }

    return { L7Proto::UNKNOWN };
}

std::expected<PacketView, ParseResult> Classifier::classify(PacketView &pkt)
{
    if (pkt.payload.empty()) {
        pkt.payload_proto = L7Proto::EMPTY;
        return { pkt };
    }

    const auto payload_parse_res = try_payload(pkt);
    if (payload_parse_res.has_value()) {
        pkt.payload_proto = payload_parse_res.value();
    } else {
        return std::unexpected{ payload_parse_res.error() };
    }

    return pkt;
}