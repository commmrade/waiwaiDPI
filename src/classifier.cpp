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


std::expected<L7Proto, ParseResult> Classifier::try_payload(PacketView &pkt)
{
    bool got_error = false;
    for (const auto &classifier : classifiers_) {
        switch (classifier->classify(pkt, tracker_.get())) {
        case ParseResult::SUCCESS: {
            return { classifier->protocol() };
        }
        case ParseResult::SUCCESS_REASSEMBLED: {
            pkt.is_payload_reasm = true;
            return { classifier->protocol() };
        }
        case ParseResult::REASSEMBLING: {
            pkt.is_payload_reasm = true;
            return std::unexpected{ ParseResult::REASSEMBLING };
        }
        case ParseResult::ERROR: {
            got_error = true;
            break;
        }
        default: {
        }
        }
    }

    if (got_error) { return std::unexpected{ ParseResult::ERROR }; }
    return { L7Proto::UNKNOWN };
}

void Classifier::add(std::unique_ptr<PayloadClassifier> &&classifier)
{
    classifiers_.emplace_back(std::move(classifier));
}

ParseResult Classifier::classify(PacketView &pkt)
{
    const auto payload_parse_res = try_payload(pkt);
    if (payload_parse_res.has_value()) {
        pkt.payload_proto = payload_parse_res.value();
    } else {
        return payload_parse_res.error();
    }

    return ParseResult::SUCCESS;
}