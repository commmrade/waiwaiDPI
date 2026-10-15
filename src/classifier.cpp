//
// Created by klewy on 8/10/26.
//


#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_TRACE
#include "classifier.hpp"
#include "conn_tracker.hpp"
#include "consts.hpp"
#include <spdlog/spdlog.h>

#include <cassert>
#include <cstdint>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <print>
#include <string_view>


ParseResult Classifier::try_payload(Connection& conn)
{
    for (const auto &classifier : classifiers_) {
        auto res = classifier->classify(conn);
        if (res) {
            switch (res.value()) {
            case ParseResult::SUCCESS: {
                return res.value();
            }
            case ParseResult::REASSEMBLING: {
                continue;
            }
            default: {
                break;
            }
            }
        } else {
            SPDLOG_WARN("Was not able to classify a packet: {}", res.error());
        }
    }

    return ParseResult::REASSEMBLING;
}

void Classifier::add(std::unique_ptr<PayloadClassifier> &&classifier)
{
    classifiers_.emplace_back(std::move(classifier));
}

ParseResult Classifier::classify(Connection& conn)
{
    const auto payload_parse_res = try_payload(conn);
    return payload_parse_res;
}