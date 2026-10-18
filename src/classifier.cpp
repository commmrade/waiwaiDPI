//
// Created by klewy on 8/10/26.
//


#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_TRACE
#include "classifier.hpp"
#include "conn_tracker.hpp"
#include "modifiers/algorithms/common.hpp"
#include <spdlog/spdlog.h>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <print>

void Classifier::add(std::unique_ptr<PayloadClassifier> &&classifier)
{
    classifiers_.emplace_back(std::move(classifier));
}

std::pair<ClassifyResult, std::optional<L7Proto>> Classifier::classify(const std::vector<Packet> &packets)
{
    const auto full_payload = concat(packets);

    int reasm_counter = 0;
    for (const auto &classifier : classifiers_) {
        auto res = classifier->classify(full_payload);
        if (res) {
            switch (res.value()) {
            case ClassifyResult::DONE: {
                return { ClassifyResult::DONE, { classifier->protocol() } };
            }
            case ClassifyResult::REASSEMBLING: {
                ++reasm_counter;
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

    if (reasm_counter) { return { ClassifyResult::REASSEMBLING, std::nullopt }; }

    return { ClassifyResult::ERROR, std::nullopt };
}