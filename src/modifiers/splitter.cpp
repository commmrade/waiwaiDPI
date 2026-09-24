//
// Created by klewy on 9/24/26.
//

#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_TRACE
#include "spdlog/spdlog.h"
#include "splitter.hpp"

#include "algorithms/split.hpp"

bool Splitter::modify(std::vector<Packet> &vec, const Connection& conn)
{
    // Go through each split and split at that position
    bool failed = false;
    if (!splits_.empty()) {
        std::vector<char> full_payload;
        for (const auto& pkt : vec) {
            const auto payload = pkt.payload();
            full_payload.insert(full_payload.end(), payload.begin(), payload.end());
        }

        for (const auto& split_pos : splits_) {
            if (!split::split(vec, split::SplitConfig{split_pos, allowed_hosts_}, conn)) {
                SPDLOG_WARN("Wasn't able to split packet at {}:{}", split_pos.arg, split_pos.offset);
                failed = true;
            }
        }
    }

    return !failed;
}

bool Splitter::matches([[maybe_unused]] const std::uint8_t l4_proto, [[maybe_unused]] const L7Proto l7_proto) const
{
    return true;
}

void Splitter::parse_config(const toml::table *table)
{
    const auto* split_node = table->get("split_at");
    if (split_node != nullptr) {
        if (!split_node->is_array()) {
            throw std::runtime_error(std::format("split_at must be an array for '{}'", Splitter::name()));
        }

        for (const auto& node : *split_node->as_array()) {
            Split new_split{};
            if (node.is_number()) {
                new_split.offset = static_cast<std::size_t>(node.as_integer()->get());
            } else {
                const auto split_str = node.as_string()->get();
                new_split = parse_split(split_str);
            }
            splits_.push_back(std::move(new_split));
        }
    } else {
        SPDLOG_WARN("'split_at' parameter for {} is not specified, but it defaults to 0", Splitter::name());
    }

    const auto* hosts_node = table->get("allowed_hosts");
    if (hosts_node != nullptr) {
        auto& allowed_hosts = allowed_hosts_.emplace();

        if (!hosts_node->is_array()) {
            throw std::runtime_error("allowed_hosts must be an array");
        }

        const auto* hosts_array = hosts_node->as_array();
        allowed_hosts.reserve(hosts_array->size());
        for (const auto& node : *hosts_array) {
            if (!node.is_string()) {
                throw std::runtime_error("All hosts must be strings");
            }

            allowed_hosts.insert(node.as_string()->get());
        }
    }
}