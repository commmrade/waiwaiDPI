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
        for (const auto& split_pos : splits_) {
            if (!split::split(vec, split_pos, conn)) {
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
    const auto split_node = table->get("split_at");
    if (split_node != nullptr) {
        if (!split_node->is_array()) {
            throw std::runtime_error(std::format("split_at should be an array for '{}'", Splitter::name()));
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
}