//
// Created by klewy on 8/24/26.
//

#include "http_host_modifier.hpp"

#include "../checksum.hpp"
#include "algorithms/split.hpp"
#include "spdlog/spdlog.h"

#include <cassert>
#include <cstring>
#include <iostream>
#include <print>
#include <ranges>


static bool host_list(const std::string_view hostname)
{
    return hostname == "httpforever.com" || hostname == "soundcloud.com";
}

bool HttpHostModifier::modify(std::vector<Packet> &vec, const Connection& conn)
{
    return split::split(vec, split::SplitConfig{split_at_, std::nullopt}, conn);
}
bool HttpHostModifier::matches(const std::uint8_t l4_proto, const L7Proto l7_proto) const
{
    return l7_proto == L7Proto::HTTP && l4_proto == IPPROTO_TCP;
}
void HttpHostModifier::parse_config(const toml::table *table)
{
    const auto split_node = table->get("split_at");
    if (split_node != nullptr) {
        if (split_node->is_number()) {
            split_at_.offset = static_cast<std::size_t>(split_node->as_integer()->get());
        } else {
            // Supported values: hoststart, hostend, hostmid, numbers (relative from hoststart start)
            const auto split_str = split_node->as_string()->get();
            split_at_ = parse_split(split_str);
        }
    } else {
        SPDLOG_WARN("'split_at' parameter for {} is not specified, but it defaults to 0", HttpHostModifier::name());
    }
}
