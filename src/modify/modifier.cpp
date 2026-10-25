//
// Created by klewy on 8/31/26.
//

#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_TRACE
#include "modifier.hpp"
#include "algorithms/common.hpp"
#include <algorithm>
#include <spdlog/spdlog.h>
#include <vector>
#include <ranges>

bool Modifier::filter(const std::vector<Packet> &packets, std::span<const char> full_payload, const Markers &markers)
{
    if (ips_.has_value()) {
        if (!std::ranges::contains(ips_.value(), packets.front().network_hdr()->saddr)) { return false; }
    }
    if (hosts_.has_value()) {
        if (!markers.hoststart.has_value() || !markers.hostend.has_value()) { return true; }

        const std::string_view host{ full_payload.begin() + static_cast<std::ptrdiff_t>(markers.hoststart.value()),
            full_payload.begin() + static_cast<std::ptrdiff_t>(markers.hostend.value()) };
        if (!std::ranges::contains(hosts_.value(), host)) { return false; }
    }

    return true;
}

void Modifier::modify(std::vector<Packet> &vec, const Connection &conn)
{
    auto filtered_packets = std::ranges::views::filter(vec, [](const Packet &packet) {
        return !packet.is_fake_blob;
    });

    auto full_payload = concat(filtered_packets);
    const auto markers = find_markers(full_payload, conn.payload_proto());
    if (!markers) {
        SPDLOG_WARN("Modifier: could not find markers, aborting");
        return;
    }

    if (!filter(vec, full_payload, markers.value())) { return; }

    ModifyContext ctx{
        .full_payload = full_payload,
        .markers = markers.value(),
        .conn = conn,
    };

    for (auto &modifier : modifiers_) {
        if (!modifier->matches(vec, conn)) { continue; }

        modifier->modify(vec, ctx);
    }
}