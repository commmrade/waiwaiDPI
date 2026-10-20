//
// Created by klewy on 8/31/26.
//

#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_TRACE
#include <spdlog/spdlog.h>
#include "modifier.hpp"
#include "algorithms/common.hpp"

void Modifier::modify(std::vector<Packet> &vec, const Connection &conn)
{
    auto full_payload = concat(vec);
    const auto markers = find_markers(full_payload, conn.payload_proto());
    if (!markers) {
        SPDLOG_WARN("Modifier: could not find markers, aborting");
        return;
    }

    ModifyContext ctx {
        .full_payload = full_payload,
        .markers = markers.value(),
        .conn = conn,
    };

    for (auto &modifier : modifiers_) {
        if (!modifier->matches(vec, conn)) {
            continue;
        }

        modifier->modify(vec, ctx);
    }
}