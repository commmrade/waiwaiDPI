//
// Created by klewy on 8/10/26.
//

#include "conn_tracker.hpp"
#include "consts.hpp"
#include <cassert>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void ConnTracker::track(const PacketView& packet)
{
    const std::tuple conn_tuple{packet.network_hdr->saddr, packet.get_source_port(), packet.network_hdr->daddr, packet.get_dest_port()};

    auto conn_iter = conns_.find(conn_tuple);
    if (conn_iter == conns_.end()) {
        auto [iter, inserted] = conns_.emplace(conn_tuple, Connection{});
        assert(inserted);
        conn_iter = iter;
    }

    conn_iter->second.update_last_packet_time();
    conn_iter->second.set_bytes_transfered(conn_iter->second.bytes_transfered() + packet.payload.size());
    conn_iter->second.count_packet();
}
Connection &ConnTracker::get_conn(const std::uint32_t saddr,
    const std::uint16_t source,
    const std::uint32_t daddr,
    const std::uint16_t dest)
{
    return conns_.at({saddr, source, daddr, dest});
}

void ConnTracker::clear_dead_connections()
{
    auto iter = conns_.begin();
    const auto now = std::chrono::system_clock::now();
    while (iter != conns_.end()) {
        const auto dur = std::chrono::duration_cast<std::chrono::seconds>(now - iter->second.get_last_packet_time());
        if (dur.count() >= DEAD_CONNECTION_TIMEOUT_SECS) {
            iter = conns_.erase(iter);
        } else {
            ++iter;
        }
    }
}