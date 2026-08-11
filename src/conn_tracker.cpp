//
// Created by klewy on 8/10/26.
//

#include "conn_tracker.hpp"

#include <cassert>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void ConnTracker::track(std::span<const char> packet)
{
    const auto* iph = reinterpret_cast<const iphdr*>(packet.data());
    const auto* tcph = reinterpret_cast<const tcphdr*>(std::next(packet.data(), iph->ihl * 4));
    const std::ptrdiff_t headers_size = (iph->ihl * 4) + (tcph->doff * 4);

    std::span<const char> const payload{std::next(packet.data(), headers_size), packet.size() - static_cast<std::size_t>(headers_size)};

    const std::tuple conn_tuple{iph->saddr, tcph->source, iph->daddr, tcph->dest};

    auto conn_iter = conns_.find(conn_tuple);
    if (conn_iter == conns_.end()) {
        auto [iter, inserted] = conns_.emplace(conn_tuple, Connection{});
        assert(inserted);
        conn_iter = iter;
    }

    conn_iter->second.set_bytes_transfered(conn_iter->second.bytes_transfered() + payload.size());
    conn_iter->second.count_packet();
}
Connection &ConnTracker::get_conn(const std::uint32_t saddr,
    const std::uint16_t source,
    const std::uint32_t daddr,
    const std::uint16_t dest)
{
    return conns_.at({saddr, source, daddr, dest});
}