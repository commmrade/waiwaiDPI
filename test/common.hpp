//
// Created by klewy on 8/14/26.
//

#ifndef WAIWAIDPI_COMMON_HPP
#define WAIWAIDPI_COMMON_HPP

#include <arpa/inet.h>
#include <catch2/catch_all.hpp>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "../src/classifier.hpp"
#include "../src/conn_tracker.hpp"


struct Context
{
    Classifier* classifier{nullptr};
    ConnTracker* tracker{nullptr};
};

inline void process_packet(Context* ctx, std::span<const char> packet)
{
    const iphdr* ip = reinterpret_cast<const iphdr*>(packet.data());
    // TODO: WHy only tcp??
    const tcphdr* tcp = reinterpret_cast<const tcphdr*>(packet.data() + ip->ihl * 4);

    std::array<char, INET_ADDRSTRLEN> ip_src{};
    std::array<char, INET_ADDRSTRLEN> ip_dst{};
    inet_ntop(AF_INET, &ip->saddr, ip_src.data(), ip_src.size());
    inet_ntop(AF_INET, &ip->daddr, ip_dst.data(), ip_dst.size());

    ctx->tracker->track(packet);
    auto& conn = ctx->tracker->get_conn(ip->saddr, tcp->source, ip->daddr, tcp->dest);

    if (!conn.is_done()) {
        auto cfed_pkt = ctx->classifier->classify(packet);
        if (cfed_pkt.payload_proto == L7Proto::HTTP) {
        } else if (cfed_pkt.payload_proto == L7Proto::TLS_HANDSHAKE) {
            if (std::strcmp(ip_dst.data(), "95.85.248.84") == 0) {
                conn.set_done(true);
            }
        }
    }
}

#endif// WAIWAIDPI_COMMON_HPP
