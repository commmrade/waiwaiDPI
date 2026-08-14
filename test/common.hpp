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


inline std::vector<char> construct_packet_from(std::span<const char> payload, const iphdr* old_ip, const tcphdr* old_tcp) {
    std::vector<char> packet;
    packet.resize(payload.size() + old_ip->ihl * 4 + old_tcp->doff * 4);

    char* ptr = packet.data();
    iphdr* ip = reinterpret_cast<iphdr*>(ptr);

    const std::size_t ip_hdr_size = old_ip->ihl * 4;
    std::memcpy(ip, old_ip, ip_hdr_size);
    ptr += ip_hdr_size;

    tcphdr* tcp = reinterpret_cast<tcphdr*>(ptr);
    const std::size_t tcp_hdr_size = old_tcp->doff * 4;
    std::memcpy(tcp, old_tcp, tcp_hdr_size);
    ptr += tcp_hdr_size;

    std::memcpy(ptr, payload.data(), payload.size());

    ip->tot_len = htons(old_ip->ihl * 4 + old_tcp->doff * 4 + payload.size());

    return packet;
}


#endif// WAIWAIDPI_COMMON_HPP
