//
// Created by klewy on 8/10/26.
//
#include "classifier.hpp"

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string_view>

bool Classifier::try_http(std::span<const char> payload)
{
    std::string_view payload_str{payload};
    // First, try to find \r\n (the status line)
    const auto crln_pos = payload_str.find("\r\n");
    if (crln_pos == std::string_view::npos) {
        return false; // no \r\n is pretty weird so it is probably not HTTP
    }

    payload_str = payload_str.substr(0, crln_pos);

    // Now, try to search for "HTTP/"
    const auto http_pos = payload_str.find("HTTP/");
    if (http_pos == std::string_view::npos) {
        return false; // HTTP string not found => not HTTP
    }

    return true;
}


bool Classifier::try_tls(std::span<const char> payload)
{
    return true;
}

Packet Classifier::classify(std::span<const char> packet)
{
    Packet pkt;
    pkt.packet = packet;

    const iphdr* iph = reinterpret_cast<const iphdr*>(packet.data());
    const tcphdr* tcph = reinterpret_cast<const tcphdr*>(packet.data() + iph->ihl * 4);
    const std::size_t headers_size = iph->ihl * 4 + tcph->doff * 4;

    std::span<const char> payload{packet.data() + headers_size, packet.size() - headers_size};

    pkt.payload = payload;

    { // HTTP Block
        if (try_http(payload)) {
            pkt.payload_proto = L7Proto::HTTP;
        }
    }

    { // TLS Block
        if (try_tls(payload)) {
            pkt.payload_proto = L7Proto::TLS;
        }
    }

    return pkt;
}