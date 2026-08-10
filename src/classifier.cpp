//
// Created by klewy on 8/10/26.
//
#include "classifier.hpp"

#include <cstdint>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <print>
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


bool Classifier::try_tls_handshake(std::span<const char> payload)
{
    // TODO: MIND THE FACT THAT TLS MAY BE SPLIT ACROSS PACKETS AND I HAVE TO USE COn. TRACKER

    if (payload.size() < 3) {
        return false; // weird shit
    }

    if (payload[0] != 0x16) {
        return false; // it maybe be TLS, but not handshake
        // we do not care about non-handshake TLS
    }

    if (payload[1] != 0x03 && payload[2] != 0x03) {
        // TODO: Fallback to Con. Tracker

        std::uint16_t tls_len{};
        std::memcpy(&tls_len, payload.data() + 3, sizeof(std::uint16_t));
        tls_len = ntohs(tls_len);

        return false; // does not look like a TLS signature
    }



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
        if (try_tls_handshake(payload)) {
            pkt.payload_proto = L7Proto::TLS_HANDSHAKE;
        }
    }

    return pkt;
}