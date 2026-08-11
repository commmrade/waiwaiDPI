//
// Created by klewy on 8/10/26.
//
#include "classifier.hpp"

#include "conn_tracker.hpp"

#include <cassert>
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


bool Classifier::try_tls_handshake(const iphdr* iph, const tcphdr* tcph, std::span<const char> packet, std::span<const char> payload)
{
    auto& conn = tracker_->get_conn(iph->saddr, tcph->source, iph->daddr, tcph->dest);
    if (conn.payload_proto() == L7Proto::TLS_HANDSHAKE && conn.reasm_.pos > 0 /* && conn.tcp_next_expected == tcph->seq */) {
        conn.reasm_.frags.emplace_back(packet.begin(), packet.end());
        conn.reasm_.pos += payload.size();
        conn.reasm_.expected_seq = static_cast<std::uint32_t>(ntohl(tcph->seq) + payload.size());

        if (conn.reasm_.pos == conn.reasm_.total_size) {
            return true; // we got the whole TLS client hello, hooray
        }

        return false;
    }

    if (payload.size() < 5) {
        return false; // weird shit, packet is probably broken
    }

    constexpr auto TLS_HANDSHAKE_TYPE = 0x16;
    if (payload[0] != TLS_HANDSHAKE_TYPE && payload[1] != 0x03 && payload[2] != 0x03) {
        return false; // it is not TLS handshake
    }

    std::uint16_t tls_len{};
    std::memcpy(&tls_len, payload.data() + 3, sizeof(std::uint16_t));
    tls_len = ntohs(tls_len);

    if (payload.size() < tls_len) { // fragmented, fuck
        conn.reasm_.frags.emplace_back(packet.begin(), packet.end());
        conn.reasm_.pos += payload.size();
        conn.reasm_.expected_seq = static_cast<std::uint32_t>(ntohl(tcph->seq) + payload.size());
        conn.reasm_.total_size = tls_len + 5; // +5 for record header
        conn.set_payload_proto(L7Proto::TLS_HANDSHAKE);

        return false; // this way packet won't be sent to modifier
    }

    return true;
}
L7Proto Classifier::try_payload(std::span<const char> packet)
{
    const auto* iph = reinterpret_cast<const iphdr*>(packet.data());
    const auto* tcph = reinterpret_cast<const tcphdr*>(std::next(packet.data(), iph->ihl * 4));
    const std::ptrdiff_t headers_size = iph->ihl * 4 + tcph->doff * 4;

    std::span<const char> const payload{std::next(packet.data(), headers_size), packet.size() - static_cast<std::size_t>(headers_size)};

    { // HTTP Block
        if (try_http(payload)) {
            return L7Proto::HTTP;
        }
    }

    { // TLS Block
        if (try_tls_handshake(iph, tcph, packet, payload)) {
            return L7Proto::TLS_HANDSHAKE;
        }
    }

    return L7Proto::UNKNOWN;
}

Packet Classifier::classify(std::span<const char> packet)
{
    Packet pkt;
    pkt.packet = packet;

    const auto* iph = reinterpret_cast<const iphdr*>(packet.data());
    const auto* tcph = reinterpret_cast<const tcphdr*>(std::next(packet.data(), iph->ihl * 4));
    const std::size_t headers_size = iph->ihl * 4 + tcph->doff * 4;
    std::span<const char> const payload{packet.data() + headers_size, packet.size() - headers_size};

    if (payload.empty()) {
        return pkt;
    }

    pkt.payload = payload;
    pkt.payload_proto = try_payload(packet);

    return pkt;
}