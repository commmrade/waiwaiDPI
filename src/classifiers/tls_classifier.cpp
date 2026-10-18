//
// Created by klewy on 8/15/26.
//

#include "tls_classifier.hpp"
#include "conn_tracker.hpp"
#include <cstring>
#include <print>

std::expected<ClassifyResult, std::string> TlsHandshakeClassifier::classify(const std::vector<char> &payload)
{
    constexpr auto TLS_HDR_LEN = 5;
    if (payload.size() < TLS_HDR_LEN) {
        return std::unexpected{ "Could not classify as TLS because packet is too small" };
    }
    constexpr auto TLS_HANDSHAKE_TYPE = 0x16;
    constexpr auto TLS_VERSION_MAJOR = 0x03;

    if (payload[0] != TLS_HANDSHAKE_TYPE || payload[1] != TLS_VERSION_MAJOR
        || (payload[2] != 0x01 && payload[2] != 0x03)) {
        return std::unexpected{ "Could not classify as TLS because packet header is not TLS" };
    }

    std::uint16_t tls_len{};
    std::memcpy(&tls_len, std::next(payload.data(), 3), sizeof(std::uint16_t));
    tls_len = ntohs(tls_len);

    if (payload.size() < tls_len + TLS_HDR_LEN) {// fragmented
        return { ClassifyResult::REASSEMBLING };
    }

    return { ClassifyResult::DONE };
}
