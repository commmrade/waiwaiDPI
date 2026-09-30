//
// Created by klewy on 8/10/26.
//

#ifndef WAIWAIDPI_PROTOCOL_HPP
#define WAIWAIDPI_PROTOCOL_HPP
#include <stdexcept>
#include <string_view>

enum class L7Proto
{
    UNKNOWN, // Unknown payload, but packets may be modified
    EMPTY,
    // REASSEMBLING, // In this case payload isn't assembled and packets should be held, packets can't be modified
    HTTP,
    TLS_HANDSHAKE,
    QUIC_INITIAL
};

inline L7Proto string_to_proto(const std::string_view str)
{
    if (str == "tls_handshake") {
        return L7Proto::TLS_HANDSHAKE;
    } else if (str == "http") {
        return L7Proto::HTTP;
    } else if (str == "quic_initial") {
        return L7Proto::QUIC_INITIAL;
    } else if (str == "empty") {
        return L7Proto::EMPTY;
    } else if (str == "unknown") {
        return L7Proto::UNKNOWN;
    } else {
        throw std::runtime_error{"Can't convert this string to proto"};
    }
}

#endif// WAIWAIDPI_PROTOCOL_HPP
