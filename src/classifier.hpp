//
// Created by klewy on 8/10/26.
//

#ifndef WAIWAIDPI_CLASSIFIER_HPP
#define WAIWAIDPI_CLASSIFIER_HPP

#include "packet_view.hpp"
#include "protocol.hpp"
#include <cstdint>
#include <expected>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <span>
#include <stdexcept>
#include <variant>

enum class ParseResult : std::uint8_t
{
    ERROR,
    REASSEMBLING,
    SUCCESS
};

class ConnTracker;
class Classifier
{
private:
    ConnTracker* tracker_{nullptr};

    ParseResult try_http(const PacketView& pkt);
    ParseResult try_tls_handshake(const PacketView& pkt);
    std::expected<L7Proto, ParseResult> try_payload(const PacketView& pkt);
public:
    explicit Classifier(ConnTracker* tracker) : tracker_(tracker) {}
    std::expected<PacketView, ParseResult> classify(PacketView& pkt);
};

#endif// WAIWAIDPI_CLASSIFIER_HPP
