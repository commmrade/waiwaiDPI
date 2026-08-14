//
// Created by klewy on 8/10/26.
//

#ifndef WAIWAIDPI_CLASSIFIER_HPP
#define WAIWAIDPI_CLASSIFIER_HPP

#include <span>
#include "protocol.hpp"
#include "packet.hpp"
#include <cstdint>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
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

    ParseResult try_http(const Packet& pkt);
    ParseResult try_tls_handshake(const Packet& pkt);
    L7Proto try_payload(const Packet& pkt);
public:
    explicit Classifier(ConnTracker* tracker) : tracker_(tracker) {}
    Packet classify(Packet& pkt);
};

#endif// WAIWAIDPI_CLASSIFIER_HPP
