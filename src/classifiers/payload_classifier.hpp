//
// Created by klewy on 8/15/26.
//

#ifndef WAIWAIDPI_PAYLOAD_CLASSIFIER_HPP
#define WAIWAIDPI_PAYLOAD_CLASSIFIER_HPP
#include <cstdint>
#include "../protocol.hpp"


class ConnTracker;
struct PacketView;
enum class ParseResult : std::uint8_t
{
    ERROR,
    REASSEMBLING,
    SUCCESS_REASSEMBLED,
    SUCCESS
};

class PayloadClassifier
{
public:
    virtual ~PayloadClassifier() = default;
    virtual ParseResult classify(const PacketView& pkt, ConnTracker* tracker) = 0;
    [[nodiscard]] virtual constexpr L7Proto protocol() const = 0;
};

#endif// WAIWAIDPI_PAYLOAD_CLASSIFIER_HPP
