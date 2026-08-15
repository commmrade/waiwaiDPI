//
// Created by klewy on 8/15/26.
//

#ifndef WAIWAIDPI_HTTP_CLASSIFIER_HPP
#define WAIWAIDPI_HTTP_CLASSIFIER_HPP
#include "payload_classifier.hpp"

class HttpClassifier final : public PayloadClassifier
{
public:
    ParseResult classify(const PacketView &pkt, ConnTracker *tracker) override;
    [[nodiscard]] constexpr L7Proto protocol() const override { return L7Proto::HTTP; }
};

#endif// WAIWAIDPI_HTTP_CLASSIFIER_HPP
