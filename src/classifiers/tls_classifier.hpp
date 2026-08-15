//
// Created by klewy on 8/15/26.
//

#ifndef WAIWAIDPI_TLS_CLASSIFIER_HPP
#define WAIWAIDPI_TLS_CLASSIFIER_HPP
#include "payload_classifier.hpp"

class TlsHandshakeClassifier final : public PayloadClassifier
{
public:
    ParseResult classify(const PacketView &pkt, ConnTracker *tracker) override;
    [[nodiscard]] constexpr L7Proto protocol() const override { return L7Proto::TLS_HANDSHAKE; }
};

#endif// WAIWAIDPI_TLS_CLASSIFIER_HPP
