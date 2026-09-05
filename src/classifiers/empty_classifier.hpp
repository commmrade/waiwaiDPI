//
// Created by klewy on 9/5/26.
//

#ifndef WAIWAIDPI_EMPTY_CLASSIFIER_HPP
#define WAIWAIDPI_EMPTY_CLASSIFIER_HPP
#include "payload_classifier.hpp"


class EmptyClassifier : public PayloadClassifier
{
public:
    ParseResult classify(const PacketView &pkt, ConnTracker &tracker) override;
    L7Proto protocol() const override;
};


#endif// WAIWAIDPI_EMPTY_CLASSIFIER_HPP
