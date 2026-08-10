//
// Created by klewy on 8/10/26.
//

#ifndef WAIWAIDPI_CLASSIFIER_HPP
#define WAIWAIDPI_CLASSIFIER_HPP
#include <span>


struct Packet
{
    std::span<const char> packet; // Note: it is non-owning
    int payload_proto; // TODO: make it an enum
    // TODO: Payload proto specific information (as an optimization to avoid doing the same thing in Modifier component
};

class ConnTracker;
class Classifier
{
private:
    ConnTracker* tracker_{nullptr};

    bool try_http(std::span<const char> payload);
    bool try_tls(std::span<const char> payload);
public:
    Classifier(ConnTracker* tracker) : tracker_(tracker) {}
    Packet classify(std::span<const char> packet);
};

#endif// WAIWAIDPI_CLASSIFIER_HPP
