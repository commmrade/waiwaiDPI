//
// Created by klewy on 8/10/26.
//

#ifndef WAIWAIDPI_CLASSIFIER_HPP
#define WAIWAIDPI_CLASSIFIER_HPP

#include "classifiers/http_classifier.hpp"
#include "classifiers/payload_classifier.hpp"
#include "classifiers/tls_classifier.hpp"
#include "packet_view.hpp"
#include "protocol.hpp"
#include <cstdint>
#include <expected>
#include <memory>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <span>
#include <stdexcept>
#include <variant>
#include <vector>

class ConnTracker;
class Classifier
{
private:
    ConnTracker *tracker_{ nullptr };
    std::vector<std::unique_ptr<PayloadClassifier>> classifiers_;

    std::expected<L7Proto, ParseResult> try_payload(PacketView &pkt);

public:
    explicit Classifier(ConnTracker *tracker) : tracker_(tracker)
    {
        classifiers_.push_back(std::make_unique<HttpClassifier>());
        classifiers_.push_back(std::make_unique<TlsHandshakeClassifier>());
    }

    ParseResult classify(PacketView &pkt);
};

#endif// WAIWAIDPI_CLASSIFIER_HPP
