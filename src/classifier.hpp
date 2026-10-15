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
    std::vector<std::unique_ptr<PayloadClassifier>> classifiers_;
    ParseResult try_payload(Connection& conn);

public:
    /* explicit */ Classifier(ConnTracker& tracker) {}

    void add(std::unique_ptr<PayloadClassifier>&& classifier);

    ParseResult classify(Connection& conn);
};

#endif// WAIWAIDPI_CLASSIFIER_HPP
