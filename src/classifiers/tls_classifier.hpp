//
// Created by klewy on 8/15/26.
//

#ifndef WAIWAIDPI_TLS_CLASSIFIER_HPP
#define WAIWAIDPI_TLS_CLASSIFIER_HPP
#include "../packet_view.hpp"
#include "payload_classifier.hpp"
#include <optional>

class Connection;
class TlsHandshakeClassifier final : public PayloadClassifier
{
public:
    std::expected<ParseResult, std::string> classify(const std::vector<char>& payload, Connection& conn) override;
    [[nodiscard]] constexpr L7Proto protocol() const override { return L7Proto::TLS; }
    [[nodiscard]] static constexpr std::string_view name()
    {
        return std::string_view{"tls_handshake_classifier"};
    }
};

#endif// WAIWAIDPI_TLS_CLASSIFIER_HPP
