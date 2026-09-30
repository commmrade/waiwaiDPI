//
// Created by klewy on 8/15/26.
//

#ifndef WAIWAIDPI_HTTP_CLASSIFIER_HPP
#define WAIWAIDPI_HTTP_CLASSIFIER_HPP
#include "payload_classifier.hpp"

class Connection;
class HttpClassifier final : public PayloadClassifier
{
    std::expected<ParseResult, std::string> buffer_pkt(Connection& conn, const PacketView& pkt);
public:
    std::expected<ParseResult, std::string> classify(const PacketView &pkt, ConnTracker& tracker) override;
    [[nodiscard]] constexpr L7Proto protocol() const override { return L7Proto::HTTP; }
    [[nodiscard]] static constexpr std::string_view name()
    {
        return std::string_view{"http_classifier"};
    }
};

#endif// WAIWAIDPI_HTTP_CLASSIFIER_HPP
