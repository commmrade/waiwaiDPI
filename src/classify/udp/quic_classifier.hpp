//
// Created by klewy on 11/6/26.
//

#ifndef WAIWAIDPI_QUIC_CLASSIFIER_HPP
#define WAIWAIDPI_QUIC_CLASSIFIER_HPP

#include "classify/classifier.hpp"

class QuicClassifier : public PayloadClassifier
{
    std::expected<ClassifyResult, std::string> classify_tls(const std::vector<std::uint8_t>& payload);
public:
    std::expected<ClassifyResult, std::string> classify(const std::vector<char> &full_payload) override;

    void parse_config([[maybe_unused]] const toml::table *table) override;
    [[nodiscard]] constexpr L7Proto protocol() const override
    {
        return L7Proto::QUIC;
    }

    // For profile building
    [[nodiscard]] static constexpr std::string_view name() { return std::string_view{ "quic_classifier" }; }
    [[nodiscard]] static constexpr int transport_protocol() { return IPPROTO_UDP; }
};


#endif// WAIWAIDPI_QUIC_CLASSIFIER_HPP
