//
// Created by klewy on 8/15/26.
//

#ifndef WAIWAIDPI_HTTP_CLASSIFIER_HPP
#define WAIWAIDPI_HTTP_CLASSIFIER_HPP

#include "classifier.hpp"

class Connection;
class HttpClassifier final : public PayloadClassifier
{
public:
    std::expected<ClassifyResult, std::string> classify(const std::vector<char> &payload) override;
    [[nodiscard]] constexpr L7Proto protocol() const override { return L7Proto::HTTP; }
    [[nodiscard]] static constexpr std::string_view name() { return std::string_view{ "http_classifier" }; }
};

#endif// WAIWAIDPI_HTTP_CLASSIFIER_HPP
