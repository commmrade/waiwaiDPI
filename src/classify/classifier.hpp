//
// Created by klewy on 8/10/26.
//

#ifndef WAIWAIDPI_CLASSIFIER_HPP
#define WAIWAIDPI_CLASSIFIER_HPP

#include "net/packet_view.hpp"
#include "net/protocol.hpp"
#include <expected>
#include <memory>
#include <netinet/ip.h>
#include <toml++/toml.hpp>
#include <vector>

class ConnTracker;

enum class ClassifyResult : std::uint8_t {
    DONE,
    REASSEMBLING,
    ERROR,
};

struct PacketView;
enum class ParseResult : std::uint8_t { ERROR, REASSEMBLING, SUCCESS };

class PayloadClassifier// NOLINT
{
public:
    virtual ~PayloadClassifier() = default;
    virtual std::expected<ClassifyResult, std::string> classify(const std::vector<char> &full_payload) = 0;

    virtual void parse_config([[maybe_unused]] const toml::table *table) {}
    [[nodiscard]] virtual constexpr L7Proto protocol() const = 0;
    // [[nodiscard]] virtual constexpr std::string_view name() const = 0;
};

class Classifier
{
private:
    std::vector<std::unique_ptr<PayloadClassifier>> classifiers_;

public:
    Classifier() = default;

    void add(std::unique_ptr<PayloadClassifier> &&classifier);

    std::pair<ClassifyResult, std::optional<L7Proto>> classify(const std::vector<Packet> &packets);
};

#endif// WAIWAIDPI_CLASSIFIER_HPP
