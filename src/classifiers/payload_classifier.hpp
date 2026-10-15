//
// Created by klewy on 8/15/26.
//

#ifndef WAIWAIDPI_PAYLOAD_CLASSIFIER_HPP
#define WAIWAIDPI_PAYLOAD_CLASSIFIER_HPP
#include "../conn_tracker.hpp"


#include "../protocol.hpp"
#include <cstdint>

#include <expected>
#include <optional>
#include <string_view>
#include <toml++/impl/table.hpp>

class ConnTracker;
struct PacketView;
enum class ParseResult : std::uint8_t
{
    ERROR,
    REASSEMBLING,
    SUCCESS
};

class PayloadClassifier //NOLINT
{
public:
    virtual ~PayloadClassifier() = default;
    virtual std::expected<ParseResult, std::string> classify(Connection& conn) = 0;

    virtual void parse_config([[maybe_unused]] const toml::table* table) {}
    [[nodiscard]] virtual constexpr L7Proto protocol() const = 0;
    // [[nodiscard]] virtual constexpr std::string_view name() const = 0;
};

#endif// WAIWAIDPI_PAYLOAD_CLASSIFIER_HPP
