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
    std::expected<ParseResult, std::string> buffer_pkt(Connection& conn, const PacketView& pkt, std::optional<std::size_t> tls_len);
public:
    std::expected<ParseResult, std::string> classify(const PacketView &pkt, ConnTracker& tracker) override;
    [[nodiscard]] constexpr L7Proto protocol() const override { return L7Proto::TLS_HANDSHAKE; }
    [[nodiscard]] static constexpr std::string_view name()
    {
        return std::string_view{"tls_handshake_classifier"};
    }
};

#endif// WAIWAIDPI_TLS_CLASSIFIER_HPP
