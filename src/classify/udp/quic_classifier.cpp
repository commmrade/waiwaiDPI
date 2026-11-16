//
// Created by klewy on 11/6/26.
//

#include "quic_classifier.hpp"
#include <print>
#include "net/quic.hpp"
#include <map>

std::expected<ClassifyResult, std::string> QuicClassifier::classify_tls(const std::vector<std::uint8_t> &payload)
{
    constexpr auto TLS_HDR_LEN = 6;
    if (payload.size() < TLS_HDR_LEN) {
        return std::unexpected{ "Could not classify as TLS because packet is too small" };
    }

    constexpr auto TLS_HANDSHAKE_TYPE = 0x01;
    if (payload[0] != TLS_HANDSHAKE_TYPE) {
        return std::unexpected{ "Could not classify as TLS because packet header is not TLS Client Hello" };
    }

    std::uint32_t tls_len = 0;
    std::memcpy(std::next(reinterpret_cast<std::uint8_t*>(&tls_len), 1), std::next(payload.data(), 1), 3);
    tls_len = ntohl(tls_len);

    if (payload.size() < tls_len + TLS_HDR_LEN - 2) { // fragmented
        return { ClassifyResult::REASSEMBLING };
    }

    return { ClassifyResult::DONE };
}

std::expected<ClassifyResult, std::string> QuicClassifier::classify(const std::vector<char> &full_payload)
{
    std::map<std::uint64_t, std::vector<std::uint8_t>> tls; // crypto offset -> data

    std::span<const std::uint8_t> quic_packets{ reinterpret_cast<const std::uint8_t *>(full_payload.data()),
        full_payload.size() };

    std::span<const std::uint8_t> quic;
    while (!(quic = extract_quic(quic_packets)).empty()) { //NOLINT
        const auto decrypted_vec = decrypt_quic(quic);
        const auto decrypted = std::span<const std::uint8_t>{decrypted_vec};
        const auto hdr = parse_quic(decrypted);

        auto payload = decrypted.subspan(hdr.payload_offset);
        if (!parse_payload_quic(payload, tls)) {
            break;
        }
    }

    const auto client_hello = quic_reassemble(tls);
    return classify_tls(client_hello);
}

void QuicClassifier::parse_config(const toml::table *table)
{

}