//
// Created by klewy on 11/6/26.
//

#include "quic_classifier.hpp"
#include <print>
#include "net/quic.hpp"
#include <map>

namespace {
std::uint64_t packet_length(const QuicInitialHdr& hdr)
{
    return hdr.packet_number_off + hdr.length;
}

std::optional<std::uint64_t> read_varint(std::span<const std::uint8_t> &s)
{
    if (s.empty()) return std::nullopt;
    const std::size_t len = std::size_t{ 1 } << (s[0] >> 6);
    if (s.size() < len) return std::nullopt;
    std::uint64_t v = s[0] & 0x3f;
    for (std::size_t i = 1; i < len; ++i) v = (v << 8) | s[i];
    s = s.subspan(len);
    return v;
}

// contiguous CRYPTO stream starting at offset 0
std::vector<std::uint8_t> reassemble(const std::map<std::uint64_t, std::vector<std::uint8_t>> &chunks)
{
    std::vector<std::uint8_t> out;
    std::uint64_t next = 0;
    for (const auto &[off, data] : chunks) {
        if (off > next) break;                        // gap, data not yet received
        if (off + data.size() <= next) continue;      // fully duplicate
        const auto skip = static_cast<std::ptrdiff_t>(next - off);
        out.insert(out.end(), data.begin() + skip, data.end());
        next = off + data.size();
    }
    return out;
}

std::span<const std::uint8_t> extract_quic(std::span<const std::uint8_t>& quic_packets)
{
    if (quic_packets.empty()) {
        return {};
    }

    const auto hdr = parse_quic(quic_packets);
    const auto packet_len = packet_length(hdr);

    if (quic_packets.size() < packet_len) {
        return {};
    }

    const auto quic = quic_packets.subspan(0, packet_len);
    quic_packets = quic_packets.subspan(packet_len);

    return quic;
}

bool parse_payload_quic(std::span<const std::uint8_t> payload, std::map<std::uint64_t, std::vector<std::uint8_t>>& tls)
{
    while (!payload.empty()) {
        const auto type = read_varint(payload);
        if (!type) {
            return false;
        }

        switch (*type) {
        case 0x00:// PADDING
        case 0x01:// PING
            break;

        case 0x02:// ACK
        case 0x03: {// ACK_ECN
            const auto largest = read_varint(payload);
            const auto delay = read_varint(payload);
            const auto range_count = read_varint(payload);
            const auto first_range = read_varint(payload);
            if (!largest || !delay || !range_count || !first_range) {
                return false;
            }
            for (std::uint64_t i = 0; i < *range_count; ++i) {
                if (!read_varint(payload) || !read_varint(payload)) {
                    return false;
                }
            }
            if (*type == 0x03) {
                for (int i = 0; i < 3; ++i) {
                    if (!read_varint(payload)) {
                        return false;
                    }
                }
            }
            break;
        }

        case 0x06: {// CRYPTO
            const auto off = read_varint(payload);
            const auto len = read_varint(payload);
            if (!off || !len || payload.size() < *len) {
                return false;
            }

            const auto data = payload.first(*len);
            auto &chunk = tls[*off];
            if (chunk.size() < data.size()) {
                chunk.assign(data.begin(), data.end());// keep longest on retransmit
            }
            payload = payload.subspan(*len);
            break;
        }

        default:
            return false;
        }
    }

    return true;
}
}// namespace

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
    while (!(quic = extract_quic(quic_packets)).empty()) {
        const auto decrypted_vec = decrypt_quic(quic);
        const auto decrypted = std::span<const std::uint8_t>{decrypted_vec};
        const auto hdr = parse_quic(decrypted);

        auto payload = decrypted.subspan(hdr.payload_offset);
        if (!parse_payload_quic(payload, tls)) {
            break;
        }
    }

    const auto client_hello = reassemble(tls);
    return classify_tls(client_hello);
}

void QuicClassifier::parse_config(const toml::table *table)
{

}