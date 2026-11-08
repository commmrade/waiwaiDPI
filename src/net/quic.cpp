//
// Created by klewy on 11/6/26.
//

#include "quic.hpp"

#include "encrypt.hpp"

#include <cassert>
#include <cstring>
#include <print>
#include <stdexcept>

constexpr std::array<const std::uint8_t, 20> initial_salt = {
    0x38,
    0x76,
    0x2c,
    0xf7,
    0xf5,
    0x59,
    0x34,
    0xb3,
    0x4d,
    0x17,
    0x9a,
    0xe6,
    0xa4,
    0xc8,
    0x0c,
    0xad,
    0xcc,
    0xbb,
    0x7f,
    0x0a,
};

QuicInitialHdr parse_quic(std::span<const std::uint8_t> quic)
{
    const auto init = quic;

    QuicInitialHdr ret;

    auto need = [&quic](std::size_t n) {
        if (quic.size() < n) throw std::out_of_range("get_packet_number: truncated packet");
    };
    auto skip = [&](std::size_t n) {
        need(n);
        quic = quic.subspan(n);
    };
    auto varint = [&]() -> std::uint64_t {
        need(1);
        const std::size_t len = std::size_t{ 1 } << (quic[0] >> 6);
        need(len);
        std::uint64_t v = quic[0] & 0x3f;
        for (std::size_t i = 1; i < len; ++i) v = (v << 8) | quic[i];
        quic = quic.subspan(len);
        return v;
    };

    need(1);
    ret.packet_number_len = (quic.front() & 0x03) + 1;

    need(1 + 4);
    skip(1 + 4);

    need(1);
    const std::uint8_t dest_conn_id_len = quic.front();
    skip(1);

    need(dest_conn_id_len);
    ret.dest_conn_id.resize(dest_conn_id_len);
    std::memcpy(ret.dest_conn_id.data(), quic.data(), dest_conn_id_len);
    skip(dest_conn_id_len);

    need(1);
    const std::uint8_t src_conn_id_len = quic.front();
    skip(1);

    need(src_conn_id_len);
    ret.src_conn_id.resize(src_conn_id_len);
    std::memcpy(ret.src_conn_id.data(), quic.data(), src_conn_id_len);
    skip(src_conn_id_len);

    need(1);
    const std::uint8_t token_len = quic.front();
    assert(token_len == 0);
    skip(1 + token_len);

    ret.length = varint();

    ret.packet_number_off = static_cast<std::size_t>(std::distance(init.data(), quic.data()));

    need(ret.packet_number_len);
    ret.packet_number.resize(ret.packet_number_len);
    std::memcpy(ret.packet_number.data(), quic.data(), ret.packet_number_len);
    skip(ret.packet_number_len);

    ret.payload_offset = static_cast<std::size_t>(std::distance(init.data(), quic.data()));

    return ret;
}

std::vector<std::uint8_t> decrypt_quic(std::span<const std::uint8_t> packet)
{
    const auto init_hdr = parse_quic(packet);
    const auto init_secret = hkdf_extract(initial_salt, init_hdr.dest_conn_id);
    const auto client_init_secret = hkdf_expand_label(init_secret, "client in", {}, 32);

    auto decrypted = lift_header_prot(packet, client_init_secret, init_hdr);
    const auto decrypted_hdr = parse_quic(decrypted);
    decrypted = lift_packet_prot(decrypted, client_init_secret, decrypted_hdr);

    return decrypted;
}

std::vector<std::uint8_t> lift_header_prot(std::span<const std::uint8_t> packet,
    std::span<const std::uint8_t> client_init_secret,
    const QuicInitialHdr &hdr)
{
    std::vector<std::uint8_t> quic{ packet.begin(), packet.end() };

    const auto hp_key = hkdf_expand_label(client_init_secret, "quic hp", {}, 16);
    const auto sample = packet.subspan(hdr.packet_number_off + 4).first(16);
    const auto mask = header_protection(hp_key, sample);

    quic.front() ^= mask.front() & 0x0f;
    const std::uint8_t pn_length = (quic.front() & 0x03) + 1;
    for (std::size_t i = 0; i < pn_length; ++i) { quic[hdr.packet_number_off + i] ^= mask[1 + i]; }

    return quic;
}
std::vector<std::uint8_t> lift_packet_prot(std::span<const std::uint8_t> packet,
    std::span<const std::uint8_t> client_init_secret,
    const QuicInitialHdr &hdr)
{
    std::vector<std::uint8_t> quic{ packet.begin(), packet.end() };

    const auto iv_secret =
        hkdf_expand_label(client_init_secret, "quic iv", {}, 12);// 12 because MIN nonce is 12 bytes in AES-GCM
    const auto aes_key = hkdf_expand_label(client_init_secret, "quic key", {}, 16);

    std::vector<std::uint8_t> nonce = iv_secret;// 12 bytes
    const std::size_t pn_len = hdr.packet_number_len;
    for (std::size_t i = 0; i < pn_len; ++i) { nonce[nonce.size() - pn_len + i] ^= hdr.packet_number[i]; }

    std::span<const std::uint8_t> const header{ quic.begin(),
        quic.begin() + static_cast<std::ptrdiff_t>(hdr.payload_offset) };
    std::span<const std::uint8_t> const ciphertext{ quic.begin() + static_cast<std::ptrdiff_t>(hdr.payload_offset),
        quic.end() };

    const auto plaintext = aead(aes_key, nonce, header, ciphertext);
    quic.erase(quic.begin() + static_cast<std::ptrdiff_t>(hdr.payload_offset), quic.end());
    quic.insert(quic.end(), plaintext.begin(), plaintext.end());

    return quic;
}
std::uint64_t quic_packet_length(const QuicInitialHdr &hdr) { return hdr.packet_number_off + hdr.length; }
std::optional<std::uint64_t> quic_read_varint(std::span<const std::uint8_t> &s)
{
    if (s.empty()) return std::nullopt;
    const std::size_t len = std::size_t{ 1 } << (s[0] >> 6);
    if (s.size() < len) return std::nullopt;
    std::uint64_t v = s[0] & 0x3f;
    for (std::size_t i = 1; i < len; ++i) v = (v << 8) | s[i];
    s = s.subspan(len);
    return v;
}
std::vector<std::uint8_t> quic_reassemble(const std::map<std::uint64_t, std::vector<std::uint8_t>> &chunks)
{
    std::vector<std::uint8_t> out;
    std::uint64_t next = 0;
    for (const auto &[off, data] : chunks) {
        if (off > next) break;// gap, data not yet received
        if (off + data.size() <= next) continue;// fully duplicate
        const auto skip = static_cast<std::ptrdiff_t>(next - off);
        out.insert(out.end(), data.begin() + skip, data.end());
        next = off + data.size();
    }
    return out;
}
std::span<const std::uint8_t> extract_quic(std::span<const std::uint8_t> &quic_packets)
{
    if (quic_packets.empty()) { return {}; }

    const auto hdr = parse_quic(quic_packets);
    const auto packet_len = quic_packet_length(hdr);

    if (quic_packets.size() < packet_len) { return {}; }

    const auto quic = quic_packets.subspan(0, packet_len);
    quic_packets = quic_packets.subspan(packet_len);

    return quic;
}
bool parse_payload_quic(std::span<const std::uint8_t> payload, std::map<std::uint64_t, std::vector<std::uint8_t>> &tls)
{
    while (!payload.empty()) {
        const auto type = quic_read_varint(payload);
        if (!type) { return false; }

        switch (*type) {
        case 0x00:// PADDING
        case 0x01:// PING
            break;

        case 0x02:// ACK
        case 0x03: {// ACK_ECN
            const auto largest = quic_read_varint(payload);
            const auto delay = quic_read_varint(payload);
            const auto range_count = quic_read_varint(payload);
            const auto first_range = quic_read_varint(payload);
            if (!largest || !delay || !range_count || !first_range) { return false; }
            for (std::uint64_t i = 0; i < *range_count; ++i) {
                if (!quic_read_varint(payload) || !quic_read_varint(payload)) { return false; }
            }
            if (*type == 0x03) {
                for (int i = 0; i < 3; ++i) {
                    if (!quic_read_varint(payload)) { return false; }
                }
            }
            break;
        }

        case 0x06: {// CRYPTO
            const auto off = quic_read_varint(payload);
            const auto len = quic_read_varint(payload);
            if (!off || !len || payload.size() < *len) { return false; }

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