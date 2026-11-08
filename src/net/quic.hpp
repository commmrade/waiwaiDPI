//
// Created by klewy on 11/6/26.
//

#ifndef WAIWAIDPI_QUIC_HPP
#define WAIWAIDPI_QUIC_HPP
#include <cstdint>
#include <span>
#include <vector>
#include <optional>
#include <map>

struct QuicInitialHdr {
    std::uint8_t packet_number_len;
    std::vector<std::uint8_t> dest_conn_id;
    std::vector<std::uint8_t> src_conn_id;
    std::uint64_t length;
    std::vector<std::uint8_t> packet_number;


    std::size_t packet_number_off;
    std::size_t payload_offset;
};
QuicInitialHdr parse_quic(std::span<const std::uint8_t> quic);

std::vector<std::uint8_t> decrypt_quic(std::span<const std::uint8_t> packet);

std::vector<std::uint8_t> lift_header_prot(std::span<const std::uint8_t> packet, std::span<const std::uint8_t> client_init_secret, const QuicInitialHdr& hdr);
std::vector<std::uint8_t> lift_packet_prot(std::span<const std::uint8_t> packet, std::span<const std::uint8_t> client_init_secret, const QuicInitialHdr& hdr);


std::uint64_t quic_packet_length(const QuicInitialHdr& hdr);
std::optional<std::uint64_t> quic_read_varint(std::span<const std::uint8_t> &s);
// contiguous CRYPTO stream starting at offset 0
std::vector<std::uint8_t> quic_reassemble(const std::map<std::uint64_t, std::vector<std::uint8_t>> &chunks);
std::span<const std::uint8_t> extract_quic(std::span<const std::uint8_t>& quic_packets);
bool parse_payload_quic(std::span<const std::uint8_t> payload, std::map<std::uint64_t, std::vector<std::uint8_t>>& tls);


#endif// WAIWAIDPI_QUIC_HPP
