//
// Created by klewy on 11/6/26.
//

#ifndef WAIWAIDPI_QUIC_HPP
#define WAIWAIDPI_QUIC_HPP
#include <cstdint>
#include <span>
#include <vector>

struct QuicInitialHdr {
    std::uint8_t packet_number_len;
    std::vector<std::uint8_t> dest_conn_id;
    std::vector<std::uint8_t> src_conn_id;
    std::uint64_t length;
    std::vector<std::uint8_t> packet_number;


    std::size_t packet_number_off;
    std::size_t payload_offset;
};
QuicInitialHdr parse_packet(std::span<const std::uint8_t> quic);

std::vector<std::uint8_t> decrypt_quic(std::span<const std::uint8_t> packet);

std::vector<std::uint8_t> lift_header_prot(std::span<const std::uint8_t> packet, std::span<const std::uint8_t> client_init_secret, const QuicInitialHdr& hdr);
std::vector<std::uint8_t> lift_packet_prot(std::span<const std::uint8_t> packet, std::span<const std::uint8_t> client_init_secret, const QuicInitialHdr& hdr);


#endif// WAIWAIDPI_QUIC_HPP
