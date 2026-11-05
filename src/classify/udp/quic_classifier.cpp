//
// Created by klewy on 11/6/26.
//

#include "quic_classifier.hpp"

#include <unordered_map>

std::uint64_t packet_length(std::span<const std::uint8_t> quic)
{

}

std::expected<ClassifyResult, std::string> QuicClassifier::classify(
    const std::vector<char> &full_payload)
{
    std::unordered_map<std::size_t, std::vector<char>> tls;

    std::span<const std::uint8_t> quic_packets{reinterpret_cast<const std::uint8_t*>(full_payload.data()), full_payload.size()};

    auto packet_len = packet_length(quic_packets);
    std::span<const std::uint8_t> quic = quic_packets.subspan(0, packet_len);
    while (!quic.empty()) {
        // .. deal with quic
        /*
         * auto quic = lift_header_prot(packet);
         * auto quic = lift_packet_prot(packet);
         * for (const auto& frame : quic.frames) {
         *      tls[frame.offset] = frame.payload;
         * }
         * if (make_sure_tls_contigious(tls)) {
         *      return ClassifyResult::DONE;
         * }
         */

        // .. end deal with quic
        quic_packets = quic_packets.subspan(packet_len);
        packet_len = packet_length(quic_packets);
        quic = quic_packets.subspan(0, packet_len);
    }
}
void QuicClassifier::parse_config(const toml::table *table)
{
}