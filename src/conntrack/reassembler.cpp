//
// Created by klewy on 11/6/26.
//

#include "reassembler.hpp"
#include <stdexcept>
#include <algorithm>

bool Reassembler::is_duplicate(const PacketView &pkt)
{
    auto iter = std::ranges::find_if(segs_.begin(), segs_.end(), [&pkt](const Packet &packet) {
        if (packet.network_hdr()->protocol == IPPROTO_TCP) {
            const auto *tcp = static_cast<const tcphdr *>(packet.transport_hdr());
            return ntohl(tcp->seq) == pkt.get_seq().value();
        } else {
            return false;
        }
    });

    return iter != segs_.end();
}
void Reassembler::sort()
{
    if (segs_.front().network_hdr()->protocol == IPPROTO_TCP) {
        std::sort(segs_.begin(), segs_.end(), [](const Packet &lhs, const Packet &rhs) {
            const auto lhs_seq = parse_packet_view(lhs).get_seq().value();
            const auto rhs_seq = parse_packet_view(rhs).get_seq().value();

            // Modular comparison (RFC 1982 / RFC 793 SEQ_LT): correct across wraparound
            return static_cast<int32_t>(lhs_seq - rhs_seq) < 0;
        });
    } else {
        throw std::logic_error{ "sort Not supported for anything other than tcp" };
    }
}
void Reassembler::reset()
{
    segs_.clear();
}
void Reassembler::insert(const PacketView &pkt)
{
    if (segs_.empty()) {
        segs_.push_back(create_packet(pkt));
    } else {
        if (!is_duplicate(pkt)) {
            if (segs_.front().network_hdr()->protocol == IPPROTO_TCP) {
                if (auto seq_opt = pkt.get_seq();
                    !segs_.empty() && seq_opt.has_value()
                    && parse_packet_view(segs_.back()).get_seq().value() + segs_.back().payload().size()
                           == seq_opt.value()) [[likely]] {
                    segs_.push_back(create_packet(pkt));
                           } else {
                               segs_.push_back(create_packet(pkt));
                               sort();
                           }
            } else {
                // It is logical to supposed that it is probably UDP and QUIC
                // In which case we don't need to sort it, since reassembler will take care of it (the thing that builds TLS client hello out of CRYPTO frames from QUIC)
                segs_.push_back(create_packet(pkt));
            }
        }
    }
}