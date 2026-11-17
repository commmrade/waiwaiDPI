//
// Created by klewy on 11/17/26.
//

#include "fooling.hpp"

namespace fooling {
bool timestamp_val_offset(Packet &packet, const int offset)
{
    auto *tcp = static_cast<tcphdr *>(packet.transport_hdr());
    std::span<char> tcp_bytes{ static_cast<char *>(packet.transport_hdr()), static_cast<std::size_t>(tcp->doff * 4) };
    if (tcp_bytes.size() <= sizeof(tcphdr)) {
        return false;// no TCP options
    }

    constexpr static std::uint8_t TS_OPT_KIND = 8;
    constexpr static std::uint8_t TS_OPT_SIZE = 10;

    tcp_bytes = tcp_bytes.subspan(sizeof(tcphdr));
    while (!tcp_bytes.empty()) {
        if (tcp_bytes.size() < 2) {
            return false;// not enough bytes to get KIND,LENGTH
        }

        const auto kind = static_cast<std::uint8_t>(tcp_bytes[0]);
        if (kind == 1) {// no-op
            tcp_bytes = tcp_bytes.subspan(1);
            continue;
        }

        const auto size = static_cast<std::uint8_t>(tcp_bytes[1]);
        if (kind != TS_OPT_KIND) {
            if (tcp_bytes.size() < size) { return false; }

            tcp_bytes = tcp_bytes.subspan(size);// size includes kind,length + payload
            continue;
        }

        if (size < TS_OPT_SIZE || size > TS_OPT_SIZE) { return false; }

        auto *tval = std::start_lifetime_as<std::uint32_t>(std::next(tcp_bytes.data(), 2));
        auto *tresp = std::start_lifetime_as<std::uint32_t>(std::next(tcp_bytes.data(), 2 + sizeof(*tval)));

        *tval = htonl(static_cast<std::uint32_t>(static_cast<int>(ntohl(*tval)) + offset));
        *tresp = htonl(static_cast<std::uint32_t>(static_cast<int>(ntohl(*tresp)) + offset));

        break;
    }

    return true;
}
} // namespace fooling