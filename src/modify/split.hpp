//
// Created by klewy on 9/24/26.
//

#ifndef WAIWAIDPI_SPLIT_HPP
#define WAIWAIDPI_SPLIT_HPP
#include "conntrack/conn_tracker.hpp"
#include "modify/args.hpp"
#include "modify/markers.hpp"
#include "net/checksum.hpp"
#include "net/packet_view.hpp"
#include <expected>
#include <vector>

#include <algorithm>


namespace helpers {
std::size_t do_operation(const std::size_t start, const Position::Operation oper, const std::size_t offset);


template<std::ranges::range Range>
std::pair<std::ranges::iterator_t<Range>, std::size_t>
    find_packet_by_offset(Range &packets, std::size_t split_pos)
{
    using Iter = std::ranges::iterator_t<Range>;

    const auto seq_of = [](const Packet &pkt) {
        const auto *tcp = static_cast<const tcphdr *>(pkt.transport_hdr());
        return ntohl(tcp->seq);
    };

    // Range может быть view (filter_view), его нельзя сортировать на месте,
    // поэтому сортируем итераторы
    std::vector<Iter> iters;
    for (auto it = std::ranges::begin(packets); it != std::ranges::end(packets); ++it) { iters.push_back(it); }

    std::ranges::stable_sort(iters, [&](const Iter &lhs, const Iter &rhs) {
        return static_cast<std::int32_t>(seq_of(*lhs) - seq_of(*rhs)) < 0;
    });

    std::size_t acc = 0;
    for (const auto &it : iters) {
        const auto sz = (*it).payload().size();
        if (split_pos < acc + sz) { return { it, split_pos - acc }; }
        acc += sz;
    }
    return { std::ranges::end(packets), 0 };
}

template<std::ranges::range Range>
void split_and_insert_packets_tcp(std::ranges::iterator_t<Range> iter,
    const std::size_t split_pos_relative_to_packet,
    Range &packets)
{
    auto &pkt = *iter;
    const auto pkt_view = parse_packet_view(pkt);
    const auto pkt_payload = pkt.payload();
    const std::span<const char> part2{
        std::next(pkt_payload.begin(), static_cast<std::ptrdiff_t>(split_pos_relative_to_packet)), pkt_payload.end()
    };

    // Second packet
    Packet second = create_packet_from(pkt_view, part2);
    second.is_fake_blob = pkt.is_fake_blob;
    second.action.action = PacketAction::Action::SEND;
    second.action.packet_id = 0;

    auto *tcp = static_cast<tcphdr *>(second.transport_hdr());
    tcp->seq = htonl(ntohl(tcp->seq) + static_cast<std::uint32_t>(split_pos_relative_to_packet));
    calc_packet_checksum(second);

    // First packet
    // ACCEPT -> DROP_AND_SEND
    // DROP_AND_SEND -> DROP_AND_SEND
    // SEND -> SEND
    pkt.packet.resize(pkt.packet.size() - part2.size());
    if (pkt.action.action == PacketAction::Action::ACCEPT) { pkt.action.action = PacketAction::Action::DROP_AND_SEND; }

    tcp = static_cast<tcphdr *>(pkt.transport_hdr());
    auto *iph = pkt.network_hdr();

    iph->tot_len = htons((iph->ihl * 4) + (tcp->doff * 4) + static_cast<std::uint16_t>(pkt.payload().size()));
    calc_packet_checksum(pkt);

    if constexpr (requires { packets.insert(iter + 1, std::move(second)); }) {
        packets.insert(iter + 1, std::move(second));
    } else {
        // view: нужен base + insert
        auto &base = packets.base();
        auto base_it = base.begin() + std::distance(packets.begin(), iter);
        base.insert(base_it + 1, std::move(second));
    }
}
}

namespace split {
    struct SplitConfig
    {
        std::reference_wrapper<const Position> pos;
    };

     template<std::ranges::range Range>
    std::expected<bool, std::string> split_http(Range& packets, const Position& pos, const Markers& marks)
    {
        std::size_t split_pos = 0;

        if (pos.arg == Markers::HOSTSTART_STR) {
            if (!marks.hoststart.has_value()) { return std::unexpected{ "Could not find 'hoststart'" }; }

            split_pos = helpers::do_operation(marks.hoststart.value(), pos.operation, pos.offset);
        } else if (pos.arg == Markers::HOSTEND_STR) {
            if (!marks.hostend.has_value()) { return std::unexpected{ "Could not find 'hostend'" }; }

            split_pos = helpers::do_operation(marks.hostend.value(), pos.operation, pos.offset);
        } else if (pos.arg == Markers::HOSTMID_STR) {
            if (!marks.hostmid.has_value()) { return std::unexpected{ "Could not find 'hostmid'" }; }

            split_pos = helpers::do_operation(marks.hostmid.value(), pos.operation, pos.offset);
        } else {
            const auto offset = pos.offset;
            split_pos = offset;
        }

        auto [iter, split_pos_relative_to_packet] = helpers::find_packet_by_offset(packets, split_pos);
        // split iter packet at split_pos_relative_to_packet
        if (split_pos_relative_to_packet == -1) {
            // already split naturally
            return { true };
        }

        helpers::split_and_insert_packets_tcp(iter, split_pos_relative_to_packet, packets);
        return { true };
    }

    template<std::ranges::range Range>
    std::expected<bool, std::string> split_tls(Range& packets, const Position& pos, const Markers& marks)
    {
        std::size_t split_pos = 0;
        if (pos.arg == Markers::HOSTSTART_STR) {
            if (!marks.hoststart.has_value()) { return std::unexpected{ "Could not find 'hoststart'" }; }

            split_pos = helpers::do_operation(marks.hoststart.value(), pos.operation, pos.offset);
        } else if (pos.arg == Markers::HOSTEND_STR) {
            if (!marks.hostend.has_value()) { return std::unexpected{ "Could not find 'hostend'" }; }

            split_pos = helpers::do_operation(marks.hostend.value(), pos.operation, pos.offset);
        } else if (pos.arg == Markers::HOSTMID_STR) {
            if (!marks.hostmid.has_value()) { return std::unexpected{ "Could not find 'hostmid'" }; }

            split_pos = helpers::do_operation(marks.hostmid.value(), pos.operation, pos.offset);
        } else if (pos.arg == Markers::SNIEXT_STR) {
            if (!marks.sniext.has_value()) { return std::unexpected{ "Could not find 'sniext'" }; }

            split_pos = helpers::do_operation(marks.sniext.value(), pos.operation, pos.offset);
        } else {
            const auto offset = pos.offset;
            split_pos = offset;
        }

        auto [iter, rel] = helpers::find_packet_by_offset(packets, split_pos);
        // split iter packet at split_pos_relative_to_packet
        if (rel == -1) {
            // already split naturally
            return { true };
        }

        helpers::split_and_insert_packets_tcp(iter, rel, packets);
        return { true };
    }

    template<std::ranges::range Range>
    std::expected<bool, std::string> split_other(Range& packets, const Position& pos, [[maybe_unused]] const Markers& marks)
    {
        const auto split_pos = pos.offset;

        auto [iter, split_pos_relative_to_packet] = helpers::find_packet_by_offset(packets, split_pos);
        if (iter == packets.end()) { return { false }; }

        if (split_pos_relative_to_packet == -1) {
            // already split naturally
            return { true };
        }

        if (packets.front().network_hdr()->protocol == IPPROTO_TCP) {
            helpers::split_and_insert_packets_tcp(iter, split_pos_relative_to_packet, packets);
        } else {
            return std::unexpected{ "Wasn't able to split packets because other protocols besides TCP are not supported" };
        }
        return { true };
    }

    template<std::ranges::range Range>
    std::expected<bool, std::string> split(Range& packets, const Position& pos, const Markers& markers, const L7Proto payload_proto)
    {
        // split based on application protocol, each protocol have a unique set of usable markers
        switch (payload_proto) {
        case L7Proto::HTTP: {
            return split_http(packets, pos, markers);
        }
        case L7Proto::TLS: {
            return split_tls(packets, pos, markers);
        }
        default: {
            return split_other(packets, pos, markers);
        }
        }
    }


}




#endif// WAIWAIDPI_SPLIT_HPP
