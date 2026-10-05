//
// Created by klewy on 8/10/26.
//

#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_TRACE
#include <spdlog/spdlog.h>
#include "conn_tracker.hpp"
#include "consts.hpp"
#include "nfq.hpp"
#include "iface.hpp"
#include <cassert>
#include <linux/netfilter.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void Connection::set_l4_proto(const std::uint8_t proto)
{
    l4_proto_ = proto;
    switch (l4_proto_) {
    case IPPROTO_TCP: {
        l4_state_.emplace<Tcp>();
        break;
    }
    case IPPROTO_UDP: {
        l4_state_.emplace<Udp>();
        break;
    }
    default: {
        throw std::runtime_error("This L4 protocol is not supported");
    }
    }
}
int Connection::get_mss() const
{
    const auto proto = get_l4_proto();
    if (proto == IPPROTO_TCP) {
        return get_l4_tcp().mss;
    } else {
        constexpr auto MTU_DEFAULT = 1500;
        if (!mtu_.has_value()) {
            const auto iface_name = iface_find(&saddr_);
            if (iface_name.has_value()) {
                const auto mtu = iface_get_mtu(iface_name.value());
                if (mtu.has_value()) {
                    mtu_.emplace(mtu.value());
                } else {
                    SPDLOG_ERROR("Failed to get MTU for interface {}: {}", iface_name.value(), mtu.error());
                    mtu_.emplace(MTU_DEFAULT);
                }
            } else {
                SPDLOG_ERROR("Failed to find an interface: {}", iface_name.error());
                mtu_.emplace(MTU_DEFAULT);
            }
        }
        return mtu_.value() - sizeof(iphdr) - sizeof(udphdr);
    }
}
void Connection::set_mss(const int mss)
{
    if (get_l4_proto() == IPPROTO_TCP) {
        std::get<Tcp>(l4_state_).mss = mss;
    } else {
        throw std::runtime_error{"Not supported"};
    }
}
void Connection::reset_reasm()
{
    reasm_.frags.clear();
    reasm_.pos = 0;
    reasm_.total_size = 0;
    reasm_.expected_seq = 0;
}

void Connection::track_transport(const PacketView &packet)
{
    switch (packet.network_hdr->protocol) {
    case IPPROTO_TCP: {
        track_tcp(packet);
        break;
    }
    case IPPROTO_UDP: {
        track_udp(packet);
        break;
    }
    default: {
        break;
    }
    }
}

static std::optional<int> parse_mss_opt(std::span<const char> tcpb)
{
    if (tcpb.size() <= sizeof(tcphdr)) {
        return false; // no TCP options
    }

    constexpr static std::uint8_t MSS_OPT_KIND = 2;
    constexpr static std::uint8_t MSS_OPT_SIZE = 4;

    tcpb = tcpb.subspan(sizeof(tcphdr));
    while (!tcpb.empty()) {
        if (tcpb.size() < 2) {
            return false;// not enough bytes to get KIND,LENGTH
        }

        const std::uint8_t kind = tcpb[0];
        if (kind == 1) {// no-op
            tcpb = tcpb.subspan(1);
            continue;
        }

        const std::uint8_t size = tcpb[1];
        if (kind != MSS_OPT_KIND) {
            if (tcpb.size() < size) { return false; }

            assert(size > 0);
            tcpb = tcpb.subspan(size);// size includes kind,length + payload
            continue;
        }

        if (size < MSS_OPT_SIZE || size > MSS_OPT_SIZE) { return false; }

        return ntohs(*std::start_lifetime_as<std::uint16_t>(std::next(tcpb.data(), 2)));
    }

    return std::nullopt;
}

void Connection::track_tcp(const PacketView &packet)
{
    const tcphdr* tcph = std::get<0>(packet.transport_hdr);
    Tcp& tcp_state = std::get<1>(l4_state_);
    tcp_state.cur_seq = ntohl(tcph->seq);

    // Track TCP state

    // 1. SYN stuff
    // If we see a SYN and then next packet is ACK and SEQ == OLD_SEQ + 1 => connection ESTAB
    // If we see a SYN + ACK => connection ESTAB (really likely)

    if (tcph->syn) {
        const auto* iph = packet.network_hdr;

        auto tcpb = packet.packet.subspan(iph->ihl * 4);
        tcpb = tcpb.subspan(0, std::min<std::size_t>(tcpb.size(), tcph->doff * 4));

        const auto mss_opt = parse_mss_opt(tcpb);

        if (mss_opt.has_value()) {
            tcp_state.mss = mss_opt.value();
        }
    }

    {
        if (tcp_state.state == Tcp::TcpState::UNKNOWN && (tcph->syn && !tcph->ack)) {
            tcp_state.state = Tcp::TcpState::SYN;
            tcp_state.expected_seq = tcp_state.cur_seq + 1; // it sent SYN, it increased SEQ by 1, if next packet is this seq, that means the SYN was ACKed
        } else if (tcp_state.state == Tcp::TcpState::SYN && (tcph->ack && ntohl(tcph->seq) == tcp_state.expected_seq)) {
            tcp_state.state = Tcp::TcpState::ESTAB;
            tcp_state.expected_seq = 0;
        } else if (tcp_state.state == Tcp::TcpState::UNKNOWN && (tcph->syn && tcph->ack)) {
            tcp_state.state = Tcp::TcpState::ESTAB;
        }
    }

    // 2. ESTAB -> FIN stuff
    // It is kinda impossible to be sure that the connection is closed so I can only guess and rely on timers
    {
        if (tcp_state.state == Tcp::TcpState::ESTAB && tcph->fin) {
            tcp_state.state = Tcp::TcpState::FIN; // FIN does not mean CLOSED, so I can't just delete this connection
        }
    }

    // 3. RST - closed 100%
    {
        if (tcph->rst) {
            tcp_state.state = Tcp::TcpState::CLOSED;
        }
    }
}
void Connection::track_udp([[maybe_unused]] const PacketView &packet) {}

int ConnTracker::timeout_for_tcp_state(const Connection::Tcp::TcpState state)
{
    switch (state) {
    case Connection::Tcp::TcpState::SYN: {
        return SYN_TCP_CONNECTION_TIMEOUT_SECS;
        break;
    }
    case Connection::Tcp::TcpState::ESTAB: {
        return ESTAB_TCP_CONNECTION_TIMEOUT_SECS;
        break;
    }
    case Connection::Tcp::TcpState::FIN: {
        return FIN_TCP_CONNECTION_TIMEOUT_SECS;
        break;
    }
    case Connection::Tcp::TcpState::CLOSED: {
        return CLOSE_TCP_CONNECTION_TIMEOUT_SECS;
        break;
    }
    default:
        return DEFAULT_CONNECTION_TIMEOUT_SECS;
    }
}
void ConnTracker::track(const PacketView &packet)
{
    const std::tuple conn_tuple{
        packet.network_hdr->saddr, packet.get_source_port(), packet.network_hdr->daddr, packet.get_dest_port(), packet.network_hdr->protocol
    };

    auto conn_iter = conns_.find(conn_tuple);
    if (conn_iter == conns_.end()) {
        auto [iter, inserted] = conns_.emplace(conn_tuple, Connection{});
        assert(inserted);
        conn_iter = iter;
        conn_iter->second.set_l4_proto(packet.network_hdr->protocol);
        conn_iter->second.set_source_addr(packet.network_hdr->saddr);
    }

    conn_iter->second.track_transport(packet);

    conn_iter->second.update_last_packet_time(std::chrono::system_clock::now());
    conn_iter->second.set_bytes_transfered(conn_iter->second.bytes_transfered() + packet.payload.size());
    conn_iter->second.count_packet();
}
Connection &ConnTracker::get_conn(const std::uint32_t saddr,
    const std::uint16_t source,
    const std::uint32_t daddr,
    const std::uint16_t dest,
    const int proto)
{
    return conns_.at({ saddr, source, daddr, dest, proto });
}

void ConnTracker::clear_dead_connections(mnl_socket* sock, const std::uint32_t queue_num)
{
    auto calculate_timeout = [](const Connection& conn) -> int {
        int timeout_value = 0;
        if (conn.get_l4_proto() == IPPROTO_TCP) {
            timeout_value = timeout_for_tcp_state(conn.get_l4_tcp().state);
        } else {
            timeout_value = DEFAULT_CONNECTION_TIMEOUT_SECS;
        }
        return timeout_value;
    };


    auto iter = conns_.begin();
    const auto now = std::chrono::system_clock::now();
    while (iter != conns_.end()) {
        const auto dur = std::chrono::duration_cast<std::chrono::seconds>(now - iter->second.get_last_packet_time());

        auto timeout = calculate_timeout(iter->second);
        if (dur.count() >= timeout) {
            // assert(iter->second.get_reasm_frags().empty()); // There can't be any packets here, because they are all processed
            if (!iter->second.get_reasm_frags().empty()) {
                for (const auto& pkt : iter->second.get_reasm_frags()) {
                    int ret = send_verdict(sock, queue_num, pkt.action.packet_id, NF_DROP);
                    if (ret < 0) {
                        SPDLOG_WARN("Unable to drop packet with id: {}", pkt.action.packet_id);
                    }
                }
            }
            iter = conns_.erase(iter);
        } else {
            ++iter;
        }
    }
}