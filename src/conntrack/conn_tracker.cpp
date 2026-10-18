//
// Created by klewy on 8/10/26.
//

#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_TRACE
#include "conn_tracker.hpp"
#include "net/consts.hpp"
#include "sys/iface.hpp"
#include "sys/nfq.hpp"
#include <cassert>
#include <linux/netfilter.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <spdlog/spdlog.h>

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
        if (!mtu_.has_value()) {
            constexpr auto MTU_DEFAULT = 1500;
            const auto mtu = iface_find_and_get_mtu(&saddr_);
            if (mtu.has_value()) {
                mtu_.emplace(mtu.value());
            } else {
                SPDLOG_ERROR("Couldn't get mtu: {}", mtu.error());
                mtu_.emplace(MTU_DEFAULT);
            }
        }
        return static_cast<int>(static_cast<unsigned long>(mtu_.value()) - sizeof(iphdr) - sizeof(udphdr));
    }
}
void Connection::set_mss(const int mss)
{
    if (get_l4_proto() == IPPROTO_TCP) {
        std::get<Tcp>(l4_state_).mss = mss;
    } else {
        throw std::runtime_error{ "Not supported" };
    }
}
void Connection::reasm_reset() { reasm_.segs.clear(); }

void Connection::reasm_insert(const PacketView &pkt)
{
    if (reasm_.segs.empty()) {
        reasm_.segs.push_back(create_packet(pkt));
    } else {
        if (!reasm_is_duplicate(pkt)) {
            if (auto seq_opt = pkt.get_seq();
                !reasm_.segs.empty() && seq_opt.has_value()
                && parse_packet_view(reasm_.segs.back()).get_seq().value() + reasm_.segs.back().payload().size()
                       == seq_opt.value()) [[likely]] {
                reasm_.segs.push_back(create_packet(pkt));
            } else {
                reasm_.segs.push_back(create_packet(pkt));
                reasm_sort();
            }
        }
    }
}

void Connection::reasm_sort()
{
    if (get_l4_proto() == IPPROTO_TCP) {
        std::sort(reasm_.segs.begin(), reasm_.segs.end(), [](const Packet &lhs, const Packet &rhs) {
            const auto lhs_seq = parse_packet_view(lhs).get_seq().value();
            const auto rhs_seq = parse_packet_view(rhs).get_seq().value();

            // Modular comparison (RFC 1982 / RFC 793 SEQ_LT): correct across wraparound
            return static_cast<int32_t>(lhs_seq - rhs_seq) < 0;
        });
    } else {
        throw std::logic_error{ "sort Not supported for anything other than tcp" };
    }
}
bool Connection::reasm_is_duplicate(const PacketView &pkt)
{
    auto iter = std::ranges::find_if(reasm_.segs.begin(), reasm_.segs.end(), [&pkt](const Packet &packet) {
        if (packet.network_hdr()->protocol == IPPROTO_TCP) {
            const auto *tcp = static_cast<const tcphdr *>(packet.transport_hdr());
            return ntohl(tcp->seq) == pkt.get_seq().value();
        } else {
            // TODO: for now it is false
            return false;
        }
    });

    return iter != reasm_.segs.end();
}

void Connection::track(const PacketView &packet)
{
    track_transport(packet);

    update_last_packet_time(std::chrono::system_clock::now());
    set_bytes_transfered(bytes_transfered() + packet.payload.size());
    count_packet();
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
        return false;// no TCP options
    }

    constexpr static std::uint8_t MSS_OPT_KIND = 2;
    constexpr static std::uint8_t MSS_OPT_SIZE = 4;

    tcpb = tcpb.subspan(sizeof(tcphdr));
    while (!tcpb.empty()) {
        if (tcpb.size() < 2) {
            return false;// not enough bytes to get KIND,LENGTH
        }

        const auto kind = static_cast<std::uint8_t>(tcpb[0]);
        if (kind == 1) {// no-op
            tcpb = tcpb.subspan(1);
            continue;
        }

        const auto size = static_cast<std::uint8_t>(tcpb[1]);
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
    const tcphdr *tcph = std::get<0>(packet.transport_hdr);
    Tcp &tcp_state = std::get<1>(l4_state_);
    tcp_state.cur_seq = ntohl(tcph->seq);

    // Track TCP state

    // 1. SYN stuff
    // If we see a SYN and then next packet is ACK and SEQ == OLD_SEQ + 1 => connection ESTAB
    // If we see a SYN + ACK => connection ESTAB (really likely)

    if (tcph->syn) {
        const auto *iph = packet.network_hdr;

        auto tcpb = packet.packet.subspan(iph->ihl * 4);
        tcpb = tcpb.subspan(0, std::min<std::size_t>(tcpb.size(), tcph->doff * 4));

        const auto mss_opt = parse_mss_opt(tcpb);

        if (mss_opt.has_value()) { tcp_state.mss = mss_opt.value(); }
    }

    {
        if (tcp_state.state == Tcp::TcpState::UNKNOWN && (tcph->syn && !tcph->ack)) {
            tcp_state.state = Tcp::TcpState::SYN;
            tcp_state.expected_seq =
                tcp_state.cur_seq
                + 1;// it sent SYN, it increased SEQ by 1, if next packet is this seq, that means the SYN was ACKed
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
            tcp_state.state = Tcp::TcpState::FIN;// FIN does not mean CLOSED, so I can't just delete this connection
        }
    }

    // 3. RST - closed 100%
    {
        if (tcph->rst) { tcp_state.state = Tcp::TcpState::CLOSED; }
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

std::unordered_map<std::tuple<unsigned, unsigned short, unsigned, unsigned short, int>, Connection>::iterator
    ConnTracker::get_conn(const std::uint32_t saddr,
        const std::uint16_t source,
        const std::uint32_t daddr,
        const std::uint16_t dest,
        const int proto)
{
    const std::tuple conn_tuple{ saddr, source, daddr, dest, proto };

    auto conn_iter = conns_.find(conn_tuple);
    if (conn_iter == conns_.end()) {
        auto [iter, inserted] = conns_.emplace(conn_tuple, Connection{});
        assert(inserted);
        conn_iter = iter;
        conn_iter->second.set_l4_proto(static_cast<std::uint8_t>(proto));
        conn_iter->second.set_source_addr(saddr);
    }

    return conn_iter;
}

void ConnTracker::clear_dead_connections(mnl_socket *sock, const std::uint32_t queue_num)
{
    auto calculate_timeout = [](const Connection &conn) -> int {
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
            for (const auto &pkt : iter->second.reasm_get()) {
                int ret = send_verdict(sock, queue_num, pkt.action.packet_id, NF_ACCEPT);
                if (ret < 0) { SPDLOG_WARN("Unable to accept packet with id: {}", pkt.action.packet_id); }
            }
            iter = conns_.erase(iter);
        } else {
            ++iter;
        }
    }
}