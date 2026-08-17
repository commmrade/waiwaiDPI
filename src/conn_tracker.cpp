//
// Created by klewy on 8/10/26.
//

#include "conn_tracker.hpp"
#include "consts.hpp"
#include <cassert>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void Connection::track_tcp(const PacketView &packet)
{
    const tcphdr* tcph = std::get<0>(packet.transport_hdr);
    Tcp& tcp_state = get_l4_tcp();
    tcp_state.cur_seq = ntohl(tcph->seq);

    // Track TCP state

    // 1. SYN stuff
    // If we see a SYN and then next packet is ACK and SEQ == OLD_SEQ + 1 => connection ESTAB
    // If we see a SYN + ACK => connection ESTAB (really likely)
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
    default:
        return DEFAULT_CONNECTION_TIMEOUT_SECS;
    }
}
void ConnTracker::track(const PacketView &packet)
{
    const std::tuple conn_tuple{
        packet.network_hdr->saddr, packet.get_source_port(), packet.network_hdr->daddr, packet.get_dest_port()
    };

    auto conn_iter = conns_.find(conn_tuple);
    if (conn_iter == conns_.end()) {
        auto [iter, inserted] = conns_.emplace(conn_tuple, Connection{});
        assert(inserted);
        conn_iter = iter;
        conn_iter->second.set_l4_proto(packet.network_hdr->protocol);
    }

    switch (packet.network_hdr->protocol) {
    case IPPROTO_TCP: {
        conn_iter->second.track_tcp(packet);
        break;
    }
    case IPPROTO_UDP: {
        conn_iter->second.track_udp(packet);
        break;
    }
    default: {
        break;
    }
    }

    conn_iter->second.update_last_packet_time(std::chrono::system_clock::now());
    conn_iter->second.set_bytes_transfered(conn_iter->second.bytes_transfered() + packet.payload.size());
    conn_iter->second.count_packet();
}
Connection &ConnTracker::get_conn(const std::uint32_t saddr,
    const std::uint16_t source,
    const std::uint32_t daddr,
    const std::uint16_t dest)
{
    return conns_.at({ saddr, source, daddr, dest });
}

void ConnTracker::clear_dead_connections()
{
    auto calculate_timeout = [](Connection& conn) -> int {
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
        if (dur.count() >= timeout) { // TODO: determine timeout based on tcp conn state, if not tcp, then some default value
            iter = conns_.erase(iter);
        } else {
            ++iter;
        }
    }
}