//
// Created by klewy on 8/17/26.
//

#include <catch2/catch_all.hpp>
#include <cstring>
#include <cstdint>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "../src/conn_tracker.hpp"

namespace {

// Builds a raw IPv4 + TCP packet into `buf` and returns total length.
// No payload, just headers - good enough for SYN / pure-ACK handshake packets.
size_t build_tcp_packet(uint8_t* buf,
                         uint32_t src_ip, uint32_t dst_ip,
                         uint16_t src_port, uint16_t dst_port,
                         uint32_t seq, uint32_t ack,
                         bool syn, bool ack_flag, bool fin, bool rst,
                         const uint8_t* payload = nullptr, size_t payload_len = 0)
{
    constexpr size_t ip_hdr_len = sizeof(struct iphdr);
    constexpr size_t tcp_hdr_len = sizeof(struct tcphdr);
    const size_t total_len = ip_hdr_len + tcp_hdr_len + payload_len;

    std::memset(buf, 0, total_len);

    auto* ip = reinterpret_cast<struct iphdr*>(buf);
    ip->ihl = ip_hdr_len / 4;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons(static_cast<uint16_t>(total_len));
    ip->id = htons(0x1234);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = src_ip;
    ip->daddr = dst_ip;
    ip->check = 0; // not computing checksum, tests likely don't validate it

    auto* tcp = reinterpret_cast<struct tcphdr*>(buf + ip_hdr_len);
    tcp->source = htons(src_port);
    tcp->dest = htons(dst_port);
    tcp->seq = htonl(seq);
    tcp->ack_seq = htonl(ack);
    tcp->doff = tcp_hdr_len / 4;
    tcp->syn = syn ? 1 : 0;
    tcp->ack = ack_flag ? 1 : 0;
    tcp->fin = fin ? 1 : 0;
    tcp->rst = rst ? 1 : 0;
    tcp->window = htons(65535);
    tcp->check = 0; // not computing checksum here either

    if (payload && payload_len > 0) {
        std::memcpy(buf + ip_hdr_len + tcp_hdr_len, payload, payload_len);
    }

    return total_len;
}

} // namespace

TEST_CASE("SYN state is determined correctly", "[tcp_conntrack]")
{
    // Client -> server direction only. We are the client here.
    // Server-side SYN-ACK is never seen, only what we send.

    const uint32_t client_ip = inet_addr("192.168.1.10");
    const uint32_t server_ip = inet_addr("93.184.216.34");
    const uint16_t client_port = 51234;
    const uint16_t server_port = 443;

    const uint32_t client_isn = 1000; // initial sequence number chosen by client

    uint8_t syn_buf[128];
    size_t syn_len = build_tcp_packet(
        syn_buf,
        client_ip, server_ip,
        client_port, server_port,
        /*seq=*/client_isn, /*ack=*/0,
        /*syn=*/true, /*ack_flag=*/false, /*fin=*/false, /*rst=*/false
    );

    // Final ACK of the handshake (step 3), still client -> server.
    // SYN consumes one sequence number, so client's next seq is isn + 1.
    // ack_seq here should be server's ISN + 1, but since we never observed
    // the SYN-ACK (wrong direction), we just pick an arbitrary plausible value.
    const uint32_t server_isn_guess = 5000;

    uint8_t ack_buf[128];
    size_t ack_len = build_tcp_packet(
        ack_buf,
        client_ip, server_ip,
        client_port, server_port,
        /*seq=*/client_isn + 1, /*ack=*/server_isn_guess + 1,
        /*syn=*/false, /*ack_flag=*/true, /*fin=*/false, /*rst=*/false
    );

    const PacketView syn_pkt = parse_packet(std::span<const char>{reinterpret_cast<const char*>(syn_buf), syn_len});
    const PacketView ack_pkt = parse_packet(std::span<const char>(reinterpret_cast<const char*>(ack_buf), ack_len));

    ConnTracker tracker{};
    tracker.track(syn_pkt);

    auto& conn = tracker.get_conn(client_ip, client_port, server_ip, server_port);
    REQUIRE(conn.get_l4_tcp().state == Connection::Tcp::TcpState::UNKNOWN);
    tracker.track(ack_pkt);
    REQUIRE(conn.get_l4_tcp().state == Connection::Tcp::TcpState::ESTAB);
}

TEST_CASE("SYN state determination fails", "[tcp_conntrack]")
{
    // Client -> server direction only. We are the client here.
    // Server-side SYN-ACK is never seen, only what we send.

    const uint32_t client_ip = inet_addr("192.168.1.10");
    const uint32_t server_ip = inet_addr("93.184.216.34");
    const uint16_t client_port = 51234;
    const uint16_t server_port = 443;

    const uint32_t client_isn = 1000; // initial sequence number chosen by client

    uint8_t syn_buf[128];
    size_t syn_len = build_tcp_packet(
        syn_buf,
        client_ip, server_ip,
        client_port, server_port,
        /*seq=*/client_isn, /*ack=*/0,
        /*syn=*/true, /*ack_flag=*/false, /*fin=*/false, /*rst=*/false
    );

    // Final ACK of the handshake (step 3), still client -> server.
    // SYN consumes one sequence number, so client's next seq is isn + 1.
    // ack_seq here should be server's ISN + 1, but since we never observed
    // the SYN-ACK (wrong direction), we just pick an arbitrary plausible value.
    const uint32_t server_isn_guess = 5000;

    uint8_t ack_buf[128];
    size_t ack_len = build_tcp_packet(
        ack_buf,
        client_ip, server_ip,
        client_port, server_port,
        /*seq=*/client_isn, /*ack=*/server_isn_guess + 1,
        /*syn=*/false, /*ack_flag=*/true, /*fin=*/false, /*rst=*/false
    );

    const PacketView syn_pkt = parse_packet(std::span<const char>{reinterpret_cast<const char*>(syn_buf), syn_len});
    const PacketView ack_pkt = parse_packet(std::span<const char>(reinterpret_cast<const char*>(ack_buf), ack_len));

    ConnTracker tracker{};
    tracker.track(syn_pkt);

    auto& conn = tracker.get_conn(client_ip, client_port, server_ip, server_port);
    REQUIRE(conn.get_l4_tcp().state == Connection::Tcp::TcpState::UNKNOWN);
    tracker.track(ack_pkt);
    REQUIRE_FALSE(conn.get_l4_tcp().state == Connection::Tcp::TcpState::ESTAB);
}


TEST_CASE("SYN-ACK state is determined correctly (server side)", "[tcp_conntrack]")
{
    // Server -> client direction only. We are the server here.
    // Client's initial SYN is never seen, only what we send.
    // We only ever emit SYN-ACK, then whatever follows (data or ACKs) -
    // the client's final handshake ACK is never observed (wrong direction).

    const uint32_t client_ip = inet_addr("192.168.1.10");
    const uint32_t server_ip = inet_addr("93.184.216.34");
    const uint16_t client_port = 51234;
    const uint16_t server_port = 443;

    const uint32_t server_isn = 5000; // initial sequence number chosen by server
    const uint32_t client_isn_guess = 1000; // we never saw the client's SYN directly,
    // but we know it from our own ack_seq choice

    uint8_t synack_buf[128];
    size_t synack_len = build_tcp_packet(
        synack_buf,
        server_ip, client_ip,
        server_port, client_port,
        /*seq=*/server_isn, /*ack=*/client_isn_guess + 1,
        /*syn=*/true, /*ack_flag=*/true, /*fin=*/false, /*rst=*/false
    );

    // Some data sent right after SYN-ACK, before we ever see the client's
    // final handshake ACK (which goes in the other direction).
    const uint8_t payload[] = "hello";
    uint8_t data_buf[128];
    size_t data_len = build_tcp_packet(
        data_buf,
        server_ip, client_ip,
        server_port, client_port,
        /*seq=*/server_isn + 1, /*ack=*/client_isn_guess + 1,
        /*syn=*/false, /*ack_flag=*/true, /*fin=*/false, /*rst=*/false,
        payload, sizeof(payload) - 1
    );

    const PacketView synack_pkt = parse_packet(std::span<const char>{reinterpret_cast<const char*>(synack_buf), synack_len});
    const PacketView data_pkt = parse_packet(std::span<const char>{reinterpret_cast<const char*>(data_buf), data_len});

    ConnTracker tracker;

    tracker.track(synack_pkt);
    auto& conn = tracker.get_conn(server_ip, server_port, client_ip, client_port);
    REQUIRE(conn.get_l4_tcp().state == Connection::Tcp::TcpState::ESTAB);

    tracker.track(data_pkt);
    REQUIRE(conn.get_l4_tcp().state == Connection::Tcp::TcpState::ESTAB);
}

TEST_CASE("FIN close sequence is determined correctly (client side)", "[tcp_conntrack]")
{
    // Client -> server direction only. We are the client here.
    // We initiate close by sending FIN. Server's ACK of our FIN, its own
    // data/FIN, and our final ACK of server's FIN are all in the other
    // direction and never observed.

    const uint32_t client_ip = inet_addr("192.168.1.10");
    const uint32_t server_ip = inet_addr("93.184.216.34");
    const uint16_t client_port = 51234;
    const uint16_t server_port = 443;

    // Assume connection was already ESTABLISHED, client had sent some data
    // and is now at seq = 2000 (arbitrary point past the handshake).
    const uint32_t client_seq = 2000;
    const uint32_t server_ack_guess = 6000; // last known ack from server side

    uint8_t syn_buf[128];
    size_t syn_len = build_tcp_packet(
        syn_buf,
        client_ip, server_ip,
        client_port, server_port,
        /*seq=*/1000, /*ack=*/0,
        /*syn=*/true, /*ack_flag=*/false, /*fin=*/false, /*rst=*/false
    );

    // Final ACK of the handshake (step 3), still client -> server.
    // SYN consumes one sequence number, so client's next seq is isn + 1.
    // ack_seq here should be server's ISN + 1, but since we never observed
    // the SYN-ACK (wrong direction), we just pick an arbitrary plausible value.
    const uint32_t server_isn_guess = 5000;

    uint8_t ack_buf[128];
    size_t ack_len = build_tcp_packet(
        ack_buf,
        client_ip, server_ip,
        client_port, server_port,
        /*seq=*/1000 + 1, /*ack=*/server_isn_guess + 1,
        /*syn=*/false, /*ack_flag=*/true, /*fin=*/false, /*rst=*/false
    );

    const PacketView syn_pkt = parse_packet(std::span<const char>{reinterpret_cast<const char*>(syn_buf), syn_len});
    const PacketView ack_pkt = parse_packet(std::span<const char>(reinterpret_cast<const char*>(ack_buf), ack_len));

    // Client sends FIN. FIN consumes one sequence number.
    uint8_t fin_buf[128];
    size_t fin_len = build_tcp_packet(
        fin_buf,
        client_ip, server_ip,
        client_port, server_port,
        /*seq=*/client_seq, /*ack=*/server_ack_guess,
        /*syn=*/false, /*ack_flag=*/true, /*fin=*/true, /*rst=*/false
    );

    // Server ACKs our FIN and later sends its own FIN once it's done
    // sending remaining data - but that's server -> client, not observed here.

    // Eventually, this direction may see a final ACK from the client,
    // acknowledging the server's FIN (server_seq_guess + 1).
    const uint32_t server_seq_guess = 7000; // wherever server's FIN landed

    uint8_t final_ack_buf[128];
    size_t final_ack_len = build_tcp_packet(
        final_ack_buf,
        client_ip, server_ip,
        client_port, server_port,
        /*seq=*/client_seq + 1, /*ack=*/server_seq_guess + 1,
        /*syn=*/false, /*ack_flag=*/true, /*fin=*/false, /*rst=*/false
    );

    const PacketView fin_pkt = parse_packet(std::span<const char>{reinterpret_cast<const char*>(fin_buf), fin_len});
    const PacketView final_ack_pkt = parse_packet(std::span<const char>{reinterpret_cast<const char*>(final_ack_buf), final_ack_len});

    ConnTracker tracker;
    tracker.track(syn_pkt);
    auto& conn = tracker.get_conn(client_ip, client_port, server_ip, server_port);
    tracker.track(ack_pkt);
    REQUIRE(conn.get_l4_tcp().state == Connection::Tcp::TcpState::ESTAB);

    tracker.track(fin_pkt);
    REQUIRE(conn.get_l4_tcp().state == Connection::Tcp::TcpState::FIN);
    tracker.track(final_ack_pkt);
    REQUIRE(conn.get_l4_tcp().state == Connection::Tcp::TcpState::FIN);
}

TEST_CASE("RST immediately terminates the connection (client side)", "[tcp_conntrack]")
{
    // Client -> server direction only. We are the client here.
    // RST can arrive at any point in the connection lifecycle - established,
    // mid-close, whatever - and should be treated as an immediate terminal
    // signal regardless of prior state.

    const uint32_t client_ip = inet_addr("192.168.1.10");
    const uint32_t server_ip = inet_addr("93.184.216.34");
    const uint16_t client_port = 51234;
    const uint16_t server_port = 443;

    // Connection was ESTABLISHED, client had sent data up to seq = 2000.
    const uint32_t client_seq = 2000;
    const uint32_t server_ack_guess = 6000;

    // Client aborts the connection with RST instead of a graceful FIN.
    uint8_t rst_buf[128];
    size_t rst_len = build_tcp_packet(
        rst_buf,
        client_ip, server_ip,
        client_port, server_port,
        /*seq=*/client_seq, /*ack=*/server_ack_guess,
        /*syn=*/false, /*ack_flag=*/true, /*fin=*/false, /*rst=*/true
    );

    // No further packets should follow in a valid stream after RST, but
    // even if the tracker sees stray packets after this, it should have
    // already torn down / invalidated the connection state.

    const PacketView rst_pkt = parse_packet(std::span<const char>{reinterpret_cast<const char*>(rst_buf), rst_len});

    ConnTracker tracker;
    tracker.track(rst_pkt);
    auto& conn = tracker.get_conn(client_ip, client_port, server_ip, server_port);
    REQUIRE(conn.get_l4_tcp().state == Connection::Tcp::TcpState::CLOSED);
}