#include "classifier.hpp"
#include "conn_tracker.hpp"


#include "nfq.hpp"
#include <arpa/inet.h>
#include <cassert>
#include <cstring>
#include <iostream>
#include <libmnl/libmnl.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <memory>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <print>
#include "consts.hpp"

struct Context
{
    mnl_socket* sock{nullptr};
    Classifier* classifier{nullptr};

    ConnTracker* tracker{nullptr};
};

int cb_loop(const struct nlmsghdr* nlh, void* data)
{
    Context* ctx = static_cast<Context*>(data);

    const nfgenmsg* genmsg = static_cast<nfgenmsg*>(mnl_nlmsg_get_payload(nlh));
    assert(genmsg);

    std::array<nlattr*, NFQA_MAX + 1> attrs{};
    int ret = nfq_nlmsg_parse(nlh, attrs.data());
    if (ret < 0) {
        perror("nfq_nlmsg_parse");
        return MNL_CB_ERROR;
    }

    assert(attrs[NFQA_PACKET_HDR]);
    const nfqnl_msg_packet_hdr* pkt_hdr = static_cast<const nfqnl_msg_packet_hdr*>(mnl_attr_get_payload(attrs[NFQA_PACKET_HDR]));
    if (!pkt_hdr) {
        std::println(std::cerr, "No packet header");
        return MNL_CB_ERROR;
    }

    assert(attrs[NFQA_PAYLOAD]);
    const std::size_t packet_len = mnl_attr_get_payload_len(attrs[NFQA_PAYLOAD]);
    std::span<const char> const packet_buf{static_cast<char*>(mnl_attr_get_payload(attrs[NFQA_PAYLOAD])), packet_len};

    auto packet = parse_packet(packet_buf);

    std::array<char, INET_ADDRSTRLEN> ip_src{};
    std::array<char, INET_ADDRSTRLEN> ip_dst{};
    inet_ntop(AF_INET, &packet.network_hdr->saddr, ip_src.data(), ip_src.size());
    inet_ntop(AF_INET, &packet.network_hdr->daddr, ip_dst.data(), ip_dst.size());

    ctx->tracker->track(packet);
    auto& conn = ctx->tracker->get_conn(packet.network_hdr->saddr, packet.get_source_port(), packet.network_hdr->daddr, packet.get_dest_port());

    if (!conn.is_done()) {
        auto cfed_pkt_res= ctx->classifier->classify(packet);
        if (cfed_pkt_res.has_value()) {
            auto& cfed_pkt = cfed_pkt_res.value();
            conn.set_done(true);
        }
    }

    ret = send_verdict(ctx->sock, ntohl(pkt_hdr->packet_id), NF_ACCEPT);
    if (ret < 0) {
        perror("send verdict");
        return MNL_CB_ERROR;
    }

    return MNL_CB_OK;
}

int main(int argc, char *argv[])
{
    int ret = 0;

    mnl_socket* socket = mnl_socket_open(NETLINK_NETFILTER);
    if (!socket) {
        perror("mnl socket open failed");
        return EXIT_FAILURE;
    }

    ret = mnl_socket_bind(socket, 0, MNL_SOCKET_AUTOPID);
    if (ret < 0) {
        perror("mnl_socket_bind");
        return EXIT_FAILURE;
    }

    const auto port_id = mnl_socket_get_portid(socket);

    constexpr auto BUF_SIZE = std::numeric_limits<std::uint16_t>::max();
    std::array<char, BUF_SIZE> buf{};

    // bind
    nlmsghdr* hdr = nfq_nlmsg_put(buf.data(), NFQNL_MSG_CONFIG, QUEUE_NUMBER);
    nfq_nlmsg_cfg_put_cmd(hdr, AF_INET, NFQNL_CFG_CMD_BIND);
    ssize_t sent = mnl_socket_sendto(socket, hdr, hdr->nlmsg_len);
    if (sent < 0) {
        perror("mnl_socket_sendto");
        return EXIT_FAILURE;
    }

    // configure
    hdr = nfq_nlmsg_put(buf.data(), NFQNL_MSG_CONFIG, QUEUE_NUMBER);
    nfq_nlmsg_cfg_put_params(hdr, NFQNL_COPY_PACKET, BUF_SIZE);

    sent = mnl_socket_sendto(socket, hdr, hdr->nlmsg_len);
    if (sent < 0) {
        perror("mnl socket sendto");
        return EXIT_FAILURE;
    }

    ret = 1;
    mnl_socket_setsockopt(socket, NETLINK_NO_ENOBUFS, &ret, sizeof(ret));


    ConnTracker tracker{};
    Classifier cfier{&tracker};

    Context ctx{};
    ctx.sock = socket;
    ctx.classifier = &cfier;
    ctx.tracker = &tracker;

    auto last_check_time = std::chrono::system_clock::now();

    for (;;) {
        const auto now = std::chrono::system_clock::now();
        const auto dur = std::chrono::duration_cast<std::chrono::seconds>(now - last_check_time);
        if (dur.count() >= CHECK_DEAD_CONNECTIONS_INTERVAL_SECS) {
            std::println("before clean up: {}", ctx.tracker->conns_size());
            ctx.tracker->clear_dead_connections();
            last_check_time = now;

            std::println("after clean up: {}", ctx.tracker->conns_size());
        }

        ssize_t const rcvd = mnl_socket_recvfrom(socket, buf.data(), BUF_SIZE);
        if (rcvd < 0) {
            perror("mnl_socket_recvfrom");
            return EXIT_FAILURE;
        }

        ret = mnl_cb_run(buf.data(), static_cast<std::size_t>(rcvd), 0, port_id, cb_loop, static_cast<void*>(&ctx));
        if (ret < 0) {
            perror("cb run");
            return EXIT_FAILURE;
        }
    }

    mnl_socket_close(socket);

    return EXIT_SUCCESS;
}


// std::string test_get_sni(std::span<const char> payload)
// {
//     std::println("payloiad!!!!: {}", payload.size());
//     if (payload.size() < 10) {
//         return {};
//     }
//
//     payload = payload.subspan(5);; // skip intro
//
//     constexpr int CLIENT_HELLO_TYPE = 0x01;
//     assert(*payload.data() == CLIENT_HELLO_TYPE);
//     payload = payload.subspan(1);
//
//     std::uint32_t ch_len{};
//     std::memcpy(std::next(reinterpret_cast<char*>(&ch_len), 1), payload.data(), 3);
//     ch_len = ntohl(ch_len);
//     payload = payload.subspan(3);
//     std::println("CH LEN: {}", ch_len);
//
//     payload = payload.subspan(34);
//
//     std::uint8_t const leg_ses_id_len = *payload.data();
//     payload = payload.subspan(leg_ses_id_len + 1);
//
//     std::uint16_t cip_suit_len{};
//     std::memcpy(&cip_suit_len, payload.data(), sizeof(cip_suit_len));
//     cip_suit_len = ntohs(cip_suit_len);
//     payload = payload.subspan(sizeof(cip_suit_len) + cip_suit_len);
//
//     std::uint8_t const compression_methods_len = *payload.data();
//     payload = payload.subspan(1 + compression_methods_len); // ✅
//
//     std::uint16_t ext_length{};
//     std::memcpy(&ext_length, payload.data(), sizeof(ext_length));
//     ext_length = ntohs(ext_length);
//     payload = payload.subspan(sizeof(ext_length), ext_length);
//
//     while (!payload.empty()) {
//         std::uint16_t ext_type{};
//         std::memcpy(&ext_type, payload.data(), sizeof(ext_type));
//         ext_type = ntohs(ext_type);
//         payload = payload.subspan(sizeof(ext_type));
//
//         std::uint16_t ext_len{};
//         std::memcpy(&ext_len, payload.data(), sizeof(ext_len));
//         ext_len = ntohs(ext_len);
//         payload = payload.subspan(sizeof(ext_len));
//
//         if (ext_type != 0x00) {
//             payload = payload.subspan(ext_len);
//             continue;
//         }
//
//         // contains server name list
//         // skip serve rname list len
//         payload = payload.subspan(2);
//
//         assert(*payload.data() == 0x00);
//         payload = payload.subspan(1);
//
//         std::uint16_t hostname_len{};
//         std::memcpy(&hostname_len, payload.data(), sizeof(hostname_len));
//         hostname_len = ntohs(hostname_len);
//         payload = payload.subspan(sizeof(hostname_len));
//
//         return std::string{payload.data(), hostname_len};
//     }
//
//     return {};
// }
