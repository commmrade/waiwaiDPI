#include "classifier.hpp"


#include "nfq.hpp"
#include <arpa/inet.h>
#include <cassert>
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

struct Context
{
    mnl_socket* sock{nullptr};
    Classifier* classifier{nullptr};
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
    std::span<const char> packet{static_cast<char*>(mnl_attr_get_payload(attrs[NFQA_PAYLOAD])), packet_len};

    const iphdr* ip = reinterpret_cast<const iphdr*>(packet.data());

    std::array<char, INET_ADDRSTRLEN> ip_src{}, ip_dst{};
    inet_ntop(AF_INET, &ip->saddr, ip_src.data(), ip_src.size());
    inet_ntop(AF_INET, &ip->daddr, ip_dst.data(), ip_dst.size());

    std::println("Packet from {} to {}", ip_src.data(), ip_dst.data());

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

    Classifier cfier{nullptr};

    Context ctx{};
    ctx.sock = socket;
    ctx.classifier = &cfier;

    for (;;) {
        ssize_t rcvd = mnl_socket_recvfrom(socket, buf.data(), BUF_SIZE);
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