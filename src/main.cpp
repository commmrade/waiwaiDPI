#include "classifier.hpp"
#include "conn_tracker.hpp"


#include "consts.hpp"
#include "modifiers/dumbass_modifier.hpp"
#include "modifiers/http_host_modifier.hpp"
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

struct Context
{
    mnl_socket *sock{ nullptr };
    Classifier *classifier{ nullptr };

    ConnTracker *tracker{ nullptr };

    int raw_sock;
};

int cb_loop(const struct nlmsghdr *nlh, void *data)
{
    Context *ctx = static_cast<Context *>(data);

    const nfgenmsg *genmsg = static_cast<nfgenmsg *>(mnl_nlmsg_get_payload(nlh));
    assert(genmsg);

    std::array<nlattr *, NFQA_MAX + 1> attrs{};
    int ret = nfq_nlmsg_parse(nlh, attrs.data());
    if (ret < 0) {
        perror("nfq_nlmsg_parse");
        return MNL_CB_ERROR;
    }

    assert(attrs[NFQA_PACKET_HDR]);
    const auto *pkt_hdr =
        static_cast<const nfqnl_msg_packet_hdr *>(mnl_attr_get_payload(attrs[NFQA_PACKET_HDR]));
    if (!pkt_hdr) {
        std::println(std::cerr, "No packet header");
        return MNL_CB_ERROR;
    }

    assert(attrs[NFQA_PAYLOAD]);
    const std::size_t packet_len = mnl_attr_get_payload_len(attrs[NFQA_PAYLOAD]);
    std::span<const char> const packet_buf{ static_cast<char *>(mnl_attr_get_payload(attrs[NFQA_PAYLOAD])),
        packet_len };

    auto packet = parse_packet_view(packet_buf);
    packet.packet_id = ntohl(pkt_hdr->packet_id);

    std::array<char, INET_ADDRSTRLEN> ip_src{};
    std::array<char, INET_ADDRSTRLEN> ip_dst{};
    inet_ntop(AF_INET, &packet.network_hdr->saddr, ip_src.data(), ip_src.size());
    inet_ntop(AF_INET, &packet.network_hdr->daddr, ip_dst.data(), ip_dst.size());

    ctx->tracker->track(packet);
    auto &conn = ctx->tracker->get_conn(packet.network_hdr->saddr,
        packet.get_source_port(),
        packet.network_hdr->daddr,
        packet.get_dest_port(),
        packet.network_hdr->protocol);

    std::vector<std::unique_ptr<Modifier>> modifiers;
    modifiers.push_back(std::make_unique<HttpHostModifier>());
    // modifiers.push_back(std::make_unique<DumbassModifier>());

    if (!conn.is_done()) {
        auto res = ctx->classifier->classify(packet);
        if (res == ParseResult::SUCCESS) {
            if (packet.payload_proto == L7Proto::TLS_HANDSHAKE) {
                conn.set_done(true);
            }
            auto &cfed_pkt = packet;
            std::vector<Packet> packets;

            if (cfed_pkt.is_payload_reasm) {
                const std::vector<Packet> frags = conn.get_reasm_frags();
                conn.reset_reasm();

                packets.reserve(frags.size());
                for (const auto &frag : frags) {
                    packets.emplace_back(frag);
                }
            } else {
                packets.emplace_back(create_packet(cfed_pkt));
            }

            for (auto &modifier : modifiers) {
                if (!modifier->matches(conn.get_l4_proto(), conn.payload_proto())) {
                    continue;
                }
                if (!modifier->modify(packets)) {
                }
            }

            for (const auto &send_pkt : packets) {
                switch (send_pkt.action.action) {
                case PacketAction::Action::ACCEPT: {
                    assert(send_pkt.action.packet_id);
                    ret = send_verdict(ctx->sock, send_pkt.action.packet_id, NF_ACCEPT);
                    if (ret < 0) {
                        perror("send accept failed, but dont stop");
                    }
                    break;
                }
                case PacketAction::Action::DROP: {
                    ret = send_verdict(ctx->sock, send_pkt.action.packet_id, NF_DROP);
                    if (ret < 0) {
                        perror("send drop failed, dont stop");
                    }
                    break;
                }
                case PacketAction::Action::DROP_AND_SEND: {
                    ret = send_verdict(ctx->sock, send_pkt.action.packet_id, NF_DROP);
                    if (ret < 0) {
                        perror("send drop failed, dont stop");
                    }
                    [[fallthrough]];
                }
                case PacketAction::Action::SEND: {
                    const auto *ip = reinterpret_cast<const iphdr *>(send_pkt.packet.data());

                    sockaddr_in dest_addr{};
                    dest_addr.sin_family = AF_INET;
                    dest_addr.sin_addr.s_addr = ip->daddr;

                    ssize_t const sent = sendto(ctx->raw_sock,
                        send_pkt.packet.data(),
                        send_pkt.packet.size(),
                        0,
                        reinterpret_cast<sockaddr *>(&dest_addr),
                        sizeof(dest_addr));
                    if (sent < 0) { perror("could not send a packet, continuing"); }
                    break;
                }
                }
            }
        }
    } else {
        ret = send_verdict(ctx->sock, ntohl(pkt_hdr->packet_id), NF_ACCEPT);
        assert(ret);
    }


    return MNL_CB_OK;
}

int main(int argc, char *argv[])
{
    int ret = 0;

    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_sock < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

    int enable = 1;
    ret = setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
    if (ret < 0) {
        perror("setsockopt");
        return EXIT_FAILURE;
    }

    int mark = 0x14;
    ret = setsockopt(raw_sock, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
    if (ret < 0) {
        perror("setsockopt");
        return EXIT_FAILURE;
    }

    mnl_socket *socket = mnl_socket_open(NETLINK_NETFILTER);
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
    nlmsghdr *hdr = nfq_nlmsg_put(buf.data(), NFQNL_MSG_CONFIG, QUEUE_NUMBER);
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

    Classifier cfier{ tracker };
    cfier.add(std::make_unique<HttpClassifier>());
    cfier.add(std::make_unique<TlsHandshakeClassifier>());

    Context ctx{};
    ctx.sock = socket;
    ctx.classifier = &cfier;
    ctx.tracker = &tracker;
    ctx.raw_sock = raw_sock;

    auto last_check_time = std::chrono::system_clock::now();

    for (;;) {
        const auto now = std::chrono::system_clock::now();
        const auto dur = std::chrono::duration_cast<std::chrono::seconds>(now - last_check_time);
        if (dur.count() >= CHECK_DEAD_CONNECTIONS_INTERVAL_SECS) {
            ctx.tracker->clear_dead_connections();
            last_check_time = now;
        }

        ssize_t const rcvd = mnl_socket_recvfrom(socket, buf.data(), BUF_SIZE);
        if (rcvd < 0) {
            perror("mnl_socket_recvfrom");
            return EXIT_FAILURE;
        }

        ret = mnl_cb_run(buf.data(), static_cast<std::size_t>(rcvd), 0, port_id, cb_loop, static_cast<void *>(&ctx));
        if (ret < 0) {
            perror("cb run");
            return EXIT_FAILURE;
        }
    }

    mnl_socket_close(socket);

    return EXIT_SUCCESS;
}

