#include "classify/classifier.hpp"
#include "conntrack/conn_tracker.hpp"
#include "argh.h"
#include "config/profile.hpp"
#include "sys/iptables.hpp"
#include "net/consts.hpp"
#include "sys/nfq.hpp"
#include <arpa/inet.h>
#include <cassert>
#include <csignal>
#include <cstring>
#include <filesystem>
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
#include <toml++/toml.hpp>
#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_TRACE
#include <spdlog/spdlog.h>

struct Context
{
    mnl_socket *sock{ nullptr };
    std::unordered_map<std::pair<std::uint16_t, int>, Profile, pair_hash> *profiles;
    ConnTracker *tracker{ nullptr };

    int raw_sock;
    std::uint32_t queue_number;
};

int cb_loop(const struct nlmsghdr *nlh, void *data)
{
    auto *ctx = static_cast<Context *>(data);

    const nfgenmsg *genmsg = static_cast<nfgenmsg *>(mnl_nlmsg_get_payload(nlh));
    assert(genmsg);

    std::array<nlattr *, NFQA_MAX + 1> attrs{};
    int ret = nfq_nlmsg_parse(nlh, attrs.data());
    if (ret < 0) {
        perror("nfq_nlmsg_parse");
        return MNL_CB_ERROR;
    }

    assert(attrs[NFQA_PACKET_HDR]);
    const auto *pkt_hdr = static_cast<const nfqnl_msg_packet_hdr *>(mnl_attr_get_payload(attrs[NFQA_PACKET_HDR]));
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
    SPDLOG_INFO("Got a packet with id {} of size {}. {}:{} -> {}:{}",
        packet.packet_id,
        packet_len,
        ip_src.data(),
        packet.get_source_port(),
        ip_dst.data(),
        packet.get_dest_port());

    auto conn_iter = ctx->tracker->get_conn(packet.network_hdr->saddr,
        packet.get_source_port(),
        packet.network_hdr->daddr,
        packet.get_dest_port(),
        packet.network_hdr->protocol);
    conn_iter->second.track(packet);

    if (!packet.payload.empty() && !conn_iter->second.is_done()) {
        auto &conn = conn_iter->second;

        auto profile_iter = ctx->profiles->find({ packet.get_dest_port(), packet.network_hdr->protocol });
        assert(profile_iter != (*ctx->profiles).end());
        auto &profile = profile_iter->second;

        conn.reasm_insert(packet);
        auto packets = conn.reasm_get();

        assert(!packets.empty());
        auto res = profile.classifier.classify(packets);
        if (res.first == ClassifyResult::DONE) {
            conn.set_payload_proto(res.second.value());
            conn.reasm_reset();

            profile.modifier.modify(packets, conn);

            for (const auto &send_pkt : packets) {
                switch (send_pkt.action.action) {
                case PacketAction::Action::ACCEPT: {
                    assert(send_pkt.action.packet_id);
                    SPDLOG_DEBUG("Packet with id {} is ACCEPTed", send_pkt.action.packet_id);
                    ret = send_verdict(ctx->sock, ctx->queue_number, send_pkt.action.packet_id, NF_ACCEPT);
                    if (ret < 0) { perror("send accept failed, but dont stop"); }
                    break;
                }
                case PacketAction::Action::DROP: {
                    SPDLOG_DEBUG("Packet with id {} is DROPped", send_pkt.action.packet_id);
                    ret = send_verdict(ctx->sock, ctx->queue_number, send_pkt.action.packet_id, NF_DROP);
                    if (ret < 0) { perror("send drop failed, dont stop"); }
                    break;
                }
                case PacketAction::Action::DROP_AND_SEND: {
                    ret = send_verdict(ctx->sock, ctx->queue_number, send_pkt.action.packet_id, NF_DROP);
                    if (ret < 0) { perror("send drop failed, dont stop"); }
                    [[fallthrough]];
                }
                case PacketAction::Action::SEND: {
                    SPDLOG_DEBUG("Packet with id {} is SEND/DROP_AND_SEND", send_pkt.action.packet_id);

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
            conn.set_done(true);
        } else if (res.first == ClassifyResult::REASSEMBLING) {
            // Nothing for now
        } else {
            conn.reasm_reset();
            conn.set_done(true);// if error that means it probably won't be correctly classified, so just drop
            for (const auto &pkt : conn.reasm_get()) {
                SPDLOG_DEBUG("Packet {} is dropped on Error", pkt.action.packet_id);
                int ret = send_verdict(ctx->sock, ctx->queue_number, pkt.action.packet_id, NF_ACCEPT);
                if (ret < 0) { SPDLOG_WARN("Unable to accept packet with id: {}", pkt.action.packet_id); }
            }

            int ret = send_verdict(ctx->sock, ctx->queue_number, packet.packet_id, NF_ACCEPT);
            if (ret < 0) { SPDLOG_WARN("Unable to accept packet with id: {}", packet.packet_id); }
        }
    } else {
        SPDLOG_DEBUG("Packet {} is dropped immediately (no payload or connection is done)", packet.packet_id);
        ret = send_verdict(ctx->sock, ctx->queue_number, packet.packet_id, NF_ACCEPT);
        assert(ret);
    }

    return MNL_CB_OK;
}

std::atomic<bool> running = true;
static_assert(std::atomic<bool>::is_always_lock_free && "Atomic cannot be used in signal handler on this platform");
void sig_handler(int sig) { running.store(false); }

int main(int argc, char *argv[])
{
    struct sigaction sig;
    sig.sa_handler = sig_handler;

    int ret = ::sigaction(SIGINT, &sig, nullptr);
    if (ret < 0) { throw std::runtime_error("Could not setup signal handler"); }

#if SPDLOG_ACTIVE_LEVEL <= SPDLOG_LEVEL_DEBUG
    spdlog::set_level(spdlog::level::debug);
#endif

    argh::parser const cmdl(argc, argv);
    std::string cfg_path;
    std::uint32_t queue_number = 1489;
    if (!(cmdl("config") >> cfg_path)) {
        throw std::runtime_error("No config path");
        return -1;
    }
    cmdl("queue-number") >> queue_number;

    if (!std::filesystem::exists(cfg_path)) {
        throw std::runtime_error(std::format("Such file '{}' does not exist", cfg_path));
    }
    if (queue_number > std::numeric_limits<std::uint16_t>::max()) {
        throw std::runtime_error("Such queue number cannot be used!");
    }

    int mark = 0x14;
    if (!rule_exists(std::format("-A OUTPUT -m mark --mark {} -j ACCEPT", mark))) {
        rule_add(std::format("iptables -A OUTPUT -m mark --mark {} -j ACCEPT", mark));
    }

    ConnTracker tracker{};
    auto profiles = build_profiles(cfg_path, tracker, queue_number);

    ret = 0;

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
    nlmsghdr *hdr = nfq_nlmsg_put(buf.data(), NFQNL_MSG_CONFIG, queue_number);
    nfq_nlmsg_cfg_put_cmd(hdr, AF_INET, NFQNL_CFG_CMD_BIND);
    ssize_t sent = mnl_socket_sendto(socket, hdr, hdr->nlmsg_len);
    if (sent < 0) {
        perror("mnl_socket_sendto");
        return EXIT_FAILURE;
    }

    // configure
    hdr = nfq_nlmsg_put(buf.data(), NFQNL_MSG_CONFIG, queue_number);
    nfq_nlmsg_cfg_put_params(hdr, NFQNL_COPY_PACKET, BUF_SIZE);

    sent = mnl_socket_sendto(socket, hdr, hdr->nlmsg_len);
    if (sent < 0) {
        perror("mnl socket sendto");
        return EXIT_FAILURE;
    }

    ret = 1;
    mnl_socket_setsockopt(socket, NETLINK_NO_ENOBUFS, &ret, sizeof(ret));

    Context ctx{};
    ctx.sock = socket;
    // ctx.classifier = &cfier;
    // ctx.modifier = &modifier;
    ctx.profiles = &profiles;
    ctx.tracker = &tracker;
    ctx.raw_sock = raw_sock;
    ctx.queue_number = queue_number;

    auto last_check_time = std::chrono::system_clock::now();

    running.store(true);
    while (running.load()) {
        ssize_t const rcvd = mnl_socket_recvfrom(socket, buf.data(), BUF_SIZE);
        if (rcvd < 0 && errno == EINTR) {
            break;
        } else if (rcvd < 0) {
            perror("mnl_socket_recvfrom");
            return EXIT_FAILURE;
        }

        ret = mnl_cb_run(buf.data(), static_cast<std::size_t>(rcvd), 0, port_id, cb_loop, static_cast<void *>(&ctx));
        if (ret < 0) {
            perror("cb run");
            return EXIT_FAILURE;
        }

        const auto now = std::chrono::system_clock::now();
        const auto dur = std::chrono::duration_cast<std::chrono::seconds>(now - last_check_time);
        if (dur.count() >= CHECK_DEAD_CONNECTIONS_INTERVAL_SECS) {
            SPDLOG_DEBUG("Deleting dead connections");
            ctx.tracker->clear_dead_connections(ctx.sock, ctx.queue_number);
            last_check_time = now;
        }
    }

    for (const auto &profile : profiles) {
        std::string protocol_str;
        if (profile.first.second == IPPROTO_TCP) {
            protocol_str = "tcp";
        } else if (profile.first.second == IPPROTO_UDP) {
            protocol_str = "udp";
        } else {
            throw std::runtime_error("Unknown protocol");
        }
        rule_remove(
            std::format("iptables -D OUTPUT -p {} -m {} --dport {} "
                        "-m connbytes --connbytes 0:{} --connbytes-dir original --connbytes-mode packets "
                        "-j NFQUEUE --queue-num {}",
                protocol_str,
                protocol_str,
                profile.first.first,
                Connection::MAX_REASM_SEGMENTS(),
                queue_number)
                .c_str());
    }
    rule_remove(std::format("iptables -D OUTPUT -m mark --mark {} -j ACCEPT", mark));

    mnl_socket_close(socket);
    return EXIT_SUCCESS;
}
