//
// Created by klewy on 8/10/26.
//
#include "nfq.hpp"
#include <array>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/linux_nfnetlink_queue.h>

int send_verdict(mnl_socket* sock, const std::uint32_t packet_id, int verd)
{
    std::array<char, 512> buf{};
    nlmsghdr* msg = nfq_nlmsg_put(buf.data(), NFQNL_MSG_VERDICT, QUEUE_NUMBER);
    nfq_nlmsg_verdict_put(msg, static_cast<int>(packet_id), verd);

    ssize_t sent = mnl_socket_sendto(sock, msg, msg->nlmsg_len);
    return static_cast<int>(sent);
}
