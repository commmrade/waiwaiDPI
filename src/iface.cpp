//
// Created by klewy on 10/6/26.
//
#include "iface.hpp"

std::expected<int, std::string> iface_get_mtu(const std::string_view iface_name) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return std::unexpected{std::format("socket creation failure because {}", std::strerror(errno))};
    }

    struct ifreq req = {};
    strncpy(req.ifr_name, iface_name.data(), sizeof(req.ifr_name));
    int ret = ioctl(sock, SIOCGIFMTU, &req);
    if (ret < 0) {
        return std::unexpected{std::format("ioctl failure because {}", std::strerror(errno))};
    }

    return {req.ifr_mtu};
}
