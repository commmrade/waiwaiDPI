#include <cerrno>
#include <cstring>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <format>
#include <string_view>
#include <arpa/inet.h>
#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>
#include <assert.h>
#include <expected>

template<typename T>
std::expected<std::string, std::string> iface_find(const T* saddr) {
    struct ifaddrs* ifs = NULL;
    int ret = getifaddrs(&ifs);
    if (ret < 0) {
        return std::unexpected{std::format("getifaddrs failure because {}", std::strerror(errno))};
    }

    for (struct ifaddrs* iface = ifs; iface != NULL; iface = iface->ifa_next) {
        if (iface->ifa_addr) {
            const struct sockaddr_storage* addr = (const struct sockaddr_storage*)iface->ifa_addr;

            if (iface->ifa_addr->sa_family == AF_INET) {
                const sockaddr_in* addr_v4 = (const struct sockaddr_in*)addr;
                if (!std::memcmp(&addr_v4->sin_addr, saddr, sizeof(addr_v4->sin_addr))) {
                    return {iface->ifa_name};
                }
            } else { // IPv6
                const sockaddr_in6* addr_v6 = (const struct sockaddr_in6*)addr;
                if (!std::memcmp(addr_v6->sin6_addr.s6_addr, saddr, sizeof(addr_v6->sin6_addr.s6_addr))) {
                    return {iface->ifa_name};
                }
            }
        }
    }

    return std::unexpected{"no such interface"};
}

inline std::expected<int, std::string> iface_get_mtu(const std::string_view iface_name) {
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
