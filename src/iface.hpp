#ifndef WAIWAIDPI_IFACE_HPP
#define WAIWAIDPI_IFACE_HPP

#include <cstring>
#include <expected>
#include <format>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string.h>
#include <string_view>
#include <sys/ioctl.h>

template<typename T>
std::expected<std::string, std::string> iface_find(const T* saddr) {
    struct ifaddrs* ifs = nullptr;
    int ret = getifaddrs(&ifs);
    if (ret < 0) {
        return std::unexpected{std::format("getifaddrs failure because {}", std::strerror(errno))};
    }

    for (struct ifaddrs* iface = ifs; iface != nullptr; iface = iface->ifa_next) {
        if (iface->ifa_addr) {
            auto addr = reinterpret_cast<const sockaddr_storage*>(iface->ifa_addr);

            if (iface->ifa_addr->sa_family == AF_INET) {
                auto addr_v4 = reinterpret_cast<const sockaddr_in*>(addr);
                if (!std::memcmp(&addr_v4->sin_addr, saddr, sizeof(addr_v4->sin_addr))) {
                    return {iface->ifa_name};
                }
            } else { // IPv6
                auto addr_v6 = reinterpret_cast<const sockaddr_in6*>(addr);
                if (!std::memcmp(addr_v6->sin6_addr.s6_addr, saddr, sizeof(addr_v6->sin6_addr.s6_addr))) {
                    return {iface->ifa_name};
                }
            }
        }
    }

    return std::unexpected{"no such interface"};
}

std::expected<int, std::string> iface_get_mtu(const std::string_view iface_name);

template<typename T>
std::expected<int, std::string> iface_find_and_get_mtu(const T* addr)
{
    const auto iface_name = iface_find(addr);
    if (iface_name.has_value()) {
        const auto mtu = iface_get_mtu(iface_name.value());
        if (mtu.has_value()) {
            return {mtu.value()};
        } else {
            return std::unexpected{mtu.error()};
        }
    } else {
        return std::unexpected{iface_name.error()};
    }
}

#endif //WAIWAIDPI_IFACE_HPP