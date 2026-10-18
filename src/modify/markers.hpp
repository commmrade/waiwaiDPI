//
// Created by klewy on 10/13/26.
//

#ifndef WAIWAIDPI_MARKERS_HPP
#define WAIWAIDPI_MARKERS_HPP
#include "net/protocol.hpp"
#include <cstdint>
#include <expected>
#include <optional>
#include <span>

struct Markers
{
    // Both TLS and HTTP
    std::optional<std::size_t> hoststart;
    static constexpr std::string_view HOSTSTART_STR = "hoststart";

    std::optional<std::size_t> hostmid;
    static constexpr std::string_view HOSTMID_STR = "hostmid";

    std::optional<std::size_t> hostend;
    static constexpr std::string_view HOSTEND_STR = "hostend";

    // TLS-specific
    std::optional<std::size_t> sniext;
    static constexpr std::string_view SNIEXT_STR = "sniext";
};

std::expected<Markers, std::string> find_markers_tls(std::span<const char> payload);
std::expected<Markers, std::string> find_markers_http(std::span<const char> payload);
std::expected<Markers, std::string> find_markers(std::span<const char> payload, const L7Proto payload_proto);

#endif// WAIWAIDPI_MARKERS_HPP
