//
// Created by klewy on 10/13/26.
//

#ifndef WAIWAIDPI_MARKERS_HPP
#define WAIWAIDPI_MARKERS_HPP
#include <cstdint>
#include <optional>
#include <span>
#include "../protocol.hpp"
#include <expected>

struct Markers
{
    // Both TLS and HTTP
    std::optional<std::size_t> hoststart;
    std::optional<std::size_t> hostmid;
    std::optional<std::size_t> hostend;

    // TLS-specific
    std::optional<std::size_t> sniext;
};

std::expected<Markers, std::string> find_markers_tls(std::span<const char> payload);
std::expected<Markers, std::string> find_markers_http(std::span<const char> payload);
std::expected<Markers, std::string> find_markers(std::span<const char> payload, const L7Proto payload_proto);

#endif// WAIWAIDPI_MARKERS_HPP
