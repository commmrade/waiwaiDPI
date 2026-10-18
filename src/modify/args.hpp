//
// Created by klewy on 9/24/26.
//

#ifndef WAIWAIDPI_SPLIT_H
#define WAIWAIDPI_SPLIT_H

#include "net/packet_view.hpp"
#include <cstring>
#include <exception>
#include <filesystem>
#include <string>

struct Position
{
    enum class Operation : std::uint8_t
    {
        None,
        Add,
        Subtract,
    };
    std::string arg; // Markers::HOSTSTART_STR, Markers::HOSTEND_STR, Markers::HOSTMID_STR - for Host in HTTP and SNI Hostname in TLS. Markers::SNIEXT_STR for TLS only.
    Operation operation{};
    std::size_t offset{0};
};

Position parse_position(const std::string_view split);
std::vector<char> parse_blob(const std::string_view &str);

#endif// WAIWAIDPI_SPLIT_H
