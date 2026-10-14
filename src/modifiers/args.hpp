//
// Created by klewy on 9/24/26.
//

#ifndef WAIWAIDPI_SPLIT_H
#define WAIWAIDPI_SPLIT_H

#include <cassert>
#include <cstdint>
#include <cstring>
#include <exception>
#include <filesystem>
#include <format>
#include <netinet/tcp.h>
#include "../packet_view.hpp"
#include <string>
#include "../checksum.hpp"


struct Position
{
    enum class Operation : std::uint8_t
    {
        None,
        Add,
        Subtract,
    };
    std::string arg; // "hoststart", "hostend", "hostmid" - for Host in HTTP and SNI Hostname in TLS. "sniext" for TLS only.
    Operation operation{};
    std::size_t offset{0};
};

Position parse_position(const std::string_view split);
std::vector<char> parse_blob(const std::string_view &str);

#endif// WAIWAIDPI_SPLIT_H
