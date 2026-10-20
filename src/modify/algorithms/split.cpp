//
// Created by klewy on 9/24/26.
//

#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_TRACE
#include <spdlog/spdlog.h>
#include "split.hpp"
#include "net/checksum.hpp"
#include "modify/markers.hpp"
#include <algorithm>
#include <cstring>
#include <iostream>
#include <print>
#include <ranges>

namespace helpers {

std::size_t do_operation(const std::size_t start, const Position::Operation oper, const std::size_t offset)
{
    std::size_t ret = start;
    switch (oper) {
    case Position::Operation::Add: {
        ret += offset;
        break;
    }
    case Position::Operation::Subtract: {
        ret -= offset;
        break;
    }
    default:
        break;
    }

    return ret;
};
}// namespace helpers