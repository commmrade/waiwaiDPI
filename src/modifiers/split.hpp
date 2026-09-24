//
// Created by klewy on 9/24/26.
//

#ifndef WAIWAIDPI_SPLIT_H
#define WAIWAIDPI_SPLIT_H

#include <cassert>
#include <cstdint>
#include <string>
#include <exception>
#include <format>

struct Split
{
    enum class Operation : std::uint8_t
    {
        None,
        Add,
        Subtract,
    };

    std::string arg;
    Operation operation{};
    std::size_t offset{0};
};

static std::size_t calculate_split_offset(const Split& split, const std::size_t sni_len)
{
    std::size_t offset = 0;

    auto do_operation = [](const std::size_t start, const Split::Operation oper, const std::size_t offset) {
        std::size_t ret = start;
        switch (oper) {
        case Split::Operation::Add: {
            ret += offset;
            break;
        }
        case Split::Operation::Subtract: {
            ret -= offset;
            break;
        }
        default:
            break;
        }

        return ret;
    };

    if (split.arg == "hoststart") {
        offset = do_operation(0, split.operation, split.offset);
    } else if (split.arg == "hostend") {
        offset = do_operation(sni_len, split.operation, split.offset);
    } else if (split.arg == "hostmid") {
        offset = do_operation(sni_len / 2, split.operation, split.offset);
    } else {
        offset = split.offset;
    }

    return offset;
}

inline Split parse_split(const std::string_view split)
{
    assert(!split.empty());

    Split ret{};

    auto iter = split.begin();
    while (iter != split.end()) {
        if (iter != split.end() && std::isalpha(*iter) != 0) {
            while (iter != split.end() && std::isalpha(*iter) != 0) {
                ret.arg += *iter;
                std::advance(iter, 1);
            }
        }
        if (iter != split.end() && std::isdigit(*iter) != 0) {
            std::string digit;
            while (iter != split.end() && std::isdigit(*iter) != 0) {
                digit += *iter;
                std::advance(iter, 1);
            }
            ret.offset = static_cast<std::size_t>(std::stoi(digit));
        }

        if (iter != split.end()) {
            if (*iter == '+') {
                ret.operation = Split::Operation::Add;
                std::advance(iter, 1);
            } else if (*iter == '-') {
                ret.operation = Split::Operation::Subtract;
                std::advance(iter, 1);
            } else {
                throw std::runtime_error("Unexpected symbol");
            }
        }
    }

    if (ret.operation != Split::Operation::None && ret.arg.empty()) {
        throw std::runtime_error(std::format("You specified an operation but didn't specify string position in '{}'", split));
    }

    return ret;
}



#endif// WAIWAIDPI_SPLIT_H
