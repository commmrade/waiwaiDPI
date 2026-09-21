//
// Created by klewy on 9/21/26.
//

#ifndef WAIWAIDPI_IPTABLES_HPP
#define WAIWAIDPI_IPTABLES_HPP
#include <cstring>
#include <memory>
#include <stdexcept>
#include <stdio.h>
#include <string_view>

static void close_pipe(FILE* pipe)
{
    pclose(pipe);
}

inline bool rule_exists(const std::string_view rule)
{
    std::unique_ptr<FILE, decltype(&close_pipe)> const pipe(popen("iptables -S", "r"), close_pipe);
    if (pipe == nullptr) {
        throw std::runtime_error("Command 'check_rule' could not be executed");
    }

    std::string response;
    response.resize(1024);

    auto const rd = fread(response.data(), 1, response.size(), pipe.get());
    if (rd < 0) {
        throw std::runtime_error(std::strerror(errno));
    }
    response.resize(rd);

    return response.contains(rule);
}

inline void rule_add(const std::string_view rule)
{
    int ret = system(rule.data());
    if (ret < 0) {
        throw std::runtime_error(std::strerror(errno));
    }
}

inline void rule_remove(const std::string_view rule)
{
    int ret = system(rule.data());
    if (ret < 0) {
        throw std::runtime_error(std::strerror(errno));
    }
}

#endif// WAIWAIDPI_IPTABLES_HPP
