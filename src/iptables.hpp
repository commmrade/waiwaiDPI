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

void close_pipe(FILE* pipe);

bool rule_exists(const std::string_view rule);
void rule_add(const std::string_view rule);
void rule_remove(const std::string_view rule);

#endif// WAIWAIDPI_IPTABLES_HPP
