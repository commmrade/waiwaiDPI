//
// Created by klewy on 8/10/26.
//

#ifndef WAIWAIDPI_CONN_TRACKER_HPP
#define WAIWAIDPI_CONN_TRACKER_HPP
#include <cstdint>
#include <map>
#include <span>
#include "protocol.hpp"

class Connection
{

};

class ConnTracker
{
private:
    std::map<std::tuple<std::uint32_t, std::uint16_t, std::uint32_t, std::uint16_t>, Connection> conns_;

public:
    void track(std::span<const char> packet);
};

#endif// WAIWAIDPI_CONN_TRACKER_HPP
