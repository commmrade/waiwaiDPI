//
// Created by klewy on 8/10/26.
//

#ifndef WAIWAIDPI_CONN_TRACKER_HPP
#define WAIWAIDPI_CONN_TRACKER_HPP
#include <cstdint>
#include <map>
#include <span>
#include "protocol.hpp"
#include <vector>

class Connection
{
private:
    std::size_t bytes_transfered_{0};
    std::size_t packet_count_{0};

    L7Proto payload_proto_{L7Proto::UNKNOWN};

    bool is_done_{false}; // should this connection be handled later on?
public:
    struct
    {
        std::vector<std::vector<char>> frags;
        std::size_t pos{0};
        std::size_t total_size{0};
        std::uint32_t expected_seq{0};
    } reasm_;
public:
    [[nodiscard]] std::size_t bytes_transfered() const
    {
        return bytes_transfered_;
    }
    void set_bytes_transfered(const std::size_t bytes)
    {
        bytes_transfered_ = bytes;
    }

    [[nodiscard]] std::size_t packet_count() const
    {
        return packet_count_;
    }
    void count_packet()
    {
        ++packet_count_;
    }

    [[nodiscard]] L7Proto payload_proto() const
    {
        return payload_proto_;
    }
    void set_payload_proto(const L7Proto proto)
    {
        payload_proto_ = proto;
    }

    [[nodiscard]] bool is_done() const
    {
        return is_done_;
    }
    void set_done(bool value)
    {
        is_done_ = value;
    }
};

class ConnTracker
{
private:
    std::map<std::tuple<std::uint32_t, std::uint16_t, std::uint32_t, std::uint16_t>, Connection> conns_;
public:
    void track(std::span<const char> packet);
    Connection& get_conn(const std::uint32_t saddr, const std::uint16_t source, const std::uint32_t daddr, const std::uint16_t dest);
};

#endif// WAIWAIDPI_CONN_TRACKER_HPP
