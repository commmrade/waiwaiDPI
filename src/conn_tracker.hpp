//
// Created by klewy on 8/10/26.
//

#ifndef WAIWAIDPI_CONN_TRACKER_HPP
#define WAIWAIDPI_CONN_TRACKER_HPP
#include <cstdint>
#include <map>
#include <span>
#include "protocol.hpp"
#include "packet.hpp"
#include <chrono>
#include <vector>

class Connection
{
private:
    std::size_t bytes_transfered_{0};
    std::size_t packet_count_{0};

    std::chrono::time_point<std::chrono::system_clock> last_packet_time_;

    L7Proto payload_proto_{L7Proto::UNKNOWN};

    struct
    {
        std::vector<std::vector<char>> frags;
        std::size_t pos{0};
        std::size_t total_size{0};
        std::uint32_t expected_seq{0};
    } reasm_;

    bool is_done_{false}; // should this connection be handled later on? TEMPORARY
public:
    bool is_reassembling() const { return reasm_.pos > 0 || reasm_.total_size > 0; }

    void add_reasm_frag(std::span<const char> frag)
    {
        reasm_.frags.emplace_back(frag.begin(), frag.end());
    }
    const std::vector<std::vector<char>>& get_reasm_frags() const
    {
        return reasm_.frags;
    }
    [[nodiscard]] std::size_t get_reasm_pos() const
    {
        return reasm_.pos;
    }
    void set_reasm_pos(const std::size_t pos)
    {
        reasm_.pos = pos;
    }
    [[nodiscard]] std::size_t get_reasm_total_size() const
    {
        return reasm_.total_size;
    }
    void set_reasm_total_size(const std::size_t total_size)
    {
        reasm_.total_size = total_size;
    }
    [[nodiscard]] std::uint32_t get_reasm_expected_seq() const
    {
        return reasm_.expected_seq;
    }
    void set_reasm_expected_seq(const std::uint32_t seq)
    {
        reasm_.expected_seq = seq;
    }

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

    [[nodiscard]] auto get_last_packet_time() const
    {
        return last_packet_time_;
    }
    void update_last_packet_time()
    {
        last_packet_time_ = std::chrono::system_clock::now();
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
    void track(const Packet& packet);
    Connection& get_conn(const std::uint32_t saddr, const std::uint16_t source, const std::uint32_t daddr, const std::uint16_t dest);
    [[nodiscard]] std::size_t conns_size() const
    {
        return conns_.size();
    }
    void clear_dead_connections();
};

#endif// WAIWAIDPI_CONN_TRACKER_HPP
