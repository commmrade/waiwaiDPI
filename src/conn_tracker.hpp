//
// Created by klewy on 8/10/26.
//

#ifndef WAIWAIDPI_CONN_TRACKER_HPP
#define WAIWAIDPI_CONN_TRACKER_HPP
#include "hash.hpp"
#include "packet_view.hpp"
#include "protocol.hpp"
#include <chrono>
#include <cstdint>
#include <map>
#include <span>
#include <unordered_map>
#include <vector>

class Connection
{
public:
    struct Tcp
    {
        enum class TcpState { UNKNOWN, SYN, ESTAB, FIN, CLOSED };
        TcpState state{ TcpState::UNKNOWN };
        std::uint32_t cur_seq{};

        // helpers
        std::uint32_t expected_seq;
    };
    struct Udp
    {
    };

private:
    std::size_t pl_bytes_transfered_{ 0 };
    std::size_t packet_count_{ 0 };

    std::chrono::time_point<std::chrono::system_clock> last_packet_time_;

    L7Proto payload_proto_{ L7Proto::UNKNOWN };

    struct
    {
        std::vector<Packet> frags;
        std::size_t pos{ 0 };
        std::size_t total_size{ 0 };
        std::optional<std::uint32_t> expected_seq{ 0 };
    } reasm_;

    std::uint8_t l4_proto_{};
    std::variant<std::monostate, Tcp, Udp> l4_state_;

    bool is_done_{ false };// should this connection be handled later on? FIX: TEMPORARY (hopefully)

    void track_tcp(const PacketView &packet);
    void track_udp(const PacketView &packet);

public:
    [[nodiscard]] std::uint8_t get_l4_proto() const { return l4_proto_; }
    [[nodiscard]] const Tcp &get_l4_tcp() const { return std::get<1>(l4_state_); }
    [[nodiscard]] const Udp &get_l4_udp() const { return std::get<2>(l4_state_); }
    void set_l4_proto(const std::uint8_t proto);


    bool is_reassembling() const { return reasm_.pos > 0 || reasm_.total_size > 0; }

    void reset_reasm();

    void add_reasm_frag(const PacketView& pkt) { reasm_.frags.emplace_back(create_packet(pkt)); }
    [[nodiscard]] const std::vector<Packet> &get_reasm_frags() const { return reasm_.frags; }
    [[nodiscard]] std::size_t get_reasm_pos() const { return reasm_.pos; }
    void set_reasm_pos(const std::size_t pos) { reasm_.pos = pos; }
    [[nodiscard]] std::size_t get_reasm_total_size() const { return reasm_.total_size; }
    void set_reasm_total_size(const std::size_t total_size) { reasm_.total_size = total_size; }
    [[nodiscard]] std::optional<std::uint32_t> get_reasm_expected_seq() const { return reasm_.expected_seq; }
    void set_reasm_expected_seq(const std::uint32_t seq) { reasm_.expected_seq = seq; }

    [[nodiscard]] std::size_t bytes_transfered() const { return pl_bytes_transfered_; }
    void set_bytes_transfered(const std::size_t bytes) { pl_bytes_transfered_ = bytes; }

    [[nodiscard]] std::size_t packet_count() const { return packet_count_; }
    void count_packet() { ++packet_count_; }

    [[nodiscard]] auto get_last_packet_time() const { return last_packet_time_; }
    void update_last_packet_time(const std::chrono::time_point<std::chrono::system_clock> time)
    {
        last_packet_time_ = time;
    }

    [[nodiscard]] L7Proto payload_proto() const { return payload_proto_; }
    void set_payload_proto(const L7Proto proto) { payload_proto_ = proto; }

    [[nodiscard]] bool is_done() const { return is_done_; }
    void set_done(bool value) { is_done_ = value; }

    void track_transport(const PacketView &packet);
};

namespace std {
template<>
struct hash<std::tuple<std::uint32_t, std::uint16_t, std::uint32_t, std::uint16_t, int>>
{
    std::size_t operator()(const std::tuple<std::uint32_t, std::uint16_t, std::uint32_t, std::uint16_t, int>& val) const noexcept
    {
        std::size_t seed = 0;
        hash_combine(seed, std::get<0>(val));
        hash_combine(seed, std::get<1>(val));
        hash_combine(seed, std::get<2>(val));
        hash_combine(seed, std::get<3>(val));
        hash_combine(seed, std::get<4>(val));
        return seed;
    }
};
}

class ConnTracker
{
private:
    std::unordered_map<std::tuple<std::uint32_t, std::uint16_t, std::uint32_t, std::uint16_t, int>, Connection> conns_;

    static int timeout_for_tcp_state(const Connection::Tcp::TcpState state);

public:
    void track(const PacketView &packet);
    void clear_dead_connections();

    Connection &get_conn(const std::uint32_t saddr,
        const std::uint16_t source,
        const std::uint32_t daddr,
        const std::uint16_t dest,
        const int proto);
    std::size_t count() const
    {
        return conns_.size();
    }
    auto& conns()
    {
        return conns_;
    }
};

#endif// WAIWAIDPI_CONN_TRACKER_HPP
