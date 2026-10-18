//
// Created by klewy on 8/10/26.
//

#ifndef WAIWAIDPI_CONN_TRACKER_HPP
#define WAIWAIDPI_CONN_TRACKER_HPP
#include "net/packet_view.hpp"
#include "net/protocol.hpp"
#include "util/hash.hpp"
#include <chrono>
#include <cstdint>
#include <map>
#include <span>
#include <unordered_map>
#include <vector>


struct mnl_socket;
class Connection
{
public:
    struct Tcp
    {
        enum class TcpState { UNKNOWN, SYN, ESTAB, FIN, CLOSED };
        TcpState state{ TcpState::UNKNOWN };
        std::uint32_t cur_seq{};

        // helpers
        std::uint32_t expected_seq{};

        int mss{536}; // According to RFC xxxx, TCP Default MSS is 536 bytes (for IPV4)
    };
    struct Udp
    {
    };

private:
    std::size_t pl_bytes_transfered_{ 0 };
    std::size_t packet_count_{ 0 };

    mutable std::optional<int> mtu_;

    std::chrono::time_point<std::chrono::system_clock> last_packet_time_;

    L7Proto payload_proto_{ L7Proto::UNKNOWN };

    struct
    {
        std::vector<Packet> segs;
    } reasm_;
    void reasm_sort();
    bool reasm_is_duplicate(const PacketView& pkt);

    std::uint32_t saddr_{};

    std::uint8_t l4_proto_{};
    std::variant<std::monostate, Tcp, Udp> l4_state_;

    bool is_done_{ false };// should this connection be handled later on? FIX: TEMPORARY (hopefully)


    void track_tcp(const PacketView &packet);
    void track_udp(const PacketView &packet);

public:
    void track(const PacketView &packet);
    void track_transport(const PacketView &packet);

    void set_source_addr(const std::uint32_t saddr)
    {
        saddr_ = saddr;
    }
    std::uint32_t get_source_addr() const
    {
        return saddr_;
    }

    static constexpr auto MAX_REASM_SEGMENTS()
    {
        return 20;
    }

    [[nodiscard]] std::uint8_t get_l4_proto() const { return l4_proto_; }
    [[nodiscard]] const Tcp &get_l4_tcp() const { return std::get<1>(l4_state_); }
    [[nodiscard]] const Udp &get_l4_udp() const { return std::get<2>(l4_state_); }
    void set_l4_proto(const std::uint8_t proto);

    int get_mss() const;
    void set_mss(const int mss);


    void reasm_reset();
    void reasm_insert(const PacketView& pkt);
    [[nodiscard]] const std::vector<Packet> &reasm_get() const { return reasm_.segs; }


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

    // TODO: make it per conn.
    static int timeout_for_tcp_state(const Connection::Tcp::TcpState state);

public:
    void clear_dead_connections(mnl_socket* sock, const std::uint32_t queue_num);

    std::unordered_map<std::tuple<unsigned, unsigned short, unsigned, unsigned short, int>, Connection>::iterator get_conn(const std::uint32_t saddr,
        const std::uint16_t source,
        const std::uint32_t daddr,
        const std::uint16_t dest,
        const int proto);

    std::size_t count() const
    {
        return conns_.size();
    }
};

#endif// WAIWAIDPI_CONN_TRACKER_HPP
